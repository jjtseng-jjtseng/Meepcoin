#!/usr/bin/env python3
"""Task 1 — instrumented, one-case-at-a-time diagnosis of the height-31 regression hang.

Three previous attempts at height 31 failed to complete. The first was a genuine port collision
between test shards, which is fixed. The last two ran for hours without finishing and were never
diagnosed. This harness exists to find out where execution actually stops, rather than launching the
same test a fourth time.

Every stage is wrapped in a HARD wall-clock timeout enforced by SIGALRM, and every stage records its
own elapsed time. On a timeout the harness preserves, for both daemons:
  * the process state from /proc/<pid>/status  (R running, S sleeping, D uninterruptible/IO, Z dead)
  * accumulated user and system CPU time, sampled twice, so a CPU-bound daemon is distinguishable
    from one blocked on I/O or simply idle
  * whether the RPC port still answers
  * the log tail
  * the candidate block bytes and both chain tips

Runs one case at a time on non-overlapping ports. Nothing else should be running.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, signal, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, rest, DAEMON, ROOT, TS_WINDOW  # noqa

FTL = 7200
FTL_MARGIN = 120
HEIGHT = 31
PORT0 = 31000
OUTDIR = "docs/h31_diagnose"
REPORT = "docs/H31_DIAGNOSIS.md"
for a in sys.argv[1:]:
    if a.startswith("--height="): HEIGHT = int(a.split("=", 1)[1])
    if a.startswith("--port="):   PORT0 = int(a.split("=", 1)[1])
    if a.startswith("--outdir="): OUTDIR = a.split("=", 1)[1]
    if a.startswith("--report="): REPORT = a.split("=", 1)[1]

STAGE_TIMEOUTS = {"start_a": 90, "start_b": 90, "mine_base": 240, "replay": 240,
                  "verify": 30, "build": 30, "sibling": 45, "submit_main": 45,
                  "submit_alt": 45, "stop_b": 45, "stop_a": 45}

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


class StageTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise StageTimeout()


signal.signal(signal.SIGALRM, _alarm)


class Stage:
    """Hard wall-clock bound on one stage, with its elapsed time recorded either way."""
    def __init__(self, rec, name):
        self.rec, self.name = rec, name

    def __enter__(self):
        self.t0 = time.time()
        signal.setitimer(signal.ITIMER_REAL, STAGE_TIMEOUTS.get(self.name, 60))
        return self

    def __exit__(self, et, ev, tb):
        signal.setitimer(signal.ITIMER_REAL, 0)
        el = round(time.time() - self.t0, 3)
        self.rec.setdefault("stages", {})[self.name] = {
            "elapsed_s": el,
            "outcome": "ok" if et is None else ("TIMEOUT" if et is StageTimeout else et.__name__)}
        if et is StageTimeout:
            self.rec["hung_stage"] = self.name
        return False


def proc_state(pid):
    """R running, S sleeping, D uninterruptible (usually disk), Z zombie, or gone."""
    try:
        st = open(f"/proc/{pid}/status").read()
        state = [l for l in st.split("\n") if l.startswith("State:")][0].split()[1:3]
        parts = open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()
        return {"state": " ".join(state), "utime": int(parts[11]), "stime": int(parts[12]),
                "threads": int([l for l in st.split("\n") if l.startswith("Threads:")][0].split()[1])}
    except Exception as e:
        return {"state": f"gone ({type(e).__name__})"}


def diagnose(rec, da, db, label):
    """Called on timeout. Distinguishes CPU-bound / IO-blocked / RPC-dead / process-gone."""
    out = {}
    for tag, d in (("A", da), ("B", db)):
        if d is None:
            out[tag] = {"note": "daemon object not created"}
            continue
        pid = d.proc.pid if getattr(d, "proc", None) else None
        s1 = proc_state(pid) if pid else {"state": "no pid"}
        time.sleep(2.0)
        s2 = proc_state(pid) if pid else {"state": "no pid"}
        cpu_delta = None
        if "utime" in s1 and "utime" in s2:
            cpu_delta = (s2["utime"] - s1["utime"]) + (s2["stime"] - s1["stime"])
        rpc_ok, rpc_err = False, None
        try:
            rest(d.rpc, "/get_info", timeout=5)
            rpc_ok = True
        except Exception as e:
            rpc_err = f"{type(e).__name__}: {e}"
        tail = []
        try:
            with open(d.log, errors="replace") as f:
                tail = f.readlines()[-25:]
        except Exception:
            pass
        verdict = ("process gone / dead" if "gone" in s1.get("state", "") else
                   "CPU-bound" if (cpu_delta or 0) > 20 else
                   "blocked in uninterruptible I/O (LMDB likely)" if s1.get("state", "").startswith("D") else
                   "alive but RPC not answering" if not rpc_ok else
                   "alive, RPC answering, idle")
        out[tag] = {"pid": pid, "state_1": s1, "state_2": s2,
                    "cpu_ticks_over_2s": cpu_delta, "rpc_responds": rpc_ok,
                    "rpc_error": rpc_err, "verdict": verdict,
                    "log_tail": [l.rstrip() for l in tail]}
    rec["diagnosis"] = out
    say(f"    ! {label}: A={out.get('A', {}).get('verdict')}  B={out.get('B', {}).get('verdict')}")


def one_case(idx, kind, rev_roles, rev_order, port):
    rec = {"case_id": f"h{HEIGHT}-{idx:02d}", "height": HEIGHT, "kind": kind,
           "roles": "rev" if rev_roles else "std", "order": "rev" if rev_order else "std",
           "port_a": port, "port_b": port + 4, "t_start": time.time()}
    da = db = None
    try:
        with Stage(rec, "start_a"):
            da = Daemon(f"h31a{port}", port, port + 1, fixed_diff=1)
            rec["pid_a"] = da.proc.pid
        with Stage(rec, "start_b"):
            db = Daemon(f"h31b{port}", port + 4, port + 5, fixed_diff=1)
            rec["pid_b"] = db.proc.pid
        rec["daemons_up"] = True
        # Contamination guard. Case 02 of the first instrumented run started with daemon A already
        # at height 32 and CPU-bound, which can only happen if a previous run's daemon was still
        # alive on that port. A fresh chain is height 1; anything else means the environment is
        # dirty and the case result would be meaningless.
        ha, hb = da.height(), db.height()
        rec["start_height_a"], rec["start_height_b"] = ha, hb
        if ha != 1 or hb != 1:
            raise RuntimeError(f"dirty environment: fresh daemons started at heights {ha}/{hb}, "
                               f"expected 1/1 -- a previous daemon is still holding these ports")

        blobs = []
        with Stage(rec, "mine_base"):
            while da.height() < HEIGHT:
                t = da.template()
                h = da.height()
                for i in range(60):
                    b = rebuild(t["blocktemplate_blob"], nonce=h * 7919 + i)
                    ok, err, _ = da.submit(b)
                    if ok:
                        blobs.append(b); break
                else:
                    raise RuntimeError(f"stuck extending at {h}: {err}")
            rec["base_height_a"] = da.height()
            rec["base_tip_a"] = da.info()["top_block_hash"]
        with Stage(rec, "replay"):
            for b in blobs:
                ok, err, _ = db.submit(b)
                if not ok:
                    raise RuntimeError(f"replay rejected: {err}")
            rec["base_height_b"] = db.height()
            rec["base_tip_b"] = db.info()["top_block_hash"]
        with Stage(rec, "verify"):
            rec["identical_history"] = (rec["base_tip_a"] == rec["base_tip_b"] and
                                        rec["base_height_a"] == rec["base_height_b"])
            if not rec["identical_history"]:
                raise RuntimeError("histories differ after replay")

        with Stage(rec, "build"):
            parent_h = HEIGHT - 1
            lo = max(0, parent_h - (TS_WINDOW - 1))
            med = epee_median(da.timestamps(lo, parent_h))
            now = int(time.time())
            ts = {"below": med - 1, "equal": med, "above": med + 1,
                  "max_future": now + FTL - FTL_MARGIN,
                  "beyond_ftl": now + FTL + FTL_MARGIN}[kind]
            t = da.template()
            cand = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0xCA0DEF)
            sib = rebuild(t["blocktemplate_blob"], nonce=0x51B1)
            rec.update(median=med, ts=ts, parent=t["prev_hash"], candidate_blob=cand)

        main_node, alt_node = (da, db) if not rev_roles else (db, da)
        if not rev_order:
            with Stage(rec, "sibling"):
                rec["sibling"] = alt_node.submit(sib)[:2]
        main_node.mark_log(); alt_node.mark_log()
        with Stage(rec, "submit_main"):
            ok_m, err_m, dt_m = main_node.submit(cand)
            rec["main"] = {"accepted": ok_m, "error": err_m, "ms": round(1000 * dt_m, 1),
                           "log": [l.split(chr(9))[-1] for l in main_node.new_log()
                                   if "imestamp" in l or "proof of work" in l]}
        with Stage(rec, "submit_alt"):
            ok_a, err_a, dt_a = alt_node.submit(cand)
            rec["alt"] = {"accepted": ok_a, "error": err_a, "ms": round(1000 * dt_a, 1),
                          "log": [l.split(chr(9))[-1] for l in alt_node.new_log()
                                  if "imestamp" in l or "proof of work" in l]}
        if rev_order:
            with Stage(rec, "sibling"):
                rec["sibling"] = alt_node.submit(sib)[:2]
        rec["disagree"] = (ok_m != ok_a)
        rec["tip_a_final"] = da.info()["top_block_hash"]
        rec["tip_b_final"] = db.info()["top_block_hash"]
    except StageTimeout:
        rec["result"] = "TIMEOUT"
        diagnose(rec, da, db, rec["case_id"])
    except Exception as e:
        rec["result"] = f"ERROR {type(e).__name__}: {e}"
        diagnose(rec, da, db, rec["case_id"])
    else:
        rec["result"] = "ok"
    finally:
        for nm, d in (("stop_b", db), ("stop_a", da)):
            if d is None:
                continue
            try:
                with Stage(rec, nm):
                    d.stop()
            except StageTimeout:
                try: d.proc.kill()
                except Exception: pass
        rec["t_end"] = time.time()
        rec["total_s"] = round(rec["t_end"] - rec["t_start"], 2)
    return rec


def main():
    os.makedirs(ROOT, exist_ok=True)
    os.makedirs(OUTDIR, exist_ok=True)
    dh = subprocess.run(["sha256sum", DAEMON], capture_output=True, text=True).stdout.split()[0]
    up = subprocess.run(["uptime", "-p"], capture_output=True, text=True).stdout.strip()

    say(f"# MeepCoin — Instrumented Diagnosis of the Height-{HEIGHT} Regression Hang")
    say()
    say("> **ANALYSIS ONLY.** One case at a time, unique ports, hard per-stage timeouts, nothing")
    say("> else running. No consensus, genesis, frozen tag, preserved chain or wallet touched.")
    say("> Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Daemon: `{DAEMON}`")
    say(f"- Daemon sha256: `{dh}`")
    say(f"- WSL uptime at start: `{up}`")
    say(f"- Per-stage timeouts: {STAGE_TIMEOUTS}")
    say()

    cases = []
    idx = 0
    port = PORT0
    for kind in ["below", "equal", "above", "max_future", "beyond_ftl"]:
        for rr, ro in ((False, False), (True, False), (False, True)):
            idx += 1
            say(f"  case {idx:02d}/15  {kind:12s} roles={'rev' if rr else 'std'} "
                f"order={'rev' if ro else 'std'}  ports {port}/{port+4}")
            r = one_case(idx, kind, rr, ro, port)
            cases.append(r)
            with open(os.path.join(OUTDIR, f"{r['case_id']}.json"), "w", encoding="utf-8") as f:
                json.dump(r, f, indent=1)
            st = r.get("stages", {})
            say(f"            -> {r['result']}  total {r['total_s']}s  "
                f"start_a {st.get('start_a', {}).get('elapsed_s')}s "
                f"mine {st.get('mine_base', {}).get('elapsed_s')}s "
                f"replay {st.get('replay', {}).get('elapsed_s')}s "
                f"main {st.get('submit_main', {}).get('elapsed_s')}s "
                f"alt {st.get('submit_alt', {}).get('elapsed_s')}s")
            port += 20
    say()

    ok = [c for c in cases if c["result"] == "ok"]
    bad = [c for c in cases if c["result"] != "ok"]
    say("## Result")
    say()
    say(f"**{len(ok)}/{len(cases)} cases completed, {len(bad)} failed or timed out.**")
    say()
    say("| case | category | roles | order | main | alt | agree | total s | slowest stage |")
    say("|---|---|---|---|---|---|---|---|---|")
    for c in cases:
        st = c.get("stages", {})
        slow = max(st.items(), key=lambda kv: kv[1]["elapsed_s"])[0] if st else "—"
        slow_s = st[slow]["elapsed_s"] if st else 0
        if c["result"] != "ok":
            say(f"| {c['case_id']} | {c['kind']} | {c['roles']} | {c['order']} | — | — "
                f"| **{c['result'][:40]}** | {c['total_s']} | {slow} {slow_s}s |")
            continue
        say(f"| {c['case_id']} | {c['kind']} | {c['roles']} | {c['order']} "
            f"| {'accept' if c['main']['accepted'] else 'reject'} "
            f"| {'accept' if c['alt']['accepted'] else 'reject'} "
            f"| {'**DISAGREE**' if c['disagree'] else 'yes'} | {c['total_s']} | {slow} {slow_s}s |")
    say()
    if bad:
        say("### Failure diagnosis")
        say()
        for c in bad:
            say(f"**{c['case_id']}** — hung stage `{c.get('hung_stage')}`")
            for tag, d in (c.get("diagnosis") or {}).items():
                say(f"- daemon {tag}: pid {d.get('pid')}, state `{d.get('state_1', {}).get('state')}`, "
                    f"CPU ticks over 2 s {d.get('cpu_ticks_over_2s')}, RPC responds "
                    f"{d.get('rpc_responds')} -> **{d.get('verdict')}**")
                for l in (d.get("log_tail") or [])[-4:]:
                    say(f"  - `{l[:160]}`")
            say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
