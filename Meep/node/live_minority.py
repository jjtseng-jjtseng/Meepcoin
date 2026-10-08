#!/usr/bin/env python3
"""The decisive live minority-attacker experiment.

Honest miners and an adaptive-timestamp attacker compete for the SAME chain, both doing real
MeepHash-W proof-of-work. Attacker ownership is never assigned after the fact: a block counts as the
attacker's only if the attacker's own submission was the one the daemon accepted, matched by block
hash read back immediately after acceptance.

  honest   the daemon's internal miner, N threads, ordinary template timestamps
  attacker an external loop that reads the tip, computes the T1+T2+T4 legal bounds from its own
           current chain view, picks lowest-legal or maximum-legal-future, and brute-forces nonces
           through submit_block until the daemon accepts one -- real proof-of-work, performed by the
           daemon's own verifier

Attacker share is TUNED by honest thread count but never INFERRED from it: both sides' hashrates are
measured (honest from /mining_status speed, attacker from accepted-block work over elapsed time) and
the achieved share is reported.

Every run uses a genuinely fresh genesis via the experimental runtime override, and reports the
genesis age actually achieved at first mining.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, statistics, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild, epee_median, rpc, rest, TS_WINDOW  # noqa

FTL = 7200
FTL_MARGIN = 5
OUTDIR = "docs/minority"
REPORT = "docs/LIVE_MINORITY.md"
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
BUDGET = 150            # wall-clock seconds of competition per run
HEIGHT_CAP = 400
RECOVER = 60            # seconds of honest-only mining after the attacker stops
PORT0 = 33000
RUNS = None
for a in sys.argv[1:]:
    if a.startswith("--budget="):  BUDGET = int(a.split("=", 1)[1])
    if a.startswith("--cap="):     HEIGHT_CAP = int(a.split("=", 1)[1])
    if a.startswith("--recover="): RECOVER = int(a.split("=", 1)[1])
    if a.startswith("--port="):    PORT0 = int(a.split("=", 1)[1])
    if a.startswith("--runs="):    RUNS = a.split("=", 1)[1].split(",")
    if a.startswith("--outdir="):  OUTDIR = a.split("=", 1)[1]
    if a.startswith("--report="):  REPORT = a.split("=", 1)[1]

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


class Run:
    def __init__(self, tag, threads, attack, port):
        self.tag, self.threads, self.attack, self.port = tag, threads, attack, port
        self.rows = []
        self.atk_hashes = set()
        self.atk_attempts = 0
        self.atk_accepted = 0
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.prov = {}

    # ---------------------------------------------------------------- attacker
    def bounds(self, d, chain_h):
        """T1+T2+T4 legal window, computed only from the attacker's own chain view."""
        parent_h = chain_h - 1
        lo_h = max(0, parent_h - (TS_WINDOW - 1))
        win = d.timestamps(lo_h, parent_h) if chain_h > 0 else []
        med = epee_median(win) if win else 0
        return med, int(time.time()) + FTL - FTL_MARGIN

    def attacker_loop(self, d):
        while not self.stop_flag.is_set():
            try:
                ch = d.height()
                if ch > HEIGHT_CAP:
                    break
                t = d.template()
                diff = int(t["difficulty"])
                med, hi = self.bounds(d, ch)
                # strongest established adaptive strategy: alternate the two legal extremes
                if ch % 2 == 0:
                    ts, choice = hi, "max-legal-future"
                else:
                    ts, choice = med, "lowest-legal"
                accepted = False
                attempts = 0
                for i in range(400):
                    if self.stop_flag.is_set():
                        break
                    blob = rebuild(t["blocktemplate_blob"], ts=ts, nonce=(ch * 100003 + i) & 0xFFFFFFFF)
                    ok, err, _ = d.submit(blob)
                    attempts += 1
                    if ok:
                        accepted = True
                        break
                with self.lock:
                    self.atk_attempts += attempts
                if accepted:
                    try:
                        hdr = rpc(d.rpc, "get_block_header_by_height",
                                  {"height": ch})["result"]["block_header"]
                    except Exception:
                        continue
                    with self.lock:
                        self.atk_accepted += 1
                        self.atk_hashes.add(hdr["hash"])
                        self.rows.append(dict(
                            wall=time.time(), height=ch, block_hash=hdr["hash"],
                            parent=t["prev_hash"], producer="attacker", timestamp=ts,
                            lower_bound=med, upper_bound=hi, strategy=choice,
                            difficulty=diff, attempts=attempts, accepted=True))
            except Exception:
                time.sleep(0.05)

    # ---------------------------------------------------------------- run
    def execute(self):
        d = L.Daemon(self.tag, self.port, self.port + 1, fixed_diff=0,
                     data_dir=os.path.join(L.ROOT, self.tag))
        gts = self.prov["requested_genesis_ts"]
        try:
            g = rpc(d.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
            self.prov.update(genesis_ts_actual=g["timestamp"], genesis_hash=g["hash"],
                             daemon_start_wall=self.prov["daemon_start_wall"])
            if g["timestamp"] != gts:
                self.prov["override_failed"] = True
            rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": self.threads,
                                          "do_background_mining": False, "ignore_battery": True})
            t_first = None
            th = None
            if self.attack:
                th = threading.Thread(target=self.attacker_loop, args=(d,), daemon=True)
                th.start()
            t0 = time.time()
            seen = 1
            while time.time() - t0 < BUDGET and d.height() <= HEIGHT_CAP:
                h = d.height()
                if h > seen:
                    if t_first is None:
                        t_first = time.time()
                        self.prov["first_block_wall"] = t_first
                        self.prov["genesis_age_at_first_block_s"] = round(t_first - gts, 1)
                    seen = h
                time.sleep(0.2)
            ms = rest(d.rpc, "/mining_status")
            self.prov["honest_hashrate_hs"] = ms.get("speed")
            self.stop_flag.set()
            if th:
                th.join(timeout=20)
            self.prov["attack_stop_height"] = d.height()
            self.prov["attack_stop_wall"] = time.time()
            atk_elapsed = self.prov["attack_stop_wall"] - t0
            # attacker hashrate = proof-of-work attempts per second, all real hashes
            self.prov["attacker_hashrate_hs"] = round(self.atk_attempts / max(atk_elapsed, 1e-9), 2)
            self.prov["attack_seconds"] = round(atk_elapsed, 1)

            # ---- recovery: honest only
            if RECOVER > 0:
                t1 = time.time()
                while time.time() - t1 < RECOVER and d.height() <= HEIGHT_CAP:
                    time.sleep(0.3)
            self.prov["final_height"] = d.height()
            # ---- read the whole chain back
            H = d.height()
            hdrs = []
            for lo in range(0, H, 500):
                hi = min(lo + 499, H - 1)
                hdrs += rpc(d.rpc, "get_block_headers_range",
                            {"start_height": lo, "end_height": hi})["result"]["headers"]
            self.headers = hdrs
            self.prov["alt_blocks"] = len(rest(d.rpc, "/get_alt_blocks_hashes")
                                          .get("blks_hashes") or [])
            info = d.info()
            self.prov["cumulative_difficulty"] = str(info.get("cumulative_difficulty"))
        finally:
            try: rest(d.rpc, "/stop_mining", {})
            except Exception: pass
            d.stop()
        return self


def analyse(r):
    hd = [h for h in r.headers if h["height"] > 0]
    atk = [h for h in hd if h["hash"] in r.atk_hashes]
    diffs = [int(h["difficulty"]) for h in hd]
    ts = [int(h["timestamp"]) for h in hd]
    iv = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
    work_all = sum(diffs)
    work_atk = sum(int(h["difficulty"]) for h in atk)
    run = best1 = best10 = cur1 = cur10 = 0
    for dv in diffs:
        cur1 = cur1 + 1 if dv == 1 else 0
        cur10 = cur10 + 1 if dv <= 10 else 0
        best1 = max(best1, cur1); best10 = max(best10, cur10)
    stop_h = r.prov.get("attack_stop_height", 0)
    after = [int(h["difficulty"]) for h in hd if h["height"] > stop_h]
    return dict(
        blocks=len(hd), attacker_blocks=len(atk),
        attacker_block_share=round(len(atk) / len(hd), 4) if hd else 0,
        attacker_work_share=round(work_atk / work_all, 4) if work_all else 0,
        longest_diff1_run=best1, longest_diff_le10_run=best10,
        min_difficulty=min(diffs) if diffs else 0,
        median_difficulty=int(statistics.median(diffs)) if diffs else 0,
        max_difficulty=max(diffs) if diffs else 0,
        p95_interval=(sorted(iv)[int(0.95 * (len(iv) - 1))] if iv else 0),
        median_interval=(int(statistics.median(iv)) if iv else 0),
        alt_blocks=r.prov.get("alt_blocks", 0),
        difficulty_at_stop=next((int(h["difficulty"]) for h in hd if h["height"] == stop_h), None),
        blocks_after_stop=len(after),
        difficulty_after_recovery=after[-1] if after else None)


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    os.makedirs(L.ROOT, exist_ok=True)
    L.DAEMON = BIN
    say("# MeepCoin — Live Minority-Attacker Experiment")
    say()
    say("> **ANALYSIS ONLY.** Isolated experimental chains with a genuinely fresh genesis. No")
    say("> consensus rule added or modified. Frozen tags, the preserved devnet database and the")
    say("> wallets are untouched. Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Binary: `{BIN}`")
    say(f"- Binary sha256: `{sha(BIN)}`")
    say(f"- Competition budget {BUDGET} s, height cap {HEIGHT_CAP}, honest-only recovery {RECOVER} s")
    say()
    say("**Attacker share is tuned by honest thread count but never inferred from it.** Both sides'")
    say("hashrates are measured: honest from the daemon's own `/mining_status` speed, attacker from")
    say("real proof-of-work attempts per second. Blocks are attributed to the attacker only when the")
    say("attacker's own submission was accepted, matched by the block hash read back immediately.")
    say()

    plan = [("control-1t", 1, False), ("atk-1t", 1, True),
            ("control-2t", 2, False), ("atk-2t", 2, True),
            ("control-4t", 4, False), ("atk-4t", 4, True),
            ("atk-4t-b", 4, True), ("atk-4t-c", 4, True),
            ("control-8t", 8, False), ("atk-8t", 8, True),
            ("atk-12t", 12, True)]
    if RUNS:
        plan = [p for p in plan if p[0] in RUNS]

    port = PORT0
    results = []
    for tag, threads, attack in plan:
        gts = int(time.time())
        r = Run(f"mn_{tag}", threads, attack, port)
        r.prov = {"tag": tag, "threads": threads, "attack": attack,
                  "compiled_genesis_ts": 1785283200, "requested_genesis_ts": gts,
                  "daemon_start_wall": time.time(), "binary_sha256": sha(BIN)}
        os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
        say(f"running `{tag}` threads={threads} attack={attack} port={port} …")
        try:
            r.execute()
            m = analyse(r)
        except Exception as e:
            say(f"  ! {tag}: {type(e).__name__}: {e}")
            port += 10
            continue
        rec = {"provenance": r.prov, "metrics": m}
        with open(os.path.join(OUTDIR, f"{tag}.json"), "w", encoding="utf-8") as f:
            json.dump({**rec, "attacker_rows": r.rows}, f, indent=1)
        results.append((tag, threads, attack, r.prov, m))
        say(f"  -> blocks {m['blocks']}  atk_blocks {m['attacker_blocks']} "
            f"({100*m['attacker_block_share']:.1f}%)  work {100*m['attacker_work_share']:.1f}%  "
            f"diff1run {m['longest_diff1_run']}  medDiff {m['median_difficulty']}  "
            f"honest {r.prov.get('honest_hashrate_hs')} H/s  atk {r.prov.get('attacker_hashrate_hs')} H/s "
            f"gAge {r.prov.get('genesis_age_at_first_block_s')}s")
        port += 10
    say()

    say("## Genesis provenance (every run)")
    say()
    say("| run | compiled genesis ts | requested | actual | genesis hash | age at first block (s) |")
    say("|---|---|---|---|---|---|")
    for tag, th, at, p, m in results:
        say(f"| `{tag}` | {p['compiled_genesis_ts']} | {p['requested_genesis_ts']} "
            f"| {p.get('genesis_ts_actual')} | `{str(p.get('genesis_hash'))[:20]}…` "
            f"| **{p.get('genesis_age_at_first_block_s')}** |")
    say()

    say("## Measured hashrate and achieved shares")
    say()
    say("| run | honest threads | honest H/s | attacker H/s | measured attacker hashrate share "
        "| attacker block share | attacker work share |")
    say("|---|---|---|---|---|---|---|")
    for tag, th, at, p, m in results:
        hh = p.get("honest_hashrate_hs") or 0
        ah = p.get("attacker_hashrate_hs") or 0
        hs = (ah / (ah + hh)) if (ah + hh) else 0
        say(f"| `{tag}` | {th} | {hh} | {ah} | {100*hs:.1f}% "
            f"| {100*m['attacker_block_share']:.1f}% | {100*m['attacker_work_share']:.1f}% |")
    say()

    say("## Primary metrics, attacked runs against matched all-honest controls")
    say()
    say("| run | blocks | longest diff==1 | longest diff<=10 | min diff | median diff | max diff "
        "| median interval | p95 interval | alt blocks | diff at stop | diff after recovery |")
    say("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for tag, th, at, p, m in results:
        say(f"| `{tag}` | {m['blocks']} | {m['longest_diff1_run']} | {m['longest_diff_le10_run']} "
            f"| {m['min_difficulty']} | {m['median_difficulty']} | {m['max_difficulty']} "
            f"| {m['median_interval']} | {m['p95_interval']} | {m['alt_blocks']} "
            f"| {m['difficulty_at_stop']} | {m['difficulty_after_recovery']} |")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
