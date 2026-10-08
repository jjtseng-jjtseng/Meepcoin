#!/usr/bin/env python3
"""Real-P2P reproduction of the suspected template-invalidation starvation.

Topology: three SEPARATE daemons with their own data directories and ports, connected only by the
normal MeepCoin P2P path.

    attacker miner -> attacker daemon  ---P2P---  honest daemon H1 <- honest internal miner
                                        \\---P2P---  honest daemon H2 <- honest internal miner

The attacker NEVER calls submit_block on an honest daemon. It builds against its own daemon's
template, submits locally, and its blocks reach the honest nodes only by relay, where each honest
node validates them independently.

WHAT THIS SEPARATES, which the earlier single-daemon run did not:
  raw capacity      each miner's hashrate measured ALONE, with no competitor  (pre-attack baseline)
  active hashing    hashrate measured DURING the run
  accepted work     share of blocks and cumulative difficulty on the final chain

FOUR CASES, to separate valid-block flooding from timestamp manipulation:
  honest_rate   honest timestamps, one submission attempt per template  (an ordinary small miner)
  honest_flood  honest timestamps, blocks produced as fast as consensus permits
  attack_rate   adaptive T1+T2+T4 timestamps, one attempt per template
  attack_flood  adaptive timestamps, as fast as consensus permits          (the suspected attack)
  none          no second miner at all -- the pure honest baseline

Every run uses a genuinely fresh genesis, shared by all three daemons, and reports its actual age.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, statistics, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild, epee_median, rpc, rest, TS_WINDOW  # noqa

FTL, FTL_MARGIN = 7200, 5
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
BUDGET = 90
BASELINE = 25          # seconds of isolated measurement per miner, before the run
HONEST_THREADS = 4
CASES = ["none", "honest_rate", "honest_flood", "attack_rate", "attack_flood"]
PORT0 = 34000
OUTDIR, REPORT = "docs/p2p_starve", "docs/P2P_STARVATION.md"
for a in sys.argv[1:]:
    if a.startswith("--budget="):  BUDGET = int(a.split("=", 1)[1])
    if a.startswith("--threads="): HONEST_THREADS = int(a.split("=", 1)[1])
    if a.startswith("--cases="):   CASES = a.split("=", 1)[1].split(",")
    if a.startswith("--port="):    PORT0 = int(a.split("=", 1)[1])
    if a.startswith("--outdir="):  OUTDIR = a.split("=", 1)[1]
    if a.startswith("--report="):  REPORT = a.split("=", 1)[1]

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


def start(tag, p2p, rpcp, peers, gts):
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    extra = []
    for pp in peers:
        extra += ["--add-exclusive-node", f"127.0.0.1:{pp}"]
    return L.Daemon(tag, p2p, rpcp, fixed_diff=0, offline=False, extra=extra,
                    data_dir=os.path.join(L.ROOT, tag))


class TipWatcher(threading.Thread):
    """Per-node timeline of tip changes. The gap between consecutive tip changes bounds how long
    that node's miner could have worked on one template -- the useful mining window."""
    def __init__(self, d, stop):
        super().__init__(daemon=True)
        self.d, self.stop, self.events, self.speeds = d, stop, [], []
        self.err = None

    def run(self):
        last = None
        t_last = time.time()
        while not self.stop.is_set():
            try:
                i = self.d.info()
                tip, h = i["top_block_hash"], i["height"]
                now = time.time()
                if tip != last:
                    if last is not None:
                        self.events.append({"wall": now, "height": h, "tip": tip,
                                            "window_s": round(now - t_last, 4)})
                    last, t_last = tip, now
                if len(self.speeds) == 0 or now - self.speeds[-1][0] > 3.0:
                    try:
                        self.speeds.append((now, rest(self.d.rpc, "/mining_status").get("speed", 0)))
                    except Exception:
                        pass
            except Exception as e:
                self.err = f"{type(e).__name__}: {e}"
            time.sleep(0.02)


class Miner(threading.Thread):
    """External miner against its OWN daemon. Real proof-of-work: every attempt is a hash the
    daemon computes. `adaptive` chooses malicious timestamps; `flood` removes the per-template
    rate limit."""
    def __init__(self, d, adaptive, flood, stop):
        super().__init__(daemon=True)
        self.d, self.adaptive, self.flood, self.stop = d, adaptive, flood, stop
        self.attempts = 0
        self.accepted = 0
        self.hashes = set()
        self.rows = []

    def run(self):
        while not self.stop.is_set():
            try:
                ch = self.d.height()
                t = self.d.template()
                diff = int(t["difficulty"])
                ts = None; choice = "honest-template"
                if self.adaptive:
                    ph = ch - 1
                    win = self.d.timestamps(max(0, ph - (TS_WINDOW - 1)), ph) if ch > 0 else []
                    med = epee_median(win) if win else 0
                    hi = int(time.time()) + FTL - FTL_MARGIN
                    ts, choice = ((hi, "max-legal-future") if ch % 2 == 0
                                  else (med, "lowest-legal"))
                budget = 400 if self.flood else 1
                ok = False
                for i in range(budget):
                    if self.stop.is_set():
                        break
                    blob = rebuild(t["blocktemplate_blob"], ts=ts,
                                   nonce=(ch * 100003 + i) & 0xFFFFFFFF)
                    r, err, _ = self.d.submit(blob)
                    self.attempts += 1
                    if r:
                        ok = True
                        break
                if ok:
                    self.accepted += 1
                    try:
                        hdr = rpc(self.d.rpc, "get_block_header_by_height",
                                  {"height": ch})["result"]["block_header"]
                        self.hashes.add(hdr["hash"])
                        self.rows.append({"height": ch, "hash": hdr["hash"], "ts": ts,
                                          "strategy": choice, "difficulty": diff})
                    except Exception:
                        pass
                elif not self.flood:
                    time.sleep(0.01)
            except Exception:
                time.sleep(0.05)


def quant(v, p):
    if not v:
        return 0
    s = sorted(v)
    return round(s[min(len(s) - 1, int(p * (len(s) - 1)))], 4)


def run_case(case, port, gts):
    """Returns a dict of measurements for one case."""
    tags = [f"p2p_atk_{case}", f"p2p_h1_{case}", f"p2p_h2_{case}"]
    pa, p1, p2 = port, port + 10, port + 20
    rec = {"case": case, "requested_genesis_ts": gts, "binary_sha256": sha(BIN),
           "ports": {"attacker": pa, "h1": p1, "h2": p2}}
    da = start(tags[0], pa, pa + 1, [p1, p2], gts)
    d1 = start(tags[1], p1, p1 + 1, [pa, p2], gts)
    d2 = start(tags[2], p2, p2 + 1, [pa, p1], gts)
    stop = threading.Event()
    try:
        for d in (da, d1, d2):
            d.wait_synced(60)
        g = rpc(d1.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
        rec["genesis_ts_actual"], rec["genesis_hash"] = g["timestamp"], g["hash"]
        rec["peers"] = {t: (d.info().get("incoming_connections_count", 0) +
                            d.info().get("outgoing_connections_count", 0))
                        for t, d in zip(("attacker", "h1", "h2"), (da, d1, d2))}

        # ---------- pre-attack RAW CAPACITY, each honest miner measured ALONE ----------
        raw = {}
        for name, d in (("h1", d1), ("h2", d2)):
            rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": HONEST_THREADS,
                                          "do_background_mining": False, "ignore_battery": True})
            # mining_status speed is a moving average and reads 0 for the first seconds, so poll
            # across the whole baseline window and take the maximum rather than sampling once.
            sp, t_b = [], time.time()
            while time.time() - t_b < BASELINE:
                try:
                    sp.append(rest(d.rpc, "/mining_status").get("speed", 0) or 0)
                except Exception:
                    pass
                time.sleep(1.0)
            raw[name] = max(sp) if sp else 0
            rest(d.rpc, "/stop_mining", {})
            time.sleep(0.5)
        rec["raw_capacity_hs"] = raw

        # ---------- the run ----------
        w1, w2 = TipWatcher(d1, stop), TipWatcher(d2, stop)
        w1.start(); w2.start()
        for d in (d1, d2):
            rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": HONEST_THREADS,
                                          "do_background_mining": False, "ignore_battery": True})
        miner = None
        if case != "none":
            miner = Miner(da, adaptive=case.startswith("attack"), flood=case.endswith("flood"),
                          stop=stop)
            miner.start()
        t0 = time.time()
        time.sleep(BUDGET)
        stop.set()
        if miner:
            miner.join(timeout=15)
        elapsed = time.time() - t0
        rec["active_hashing_hs"] = {"h1": max([s for _, s in w1.speeds] or [0]),
                                    "h2": max([s for _, s in w2.speeds] or [0]),
                                    "h1_mean": round(statistics.mean([s for _, s in w1.speeds]), 1)
                                    if w1.speeds else 0,
                                    "h2_mean": round(statistics.mean([s for _, s in w2.speeds]), 1)
                                    if w2.speeds else 0}
        rec["attacker_attempts_hs"] = round(miner.attempts / elapsed, 2) if miner else 0
        rec["attacker_local_accepted"] = miner.accepted if miner else 0
        for d in (d1, d2):
            try: rest(d.rpc, "/stop_mining", {})
            except Exception: pass
        time.sleep(2.0)

        # ---------- useful mining windows, per honest node ----------
        for nm, w in (("h1", w1), ("h2", w2)):
            wins = [e["window_s"] for e in w.events]
            rec[f"{nm}_tip_changes"] = len(wins)
            rec[f"{nm}_window_mean"] = round(statistics.mean(wins), 4) if wins else None
            rec[f"{nm}_window_median"] = round(statistics.median(wins), 4) if wins else None
            rec[f"{nm}_window_p5"] = quant(wins, 0.05)
            rec[f"{nm}_window_p95"] = quant(wins, 0.95)

        # ---------- final chains ----------
        tips, heights = {}, {}
        for nm, d in (("attacker", da), ("h1", d1), ("h2", d2)):
            i = d.info()
            tips[nm], heights[nm] = i["top_block_hash"], i["height"]
        rec["final_tips"], rec["final_heights"] = tips, heights
        rec["converged"] = len(set(tips.values())) == 1

        H = heights["h1"]
        hdrs = []
        for lo in range(0, H, 500):
            hdrs += rpc(d1.rpc, "get_block_headers_range",
                        {"start_height": lo, "end_height": min(lo + 499, H - 1)})["result"]["headers"]
        body = [h for h in hdrs if h["height"] > 0]
        atk = [h for h in body if miner and h["hash"] in miner.hashes]
        diffs = [int(h["difficulty"]) for h in body]
        rec["chain_blocks"] = len(body)
        rec["attacker_mainchain_blocks"] = len(atk)
        rec["attacker_block_share"] = round(len(atk) / len(body), 4) if body else 0
        rec["attacker_work_share"] = (round(sum(int(h["difficulty"]) for h in atk) / sum(diffs), 4)
                                      if diffs and sum(diffs) else 0)
        rec["median_difficulty"] = int(statistics.median(diffs)) if diffs else 0
        rec["max_difficulty"] = max(diffs) if diffs else 0
        best = cur = 0
        for dv in diffs:
            cur = cur + 1 if dv <= 10 else 0
            best = max(best, cur)
        rec["longest_diff_le10_run"] = best
        rec["alt_blocks"] = {nm: len(rest(d.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or [])
                             for nm, d in (("attacker", da), ("h1", d1), ("h2", d2))}
        rec["attacker_rows"] = (miner.rows[:200] if miner else [])
    finally:
        stop.set()
        for d in (d2, d1, da):
            try: d.stop()
            except Exception: pass
    return rec


def main():
    os.makedirs(OUTDIR, exist_ok=True); os.makedirs(L.ROOT, exist_ok=True)
    L.DAEMON = BIN
    say("# MeepCoin — Real-P2P Test of the Template-Invalidation Starvation Hypothesis")
    say()
    say("> **ANALYSIS ONLY.** No consensus rule added or modified. T1/T2/T4 unchanged. Frozen tags,")
    say("> the preserved devnet database and the wallets are untouched. No public genesis, no public")
    say("> infrastructure. Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Binary: `{BIN}` sha256 `{sha(BIN)}`")
    say(f"- Topology: three separate daemons, own data dirs and ports, connected by P2P only.")
    say("  **The attacker never calls submit_block on an honest daemon.** Its blocks reach the")
    say("  honest nodes only by relay and are validated independently there.")
    say(f"- Honest miners: {HONEST_THREADS} threads each, on their own daemons.")
    say(f"- Per-case budget {BUDGET} s; raw capacity measured in isolation for {BASELINE//2} s per miner.")
    say()

    port = PORT0
    out = []
    for case in CASES:
        gts = int(time.time())
        say(f"running `{case}` …")
        try:
            r = run_case(case, port, gts)
        except Exception as e:
            say(f"  ! {case}: {type(e).__name__}: {e}")
            port += 40
            continue
        with open(os.path.join(OUTDIR, f"{case}.json"), "w", encoding="utf-8") as f:
            json.dump(r, f, indent=1)
        out.append(r)
        say(f"  -> peers {r['peers']}  raw {r['raw_capacity_hs']}  "
            f"active h1 {r['active_hashing_hs']['h1']} h2 {r['active_hashing_hs']['h2']}  "
            f"atk {r['attacker_attempts_hs']} H/s  blocks {r['chain_blocks']}  "
            f"atk_share {100*r['attacker_block_share']:.1f}%  medDiff {r['median_difficulty']}  "
            f"h1_window_med {r['h1_window_median']}s  converged {r['converged']}")
        port += 40
    say()

    say("## Capacity, active hashing and accepted work — kept separate")
    say()
    say("| case | H1 raw (alone) | H2 raw (alone) | H1 active | H2 active | attacker attempts/s "
        "| attacker block share | attacker work share |")
    say("|---|---|---|---|---|---|---|---|")
    for r in out:
        say(f"| `{r['case']}` | {r['raw_capacity_hs'].get('h1')} | {r['raw_capacity_hs'].get('h2')} "
            f"| {r['active_hashing_hs']['h1']} | {r['active_hashing_hs']['h2']} "
            f"| {r['attacker_attempts_hs']} | {100*r['attacker_block_share']:.1f}% "
            f"| {100*r['attacker_work_share']:.1f}% |")
    say()

    say("## Useful mining window at each honest node (seconds between tip changes)")
    say()
    say("| case | H1 tip changes | H1 mean | H1 median | H1 p5 | H1 p95 | H2 median | median difficulty |")
    say("|---|---|---|---|---|---|---|---|")
    for r in out:
        say(f"| `{r['case']}` | {r['h1_tip_changes']} | {r['h1_window_mean']} "
            f"| {r['h1_window_median']} | {r['h1_window_p5']} | {r['h1_window_p95']} "
            f"| {r['h2_window_median']} | {r['median_difficulty']} |")
    say()

    say("## Chain outcome")
    say()
    say("| case | blocks | longest diff<=10 run | max difficulty | alt blocks (atk/h1/h2) | all tips equal |")
    say("|---|---|---|---|---|---|")
    for r in out:
        ab = r["alt_blocks"]
        say(f"| `{r['case']}` | {r['chain_blocks']} | {r['longest_diff_le10_run']} "
            f"| {r['max_difficulty']} | {ab.get('attacker')}/{ab.get('h1')}/{ab.get('h2')} "
            f"| {r['converged']} |")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
