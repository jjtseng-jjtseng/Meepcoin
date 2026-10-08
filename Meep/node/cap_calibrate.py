#!/usr/bin/env python3
"""LD-cap: what does `mining_status.speed` actually measure, and what is real raw capacity?

The p2p_starvation run reported 0 H/s for whichever honest node was measured FIRST. cap_probe.py
showed the miner was NOT broken -- the node mined 5 blocks during the window that reported 0 H/s.
So `speed` was not under-reporting a working miner by accident; something about the chain state
made it read zero.

miner.cpp:
    merge_hr()  every 2 s:  m_current_hash_rate = m_hashes * 1000 / (elapsed_ms + 1)
    worker_thread():        ++m_hashes  once per hash attempt

Integer division floors to 0 only when the miner completed FEWER THAN ONE HASH PER SECOND. The
hypothesis is therefore: at difficulty ~1 essentially every hash wins, so the miner spends its time
waiting for a new block template rather than hashing, and `speed` correctly reports a near-zero
HASH rate for a node that is producing blocks as fast as it can.

This script tests that directly by recording (tip difficulty, speed) together as one daemon's
difficulty climbs from 1 upward, with no attacker and no consensus bypass.

If confirmed:
  * `speed` is only a valid capacity instrument where the miner is HASH-bound (high difficulty);
  * raw capacity must be measured in that regime and treated as a hardware constant;
  * an observed "hashrate collapse" at low difficulty is NOT by itself evidence of starvation.

LOCALHOST / PRIVATE THROWAWAY CHAIN. Dev/test coins with no monetary value.
"""
import json, os, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rpc, rest

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 35700))
SECS = int(ARG.get("--secs", 240))
THREADS = int(ARG.get("--threads", 4))
OUT = ARG.get("--out", "docs/lowdiff/cap_calibrate.json")


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


def main():
    os.makedirs(L.ROOT, exist_ok=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    gts = int(time.time())
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    # offline: no peers at all, so nothing external can affect the measurement
    d = L.Daemon("cap_cal", PORT, PORT + 1, fixed_diff=0, offline=True,
                 data_dir=os.path.join(L.ROOT, "cap_cal"))
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "binary": BIN, "binary_sha256": sha(BIN), "threads": THREADS,
           "genesis_ts": gts, "fixed_difficulty": "0 (disabled -- real difficulty algorithm)",
           "samples": []}
    try:
        d.wait_synced(60)
        g = rpc(d.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
        rec["genesis_hash"] = g["hash"]
        rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": THREADS,
                                      "do_background_mining": False, "ignore_battery": True})
        t0 = time.time()
        while time.time() - t0 < SECS:
            try:
                i = d.info()
                ms = rest(d.rpc, "/mining_status")
                h = int(i["height"])
                hdr = rpc(d.rpc, "get_block_header_by_height",
                          {"height": h - 1})["result"]["block_header"]
                rec["samples"].append({
                    "t": round(time.time() - t0, 2), "height": h,
                    "tip_difficulty": int(hdr["difficulty"]),
                    "cumulative_difficulty": int(hdr.get("cumulative_difficulty", 0)),
                    "speed": ms.get("speed"), "active": ms.get("active")})
            except Exception as e:
                rec["samples"].append({"t": round(time.time() - t0, 2),
                                       "error": f"{type(e).__name__}: {e}"})
            time.sleep(1.0)
        rest(d.rpc, "/stop_mining", {})
    finally:
        try: d.stop()
        except Exception: pass

    s = [x for x in rec["samples"] if "speed" in x and x.get("tip_difficulty") is not None]
    # bucket speed by tip difficulty
    buckets = [(0, 1), (2, 10), (11, 100), (101, 1000), (1001, 10 ** 4), (10 ** 4 + 1, 10 ** 12)]
    rec["speed_by_difficulty"] = []
    for lo, hi in buckets:
        v = [x["speed"] for x in s if lo <= x["tip_difficulty"] <= hi]
        if v:
            rec["speed_by_difficulty"].append({
                "difficulty_range": f"{lo}-{hi if hi < 10**12 else 'inf'}", "n": len(v),
                "speed_min": min(v), "speed_median": int(statistics.median(v)),
                "speed_max": max(v), "zero_samples": sum(1 for x in v if x == 0)})
    hashbound = [x["speed"] for x in s if x["tip_difficulty"] >= 1000 and x["speed"]]
    rec["raw_capacity_hs"] = {
        "definition": f"max mining_status.speed while tip difficulty >= 1000, {THREADS} threads",
        "n_samples": len(hashbound),
        "max": max(hashbound) if hashbound else None,
        "median": int(statistics.median(hashbound)) if hashbound else None}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)

    print(f"genesis {rec.get('genesis_hash','?')[:16]}  samples {len(s)}", flush=True)
    print(f"{'difficulty':>14} | {'n':>4} | {'speed min':>9} | {'median':>7} | {'max':>6} | zeros")
    for b in rec["speed_by_difficulty"]:
        print(f"{b['difficulty_range']:>14} | {b['n']:>4} | {b['speed_min']:>9} | "
              f"{b['speed_median']:>7} | {b['speed_max']:>6} | {b['zero_samples']}")
    print(f"\nraw capacity ({THREADS} threads, hash-bound regime): "
          f"max={rec['raw_capacity_hs']['max']} median={rec['raw_capacity_hs']['median']} H/s")
    print(f"written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
