#!/usr/bin/env python3
"""Collect a per-block difficulty trace from a LIVE daemon and verify it against next_difficulty.

Two jobs:
  1. Record what is needed per block: height, timestamp, difficulty, interval.
  2. FIDELITY CHECK -- recompute each block's difficulty independently from the preceding
     timestamps and cumulative difficulties, using the same window the daemon uses, and compare.
     If the daemon and the independent recomputation disagree, the simulator's results do not
     transfer to the real chain and must not be reported as if they did.

Usage: collect_difficulty_trace.py <rpc_port> [out.csv]

LOCALHOST / PRIVATE TEST CHAIN. Dev/test coins with no monetary value.
"""
import json, sys, urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 24081
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/difftest_trace.csv"

DIFFICULTY_WINDOW = 720
DIFFICULTY_LAG = 15
DIFFICULTY_CUT = 60
DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG
TARGET = 60


def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read())
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]


def next_difficulty(timestamps, cumulative, target):
    """Port of cryptonote::next_difficulty, used ONLY as an independent cross-check."""
    ts = list(timestamps)
    cd = list(cumulative)
    if len(ts) > DIFFICULTY_WINDOW:
        ts = ts[:DIFFICULTY_WINDOW]
        cd = cd[:DIFFICULTY_WINDOW]
    length = len(ts)
    if length <= 1:
        return 1
    ts.sort()
    if length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT:
        cut_begin, cut_end = 0, length
    else:
        cut_begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) // 2
        cut_end = cut_begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT)
    time_span = ts[cut_end - 1] - ts[cut_begin]
    if time_span == 0:
        time_span = 1
    total_work = cd[cut_end - 1] - cd[cut_begin]
    return (total_work * target + time_span - 1) // time_span


def main():
    height = int(rpc("get_last_block_header")["block_header"]["height"])
    print(f"chain tip height {height}; fetching headers 0..{height}")

    hdrs = []
    step = 200
    for lo in range(0, height + 1, step):
        hi = min(lo + step - 1, height)
        r = rpc("get_block_headers_range", {"start_height": lo, "end_height": hi})
        hdrs.extend(r["headers"])
    hdrs.sort(key=lambda h: h["height"])
    print(f"got {len(hdrs)} headers")

    rows = []
    agree = disagree = skipped = 0
    for i, h in enumerate(hdrs):
        interval = 0 if i == 0 else int(h["timestamp"]) - int(hdrs[i - 1]["timestamp"])
        recomputed = None
        if i >= 1:
            lo = max(0, i - DIFFICULTY_BLOCKS_COUNT)
            window = [w for w in hdrs[lo:i] if int(w["height"]) >= 1]
            if len(window) >= 2:
                ts = [int(w["timestamp"]) for w in window]
                cd = [int(w["cumulative_difficulty"]) for w in window]
                recomputed = next_difficulty(ts, cd, TARGET)
        d = int(h["difficulty"])
        if recomputed is None:
            skipped += 1
        elif recomputed == d:
            agree += 1
        else:
            disagree += 1
        rows.append((int(h["height"]), int(h["timestamp"]), interval, d,
                     int(h["cumulative_difficulty"]), recomputed))

    with open(OUT, "w") as f:
        f.write("height,timestamp,interval_s,difficulty,cumulative_difficulty,recomputed\n")
        for r in rows:
            f.write(",".join("" if x is None else str(x) for x in r) + "\n")
    print(f"wrote {OUT}")
    print()

    print("=== per-block trace ===")
    print(f"{'height':>7} {'timestamp':>12} {'interval':>9} {'difficulty':>14} {'recomputed':>14}")
    show = rows[:26]
    if len(rows) > 38:
        show = rows[:26] + [None] + rows[-12:]
    for r in show:
        if r is None:
            print("    ...")
            continue
        rc = "" if r[5] is None else str(r[5])
        print(f"{r[0]:>7} {r[1]:>12} {r[2]:>9} {r[3]:>14} {rc:>14}")

    print()
    ivs = [r[2] for r in rows[1:]]
    if ivs:
        s = sorted(ivs)
        print(f"intervals: n={len(ivs)} mean={sum(ivs)/len(ivs):.1f}s "
              f"median={s[len(s)//2]}s max={max(ivs)}s target={TARGET}s")
    ds = [r[3] for r in rows]
    print(f"difficulty: min={min(ds)} max={max(ds)} last={ds[-1]}")
    print()
    print(f"FIDELITY: daemon vs independent recomputation -> "
          f"{agree} agree, {disagree} disagree, {skipped} not comparable")
    verdict = "PASS" if (disagree == 0 and agree > 0) else ("FAIL" if disagree else "INCONCLUSIVE")
    print("DIFFICULTY TRACE FIDELITY: " + verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
