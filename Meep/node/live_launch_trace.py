#!/usr/bin/env python3
"""Live launch validation for the provisional design: T1 + T2 + T4, difficulty algorithm UNCHANGED.

Runs against a real daemon on fresh throwaway chains with REAL automatic difficulty
(`--fixed-difficulty 0`). Every difficulty figure below is the daemon's own `next_difficulty()`
output; the Python re-computation is only used to expose the window internals and is checked against
the daemon's value on every block.

Sections
  honest   internal miner at a chosen thread count, per-block trace including the difficulty window,
           the sorted window, cut indices, span_cut, total work and the recomputed raw difficulty
  attack   five timestamp strategies, with the attacker computing legality under the PATCHED rule

Selected by env / args:
  MEEP_DAEMON      which binary to run
  --label=         name used in the report
  --threads=       miner threads for the honest run
  --budget=        wall-clock seconds for the honest run
  --target=        honest height target
  --attack=        comma list of strategies, or "none"
  --out=           output json path
  --report=        markdown path

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import (Daemon, rebuild, epee_median, rpc, rest, ADDR, DAEMON,  # noqa
                                  ROOT, TS_WINDOW)

FTL = 7200
DIFF_WINDOW = 720
DIFF_CUT = 60
DIFF_BLOCKS_COUNT = 735
TARGET = 60

LABEL, THREADS, BUDGET, HTARGET = "run", 4, 300, 100
ATTACKS = ["alt_lowest_max", "lowest_only", "max_future_only", "median_boundary", "honest_ts"]
OUTJSON, REPORT, PORT = "docs/live_trace.json", "docs/LIVE_TRACE.md", 29600
ATK_TARGET, ATK_BUDGET = 200, 420
for a in sys.argv[1:]:
    if a.startswith("--label="):   LABEL = a.split("=", 1)[1]
    if a.startswith("--threads="): THREADS = int(a.split("=", 1)[1])
    if a.startswith("--budget="):  BUDGET = int(a.split("=", 1)[1])
    if a.startswith("--target="):  HTARGET = int(a.split("=", 1)[1])
    if a.startswith("--attack="):  ATTACKS = [] if a.split("=", 1)[1] == "none" else a.split("=", 1)[1].split(",")
    if a.startswith("--out="):     OUTJSON = a.split("=", 1)[1]
    if a.startswith("--report="):  REPORT = a.split("=", 1)[1]
    if a.startswith("--port="):    PORT = int(a.split("=", 1)[1])
    if a.startswith("--attack-target="): ATK_TARGET = int(a.split("=", 1)[1])
    if a.startswith("--attack-budget="): ATK_BUDGET = int(a.split("=", 1)[1])

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def cut_of(n):
    if n <= DIFF_WINDOW - 2 * DIFF_CUT:
        return 0, n
    b = (n - (DIFF_WINDOW - 2 * DIFF_CUT) + 1) // 2
    return b, b + (DIFF_WINDOW - 2 * DIFF_CUT)


def next_difficulty_py(ts, cd):
    """cryptonote::next_difficulty, reimplemented to expose the internals. Verified against the
    daemon's own value on every block; any mismatch is reported, never hidden."""
    ts, cd = list(ts), list(cd)
    if len(ts) > DIFF_WINDOW:
        ts, cd = ts[:DIFF_WINDOW], cd[:DIFF_WINDOW]
    n = len(ts)
    if n <= 1:
        return 1, {"n": n, "cut_begin": 0, "cut_end": n, "span_cut": 0, "total_work": 0,
                   "sorted": [], "n_equal_adjacent": 0}
    srt = sorted(ts)
    cb, ce = cut_of(n)
    span = srt[ce - 1] - srt[cb]
    span_raw = span
    if span == 0:
        span = 1
    work = cd[ce - 1] - cd[cb]
    d = (work * TARGET + span - 1) // span
    n_eq = sum(1 for k in range(1, len(srt)) if srt[k] == srt[k - 1])
    return d, {"n": n, "cut_begin": cb, "cut_end": ce, "span_cut": span_raw,
               "span_used": span, "total_work": work, "sorted": srt[:24],
               "n_equal_adjacent": n_eq}


def headers(d, lo, hi):
    if hi < lo:
        return []
    return rpc(d.rpc, "get_block_headers_range",
               {"start_height": lo, "end_height": hi})["result"]["headers"]


def window_for(d, chain_h):
    """Exactly what get_difficulty_for_next_block collects: heights [h-735 .. h-1], genesis skipped
    when the chain is longer than the window."""
    lo = max(1, chain_h - DIFF_BLOCKS_COUNT)
    hs = headers(d, lo, chain_h - 1)
    return ([int(x["timestamp"]) for x in hs],
            [int(x["cumulative_difficulty"]) for x in hs])


def bound_t1t2(d, chain_h):
    parent_h = chain_h - 1
    lo = max(0, parent_h - (TS_WINDOW - 1))
    win = [int(x["timestamp"]) for x in headers(d, lo, parent_h)] if chain_h > 0 else []
    return (epee_median(win) if win else None), win


def honest_run(port, threads, budget, target):
    d = Daemon(f"lt_h{port}", port, port + 1, fixed_diff=0)
    rows, t0 = [], time.time()
    stop_reason = "reached height target"
    try:
        r = rest(d.rpc, "/start_mining", {"miner_address": ADDR, "threads_count": threads,
                                          "do_background_mining": False, "ignore_battery": True})
        if r.get("status") != "OK":
            raise RuntimeError(f"start_mining refused: {r}")
        seen = 1
        while True:
            h = d.height()
            if h > target:
                break
            if time.time() - t0 > budget:
                stop_reason = f"wall-clock budget {budget} s exhausted at height {h}"
                break
            if h <= seen:
                time.sleep(0.2); continue
            for ht in range(seen, h):
                wall = time.time()
                hdr = rpc(d.rpc, "get_block_header_by_height",
                          {"height": ht})["result"]["block_header"]
                ts, cd = window_for(d, ht)
                raw, meta = next_difficulty_py(ts, cd)
                med, medwin = bound_t1t2(d, ht)
                prev_ts = rows[-1]["timestamp"] if rows else None
                rows.append(dict(
                    height=ht, timestamp=int(hdr["timestamp"]),
                    wall_accept=wall,
                    interval=(int(hdr["timestamp"]) - prev_ts) if prev_ts is not None else None,
                    difficulty_used=int(hdr["difficulty"]),
                    cumulative_difficulty=int(hdr["cumulative_difficulty"]),
                    median_bound=med, t1_clamped=(med is not None and int(hdr["timestamp"]) == med),
                    same_second_in_window=meta["n_equal_adjacent"],
                    window_n=meta["n"], cut_begin=meta["cut_begin"], cut_end=meta["cut_end"],
                    span_cut=meta["span_cut"], span_used=meta.get("span_used"),
                    total_work=meta["total_work"], raw_next_difficulty=raw,
                    sorted_head=meta["sorted"], block_hash=hdr["hash"]))
            seen = h
        final_h = d.height()
        final_diff = int(d.template()["difficulty"])
        try:
            ms = rest(d.rpc, "/mining_status")
            hashrate = ms.get("speed", 0)
        except Exception:
            hashrate = None
    finally:
        try: rest(d.rpc, "/stop_mining", {})
        except Exception: pass
        d.stop()
    return dict(rows=rows, final_height=final_h, final_difficulty=final_diff,
                hashrate=hashrate, threads=threads, seconds=round(time.time() - t0, 1),
                stop_reason=stop_reason)


def attack_run(port, strategy, target=200, budget=420):
    d = Daemon(f"lt_a{port}", port, port + 1, fixed_diff=0)
    rows, t0 = [], time.time()
    stop_reason = "reached height target"
    rejected_here = 0
    try:
        while d.height() <= target:
            if time.time() - t0 > budget:
                stop_reason = f"budget {budget} s exhausted"; break
            ch = d.height()
            t = d.template()
            diff = int(t["difficulty"])
            med, _ = bound_t1t2(d, ch)
            lo = med if med is not None else 0
            now = int(time.time())
            hi = now + FTL - 5
            if strategy == "alt_lowest_max":     ts = hi if ch % 2 == 0 else lo
            elif strategy == "lowest_only":      ts = lo
            elif strategy == "max_future_only":  ts = hi
            elif strategy == "median_boundary":  ts = lo
            elif strategy == "honest_ts":        ts = None
            else: raise ValueError(strategy)
            ok = False
            for i in range(300):
                ok, err, _ = d.submit(rebuild(t["blocktemplate_blob"], ts=ts,
                                              nonce=ch * 100003 + i))
                if ok: break
            rows.append(dict(height=ch, lower_bound=lo, upper_bound=hi, chosen=ts,
                             difficulty=diff, accepted=ok))
            if not ok:
                rejected_here += 1
                if rejected_here >= 3:
                    stop_reason = f"height {ch} rejected 3x: {err}"; break
            else:
                rejected_here = 0
        final_h, final_diff = d.height(), int(d.template()["difficulty"])
    finally:
        d.stop()
    acc = [r for r in rows if r["accepted"]]
    run = best = 0
    for r in acc:
        if r["difficulty"] <= 10: run += 1; best = max(best, run)
        else: run = 0
    first = {}
    for thr in (1, 10, 100, 1000):
        m = next((r["height"] for r in acc if r["difficulty"] > thr), None)
        first[f"first_above_{thr}"] = m
    return dict(strategy=strategy, rows=rows, accepted=len(acc), final_height=final_h,
                final_difficulty=final_diff, longest_min_run=best,
                near_min_frac=(sum(1 for r in acc if r["difficulty"] <= 10) / len(acc)) if acc else 0,
                milestones=first,
                beyond_60=(final_h > 61 and best > 0), seconds=round(time.time() - t0, 1),
                stop_reason=stop_reason)


def main():
    os.makedirs(ROOT, exist_ok=True)
    # The genesis timestamp is COMPILED IN, so the config file on disk is not authoritative -- an
    # earlier run read it from there and mislabelled a stale-genesis binary as fresh. Ask the daemon.
    genesis_ts, genesis_hash = 0, "?"
    _probe = Daemon("gts", PORT + 90, PORT + 91, fixed_diff=1)
    try:
        _h = rpc(_probe.rpc, "get_block_header_by_height",
                 {"height": 0})["result"]["block_header"]
        genesis_ts, genesis_hash = int(_h["timestamp"]), _h["hash"]
    finally:
        _probe.stop()
    now = int(time.time())
    dh = subprocess.run(["sha256sum", DAEMON], capture_output=True, text=True).stdout.split()[0]

    say(f"# MeepCoin — Live Launch Trace: {LABEL}")
    say()
    say("> **ANALYSIS ONLY.** Fresh throwaway chains, REAL automatic difficulty. Provisional design")
    say("> under test: T1 + T2 + T4, difficulty algorithm UNCHANGED. No frozen tag, preserved chain,")
    say("> wallet or public infrastructure touched. Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Daemon: `{DAEMON}`")
    say(f"- Daemon sha256: `{dh}`")
    say(f"- **Genesis timestamp {genesis_ts} (read from the daemon, block 0), hash "
        f"`{genesis_hash[:16]}…`; age at start of run {now - genesis_ts} s "
        f"({(now - genesis_ts)/86400.0:.3f} days)**")
    say()

    out = {"label": LABEL, "daemon": DAEMON, "daemon_sha256": dh,
           "genesis_ts": genesis_ts, "genesis_hash": genesis_hash,
           "genesis_age_s": now - genesis_ts}

    hr = honest_run(PORT, THREADS, BUDGET, HTARGET)
    out["honest"] = hr
    rows = hr["rows"]
    say("## Honest launch")
    say()
    say(f"- threads {hr['threads']}, budget {BUDGET} s, ran {hr['seconds']} s, "
        f"reached height {hr['final_height']}, stopped: {hr['stop_reason']}")
    if hr["hashrate"]:
        say(f"- miner speed reported by the daemon: {hr['hashrate']} H/s")
    if rows:
        peak = max(r["difficulty_used"] for r in rows)
        peak_h = next(r["height"] for r in rows if r["difficulty_used"] == peak)
        ivs = [r["interval"] for r in rows if r["interval"] is not None]
        worst = max(ivs) if ivs else 0
        say(f"- **peak difficulty {peak} at height {peak_h}**, worst inter-block interval "
            f"{worst} s, any block over 30 min: **{'YES' if worst > 1800 else 'no'}**")
        mism = [r for r in rows if r["height"] >= 2 and r["raw_next_difficulty"] != r["difficulty_used"]]
        say(f"- recomputed raw next_difficulty vs the daemon's own value: "
            f"**{len(mism)} mismatches out of {len(rows)}**")
    say()
    say("### Per-block trace (first 24 heights)")
    say()
    say("| h | timestamp | iv | median bound | clamped | n_win | n_eq | cut | **span_cut** "
        "| total work | raw next | difficulty used |")
    say("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows[:24]:
        say(f"| {r['height']} | {r['timestamp']} | {r['interval']} | {r['median_bound']} "
            f"| {'yes' if r['t1_clamped'] else 'no'} | {r['window_n']} | {r['same_second_in_window']} "
            f"| {r['cut_begin']}–{r['cut_end']} | **{r['span_cut']}** | {r['total_work']} "
            f"| {r['raw_next_difficulty']} | {r['difficulty_used']} |")
    say()

    if ATTACKS:
        say("## Adaptive attacker (legality computed under the PATCHED rule)")
        say()
        say("| strategy | accepted | final height | final difficulty | longest difficulty-1 run "
            "| near-minimum share | past height 60 | stopped |")
        say("|---|---|---|---|---|---|---|---|")
        out["attacks"] = []
        p = PORT + 20
        for st in ATTACKS:
            try:
                a = attack_run(p, st, ATK_TARGET, ATK_BUDGET)
                out["attacks"].append(a)
                say(f"| `{st}` | {a['accepted']} | {a['final_height']} | {a['final_difficulty']} "
                    f"| **{a['longest_min_run']}** | {100*a['near_min_frac']:.0f}% "
                    f"| {'yes' if a['beyond_60'] else 'no'} | {a['stop_reason']} |")
                m = a.get("milestones", {})
                say(f"|   ↳ first height with difficulty above 1 / 10 / 100 / 1000 "
                    f"| {m.get('first_above_1')} | {m.get('first_above_10')} "
                    f"| {m.get('first_above_100')} | {m.get('first_above_1000')} | | | |")
            except Exception as e:
                say(f"| `{st}` | — | — | — | — | — | — | ERROR `{type(e).__name__}: {e}` |")
            p += 20
        say()

    say("_Dev/test coins on private localhost chains. No monetary value._")
    os.makedirs(os.path.dirname(OUTJSON) or ".", exist_ok=True)
    json.dump(out, open(OUTJSON, "w", encoding="utf-8"))
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT} and {OUTJSON}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
