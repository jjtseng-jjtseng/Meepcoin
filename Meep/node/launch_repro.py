#!/usr/bin/env python3
"""Task 1 — clean live reproduction of the launch-window timestamp defect.

Seven timestamp strategies, each on its OWN freshly wiped chain, mined from genesis with the REAL
automatic difficulty algorithm (`--fixed-difficulty 0`, so `Blockchain::get_difficulty_for_next_block`
computes every value). Nothing is forced.

Per-block evidence is written to `docs/launch_repro/<strategy>.jsonl`, one JSON object per
submission, holding: full serialized block, block hash, parent hash, height, timestamp, validator
wall-clock time, calculated lower and upper timestamp bounds, difficulty used to mine the block,
calculated next difficulty, daemon response, relevant daemon log lines, and whether proof-of-work
validation was reached.

Recording policy, stated rather than implied: strategies that hold difficulty at 1 need exactly one
submission per height, so every submission is recorded in full. Strategies whose difficulty rises
need repeated nonces; for those, every submission that is rejected for a NON-proof-of-work reason is
recorded in full, and consecutive proof-of-work misses at one height are collapsed into a single
record carrying the attempt count and the first blob. No timestamp-relevant event is ever collapsed.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value. The frozen devnet at
~/.meepcoin-devnet is never opened.
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, ROOT, TS_WINDOW  # noqa: E402

FTL = 7200
GENESIS_TS = 1785283200
TARGET_H = 200
OUTDIR = "docs/launch_repro"
REPORT = "docs/LAUNCH_REPRO.md"
# --outdir / --report let the same harness be run twice -- once against the baseline daemon and once
# against a candidate build -- without either run overwriting the other's evidence.
for _a in sys.argv[1:]:
    if _a.startswith("--outdir="):
        OUTDIR = _a.split("=", 1)[1]
    if _a.startswith("--report="):
        REPORT = _a.split("=", 1)[1]
PER_BLOCK_NONCE_BUDGET = 300
# --rule selects which timestamp rule the ATTACKER models when it computes "the lowest legal value".
# Running an upstream-modelled attacker against a T1+T2 daemon understates the fix, because the
# attacker keeps writing 0 and is trivially rejected. Set --rule=t1t2 when testing the patched build.
RULE = "upstream"
for _a in sys.argv[1:]:
    if _a.startswith("--rule="):
        RULE = _a.split("=", 1)[1]
lines = []


def say(s=""):
    print(s, flush=True)
    lines.append(s)


def classify_pow(log, accepted):
    """Was proof-of-work validation reached? Decided from the daemon's own log line."""
    blob = " ".join(log)
    if "less than median" in blob or "bigger than local time" in blob:
        return False, "rejected at the timestamp check, which runs before PoW"
    if "does not have enough proof of work" in blob:
        return True, "rejected at the PoW check, so PoW was reached"
    if accepted:
        return True, "accepted, so every check including PoW passed"
    return None, "no decisive log line"


def bounds(d, chain_h, now):
    """The lower bound in force under the selected rule, plus the available-history median."""
    all_ts = d.timestamps(0, chain_h - 1) if chain_h > 0 else []
    avail_median = epee_median(all_ts) if all_ts else None
    if RULE == "t1t2":
        # one shared window [max(0, p-59) .. p], genesis included, applying at every height
        parent_h = chain_h - 1
        lo = max(0, parent_h - (TS_WINDOW - 1))
        win = d.timestamps(lo, parent_h) if chain_h > 0 else []
        return {"applies": bool(win), "value": epee_median(win) if win else None,
                "reason": f"T1+T2 shared window, heights {lo}..{parent_h} (n={len(win)})",
                "available_history_median": avail_median,
                "available_history_n": len(all_ts)}, now + FTL
    if chain_h < TS_WINDOW:
        return {"applies": False, "value": None,
                "reason": f"chain_h {chain_h} < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {TS_WINDOW};"
                          " check_block_timestamp returns true before computing any median",
                "available_history_median": avail_median,
                "available_history_n": len(all_ts)}, now + FTL
    win = d.timestamps(chain_h - TS_WINDOW, chain_h - 1)
    return {"applies": True, "value": epee_median(win),
            "reason": f"median of heights {chain_h-TS_WINDOW}..{chain_h-1} (n={len(win)})",
            "available_history_median": avail_median,
            "available_history_n": len(all_ts)}, now + FTL


# "Maximum legal future timestamp" is taken 5 s inside the limit. Sitting exactly on now+FTL loses
# a race: seconds elapse between this script reading the clock and the daemon calling time(NULL) in
# check_block_timestamp, so the block arrives already past the bound. The exact boundary is not being
# re-measured here -- it was established separately as +7200 accepted / +7201 rejected.
FTL_MARGIN = 5


def pick_ts(strategy, chain_h, lb, now):
    am = lb["available_history_median"]
    base = lb["value"] if lb["applies"] else (am if am is not None else GENESIS_TS)
    max_future = now + FTL - FTL_MARGIN
    if strategy == "honest":            return None
    if strategy == "zero":              return 0
    if strategy == "alt_zero_max":      return max_future if chain_h % 2 == 0 else 0
    if strategy == "alt_genesis_max":   return max_future if chain_h % 2 == 0 else GENESIS_TS
    if strategy == "median":            return base
    if strategy == "median_minus_1":    return max(0, base - 1)
    if strategy == "median_plus_1":     return base + 1
    # The adaptive attacker. alt_zero_max writes a literal 0 on odd heights, so it self-terminates
    # at height 61 the moment the median rule starts applying -- that is a limit of the STRATEGY,
    # not of the attack class. This variant always writes the LOWEST value that is legal right now:
    # 0 while the rule does not apply, the median itself once it does.
    if strategy == "alt_lowest_max":
        return max_future if chain_h % 2 == 0 else (lb["value"] if lb["applies"] else 0)
    if strategy == "lowest_only":
        return lb["value"] if lb["applies"] else 0
    if strategy == "max_future_only":
        return max_future
    raise ValueError(strategy)


def run_honest_internal(port, budget_s):
    """The honest chain cannot be brute-forced through `submit_block`: its own launch spike puts
    difficulty beyond reach within a few blocks. It is therefore mined by the daemon's INTERNAL
    miner, which builds templates with the daemon's own clock -- the definition of honest -- at this
    host's real MeepHash-W hashrate. Every accepted block is then read back in full.

    Stated limitation: `validator_wall_clock` for these rows is the time this script OBSERVED the
    block, not the instant the daemon validated it. Every other field is exact."""
    os.makedirs(OUTDIR, exist_ok=True)
    path = os.path.join(OUTDIR, "honest.jsonl")
    fh = open(path, "w", encoding="utf-8", newline="\n")
    from live_median_boundary import rpc, rest, ADDR
    d = Daemon("lr_honest", port, port + 1, fixed_diff=0)
    t_start = time.time()
    seen, n_acc = 1, 0
    stop_reason = "reached the height target"
    try:
        # start_mining / stop_mining are REST endpoints, NOT json_rpc methods.
        r = rest(d.rpc, "/start_mining", {"miner_address": ADDR, "threads_count": 8,
                                          "do_background_mining": False, "ignore_battery": True})
        if r.get("status") != "OK":
            raise RuntimeError(f"start_mining refused: {r}")
        while True:
            h = d.height()
            if h > TARGET_H:
                break
            if time.time() - t_start > budget_s:
                stop_reason = (f"wall-clock budget of {budget_s} s exhausted while mining at "
                               f"difficulty {int(d.template()['difficulty'])}")
                break
            if h <= seen:
                time.sleep(0.25)
                continue
            for height in range(seen, h):
                wall = time.time()
                blk = rpc(d.rpc, "get_block", {"height": height})["result"]
                hdr = blk["block_header"]
                lb, ub = bounds(d, height, int(hdr["timestamp"]))
                fh.write(json.dumps(dict(
                    strategy="honest", height=height, attempt=0, accepted=True,
                    daemon_response="OK (internally mined)",
                    validator_wall_clock=wall,
                    validator_wall_clock_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall)),
                    validator_wall_clock_note="observation time, not validation time",
                    timestamp_written=int(hdr["timestamp"]),
                    lower_bound=lb, upper_bound_ftl=ub,
                    difficulty_used=int(hdr["difficulty"]),
                    parent_hash=hdr["prev_hash"], block_hash=hdr["hash"],
                    block_blob=blk.get("blob"),
                    pow_reached=True,
                    pow_verdict="accepted by the daemon's own miner, so every check passed",
                    daemon_log=[])) + "\n")
                n_acc += 1
            fh.flush()
            seen = h
        final_h = d.height()
        final_diff = int(d.template()["difficulty"])
    finally:
        try: rest(d.rpc, "/stop_mining", {})
        except Exception: pass
        d.stop()
        fh.close()
    return dict(strategy="honest", accepted=n_acc, final_height=final_h,
                final_difficulty=final_diff, stop_reason=stop_reason,
                seconds=round(time.time() - t_start, 1), path=path)


def run_strategy(strategy, port, budget_s):
    if strategy == "honest":
        return run_honest_internal(port, budget_s)
    os.makedirs(OUTDIR, exist_ok=True)
    path = os.path.join(OUTDIR, f"{strategy}.jsonl")
    fh = open(path, "w", encoding="utf-8", newline="\n")
    d = Daemon(f"lr_{strategy}", port, port + 1, fixed_diff=0)
    t_start = time.time()
    n_acc = 0
    rejected_here = 0
    stop_reason = "reached the height target"
    try:
        while d.height() <= TARGET_H:
            if time.time() - t_start > budget_s:
                stop_reason = f"wall-clock budget of {budget_s} s exhausted"
                break
            chain_h = d.height()
            t = d.template()
            diff_used = int(t["difficulty"])
            now = int(time.time())
            lb, ub = bounds(d, chain_h, now)
            ts = pick_ts(strategy, chain_h, lb, now)

            pow_misses, first_miss_blob, done = 0, None, False
            for i in range(PER_BLOCK_NONCE_BUDGET):
                blob = rebuild(t["blocktemplate_blob"], ts=ts, nonce=chain_h * 100003 + i)
                d.mark_log()
                wall = time.time()
                ok, err, dt = d.submit(blob)
                log = [l.split(chr(9))[-1] for l in d.new_log()
                       if any(k in l for k in ("timestamp", "Timestamp", "proof of work",
                                               "Block with id", "invalid"))]
                reached, why_reached = classify_pow(log, ok)

                if (not ok) and reached is True and "proof of work" in " ".join(log):
                    pow_misses += 1
                    if first_miss_blob is None:
                        first_miss_blob = blob
                    continue

                rec = dict(strategy=strategy, height=chain_h, attempt=i,
                           accepted=ok, daemon_response=("OK" if ok else err),
                           submit_ms=round(1000 * dt, 3),
                           validator_wall_clock=wall,
                           validator_wall_clock_utc=time.strftime(
                               "%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall)),
                           timestamp_written=ts if ts is not None
                                              else int(t["blocktemplate_blob"] and 0) or None,
                           lower_bound=lb, upper_bound_ftl=ub,
                           difficulty_used=diff_used,
                           parent_hash=t["prev_hash"], block_blob=blob,
                           pow_reached=reached, pow_verdict=why_reached,
                           daemon_log=log, pow_misses_before=pow_misses,
                           first_pow_miss_blob=first_miss_blob)
                if ok:
                    hdr = d.rpc_block_header(chain_h)
                    rec["block_hash"] = hdr.get("hash")
                    rec["timestamp_written"] = hdr.get("timestamp")
                    rec["next_difficulty"] = int(d.template()["difficulty"])
                    n_acc += 1
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                done = True
                break
            if not done:
                fh.write(json.dumps(dict(
                    strategy=strategy, height=chain_h, accepted=False,
                    daemon_response=f"proof-of-work budget of {PER_BLOCK_NONCE_BUDGET} exhausted",
                    difficulty_used=diff_used, lower_bound=lb, upper_bound_ftl=ub,
                    parent_hash=t["prev_hash"], first_pow_miss_blob=first_miss_blob,
                    pow_misses_before=pow_misses, pow_reached=True,
                    pow_verdict="every attempt reached PoW and failed it")) + "\n")
                fh.flush()
                stop_reason = (f"proof-of-work became infeasible at difficulty {diff_used}"
                               f" after {PER_BLOCK_NONCE_BUDGET} nonces")
                break
            if not ok:
                rejected_here += 1
                if rejected_here >= 3:
                    stop_reason = (f"height {chain_h} rejected {rejected_here} times running: {err}"
                                   f" -- the strategy cannot extend the chain past this point")
                    break
            else:
                rejected_here = 0
        final_h = d.height()
        final_diff = int(d.template()["difficulty"])
    finally:
        d.stop()
        fh.close()
    return dict(strategy=strategy, accepted=n_acc, final_height=final_h,
                final_difficulty=final_diff, stop_reason=stop_reason,
                seconds=round(time.time() - t_start, 1), path=path)


def main():
    os.makedirs(ROOT, exist_ok=True)
    say("# MeepCoin — Live Launch-Window Reproduction (task 1)")
    say()
    say("> **ANALYSIS ONLY.** Fresh isolated throwaway chains, own data dirs and ports, REAL")
    say("> automatic difficulty (`--fixed-difficulty 0`). No consensus, genesis, economics, frozen")
    say("> tag, existing chain database, wallet or public infrastructure is touched.")
    say("> Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Height target {TARGET_H}; per-height proof-of-work budget {PER_BLOCK_NONCE_BUDGET}"
        f" nonces via `submit_block`")
    say(f"- Per-block evidence: `{OUTDIR}/<strategy>.jsonl`")
    say()

    plan = [("honest", 26400, 900), ("zero", 26410, 300), ("alt_zero_max", 26420, 300),
            ("alt_genesis_max", 26430, 300), ("median", 26440, 300),
            ("median_minus_1", 26450, 300), ("median_plus_1", 26460, 300),
            ("alt_lowest_max", 26470, 420), ("lowest_only", 26480, 420),
            ("max_future_only", 26490, 420)]
    # --only lets an interrupted run resume without discarding strategies that already finished;
    # their summaries are reloaded from disk so the report still covers all seven.
    only = None
    for a in sys.argv[1:]:
        if a.startswith("--only="):
            only = set(a.split("=", 1)[1].split(","))
    out = []
    for strat, port, budget in plan:
        summ = os.path.join(OUTDIR, f"{strat}.summary.json")
        if only is not None and strat not in only:
            if os.path.exists(summ):
                r = json.load(open(summ, encoding="utf-8"))
                out.append(r)
                say(f"reusing completed `{strat}` from a previous run "
                    f"(height {r['final_height']}, {r['accepted']} accepted)")
            else:
                say(f"skipping `{strat}` -- not selected and no previous result on disk")
            continue
        say(f"running `{strat}` …")
        r = run_strategy(strat, port, budget)
        os.makedirs(OUTDIR, exist_ok=True)
        json.dump(r, open(summ, "w", encoding="utf-8"))
        out.append(r)
        say(f"  -> height {r['final_height']}, final difficulty {r['final_difficulty']}, "
            f"{r['accepted']} accepted, {r['seconds']} s, stopped: {r['stop_reason']}")
    say()

    say("## Summary")
    say()
    say("| strategy | accepted blocks | final height | final difficulty | stopped because |")
    say("|---|---|---|---|---|")
    for r in out:
        say(f"| `{r['strategy']}` | {r['accepted']} | {r['final_height']} | "
            f"{r['final_difficulty']} | {r['stop_reason']} |")
    say()

    say("## Difficulty trajectory, first 24 heights")
    say()
    hdr = "| height | " + " | ".join(f"`{r['strategy']}`" for r in out) + " |"
    say(hdr)
    say("|" + "---|" * (len(out) + 1))
    traj = {}
    for r in out:
        traj[r["strategy"]] = {}
        for line in open(r["path"], encoding="utf-8"):
            o = json.loads(line)
            if o.get("accepted"):
                traj[r["strategy"]][o["height"]] = o["difficulty_used"]
    for h in range(24):
        say(f"| {h} | " + " | ".join(str(traj[r['strategy']].get(h, "—")) for r in out) + " |")
    say()

    say("## Peak and final difficulty over the whole run")
    say()
    say("| strategy | peak difficulty | height of peak | difficulty at last accepted height |")
    say("|---|---|---|---|")
    for r in out:
        t = traj[r["strategy"]]
        if not t:
            say(f"| `{r['strategy']}` | — | — | — |"); continue
        pk = max(t.values()); pkh = max(h for h, v in t.items() if v == pk)
        last = t[max(t)]
        say(f"| `{r['strategy']}` | {pk} | {pkh} | {last} |")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
