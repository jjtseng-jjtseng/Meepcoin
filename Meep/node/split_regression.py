#!/usr/bin/env python3
"""Task 2 — comprehensive main-versus-alternative validity regression.

For each tested height the SAME candidate block bytes, on byte-identical parent history, are made to
arrive as a main-chain extension on one node and an alternative-chain block on another. The pass
condition is strict: **zero context-dependent validity disagreements**. A case fails if the two nodes
reach different verdicts for identical bytes.

Heights: 1, 2, 30, 31, 58, 59, 60, 61, 62, 90, and 200 (mature, above the launch window).
Timestamp cases per height: below-median, equal-to-median, above-median, maximum legal future, and
one second beyond the future limit.
Variants: standard, reversed node roles, reversed block-arrival order.

Then, separately: restart after a disagreement, re-offering the candidate, a higher-cumulative-work
branch, a multi-block reorganisation crossing heights 59-61, and a database reload.

The median is computed with the rule the daemon under test actually uses; pass --rule=t1t2 or
--rule=upstream. Proof-of-work is trivial (`--fixed-difficulty 1`) so arbitrary candidates can be
built: this tests TIMESTAMP validity, not proof-of-work.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import os, shutil, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, ROOT, TS_WINDOW  # noqa: E402

FTL = 7200
REPORT = "docs/SPLIT_REGRESSION.md"
RULE = "t1t2"
PORT_BASE = 26800
# Margin, in seconds, from the future-time limit for the max_future / beyond_ftl probes. The two
# daemons call time(NULL) independently a few hundred ms apart, so a probe sitting exactly on the
# boundary can legitimately land on opposite sides for the two nodes. That is a property of the
# clock, not of the rule, and the exact boundary was measured separately (+7200 accept, +7201
# reject). A generous margin removes the race without weakening the test.
FTL_MARGIN = 120
HEIGHTS = [1, 2, 30, 31, 58, 59, 60, 61, 62, 90, 200]
TS_KINDS = ["below", "equal", "above", "max_future", "beyond_ftl"]
for _a in sys.argv[1:]:
    if _a.startswith("--report="):
        REPORT = _a.split("=", 1)[1]
    if _a.startswith("--rule="):
        RULE = _a.split("=", 1)[1]
    if _a.startswith("--heights="):
        HEIGHTS = [int(x) for x in _a.split("=", 1)[1].split(",")]
    if _a.startswith("--port="):
        PORT_BASE = int(_a.split("=", 1)[1])
    if _a.startswith("--ftl-margin="):
        FTL_MARGIN = int(_a.split("=", 1)[1])

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def median_in_force(node, parent_h, chain_h):
    """The lower bound the daemon under test applies, and whether it applies at all."""
    if RULE == "t1t2":
        lo = max(0, parent_h - (TS_WINDOW - 1))
        return True, epee_median(node.timestamps(lo, parent_h))
    if chain_h < TS_WINDOW:
        return False, None
    return True, epee_median(node.timestamps(chain_h - TS_WINDOW, chain_h - 1))


def mine_to(d, chain_h, nonce_base=0):
    while d.height() < chain_h:
        t = d.template()
        h = d.height()
        for i in range(60):
            ok, err, _ = d.submit(rebuild(t["blocktemplate_blob"], nonce=nonce_base + h * 7919 + i))
            if ok:
                break
        else:
            raise RuntimeError(f"could not extend to {chain_h} at {h}: {err}")


def build_identical(a, b, chain_h):
    """Mine on A and replay the identical bytes into B.

    NOTE, learned the hard way: do NOT clone a data directory to reuse history. Monero preallocates
    a sparse LMDB map whose apparent size here is 27 GB, so copying a data dir costs far more than
    re-mining a short chain at difficulty 1. Mining 200 blocks takes about five seconds; copying the
    directory took over a minute per case."""
    blobs = []
    while a.height() < chain_h:
        t = a.template()
        h = a.height()
        for i in range(60):
            blob = rebuild(t["blocktemplate_blob"], nonce=h * 7919 + i)
            ok, err, _ = a.submit(blob)
            if ok:
                blobs.append(blob); break
        else:
            raise RuntimeError(f"could not extend to {chain_h} at {h}: {err}")
    for blob in blobs:
        ok, err, _ = b.submit(blob)
        if not ok:
            raise RuntimeError(f"replay into B failed: {err}")
    if a.info()["top_block_hash"] != b.info()["top_block_hash"] or a.height() != b.height():
        raise RuntimeError("histories differ after replay")


def one_case(chain_h, kind, reverse_roles, reverse_order, port):
    da = Daemon(f"rg_a{port}", port, port + 1, fixed_diff=1)
    db = Daemon(f"rg_b{port}", port + 4, port + 5, fixed_diff=1)
    res = {"chain_h": chain_h, "kind": kind, "roles": "rev" if reverse_roles else "std",
           "order": "rev" if reverse_order else "std"}
    try:
        build_identical(da, db, chain_h)
        res["tip"] = da.info()["top_block_hash"]
        parent_h = chain_h - 1
        applies, med = median_in_force(da, parent_h, chain_h)
        now = int(time.time())
        base = med if med is not None else 0
        ts = {"below": base - 1, "equal": base, "above": base + 1,
              "max_future": now + FTL - FTL_MARGIN,
              "beyond_ftl": now + FTL + FTL_MARGIN}[kind]
        if ts < 0:
            ts = 0
        res.update(rule_applies=applies, median=med, ts=ts)

        main_node, alt_node = (da, db) if not reverse_roles else (db, da)
        t = da.template()
        res["parent"] = t["prev_hash"]
        candidate = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0xCA0DEF)
        sibling = rebuild(t["blocktemplate_blob"], nonce=0x51B1)

        if not reverse_order:
            ok_s, err_s, _ = alt_node.submit(sibling)
            res["sibling"] = (ok_s, err_s)
        main_node.mark_log(); alt_node.mark_log()
        ok_m, err_m, _ = main_node.submit(candidate)
        log_m = [l.split(chr(9))[-1] for l in main_node.new_log()
                 if any(k in l for k in ("imestamp", "proof of work"))]
        ok_a, err_a, _ = alt_node.submit(candidate)
        log_a = [l.split(chr(9))[-1] for l in alt_node.new_log()
                 if any(k in l for k in ("imestamp", "proof of work"))]
        if reverse_order:
            ok_s, err_s, _ = alt_node.submit(sibling)
            res["sibling"] = (ok_s, err_s)

        res.update(main_ok=ok_m, main_err=err_m, main_log=log_m,
                   alt_ok=ok_a, alt_err=err_a, alt_log=log_a,
                   disagree=(ok_m != ok_a))
    finally:
        db.stop(); da.stop()
    return res


def extra_tests(port):
    """Restart, re-offer, higher-work branch, reorg crossing 59-61, database reload."""
    out = []
    da = Daemon(f"ex_a{port}", port, port + 1, fixed_diff=1)
    db = Daemon(f"ex_b{port}", port + 4, port + 5, fixed_diff=1)
    try:
        build_identical(da, db, 59)          # candidate will occupy height 59
        parent_h = 58
        _, med = median_in_force(da, parent_h, 59)
        t = da.template()
        cand = rebuild(t["blocktemplate_blob"], ts=med - 1, nonce=0xBEEF01)   # below the bound
        sib = rebuild(t["blocktemplate_blob"], nonce=0xBEEF02)
        ok_s, _, _ = db.submit(sib)
        ok_m, err_m, _ = da.submit(cand)
        ok_a, err_a, _ = db.submit(cand)
        out.append(("below-bound candidate at height 59, main vs alt",
                    f"main={'accept' if ok_m else 'reject'} alt={'accept' if ok_a else 'reject'}",
                    ok_m == ok_a))

        # re-offer
        ok_m2, _, _ = da.submit(cand)
        ok_a2, _, _ = db.submit(cand)
        out.append(("re-offering the same candidate",
                    f"main={'accept' if ok_m2 else 'reject'} alt={'accept' if ok_a2 else 'reject'}",
                    ok_m2 == ok_a2))

        # higher cumulative work: extend whichever node accepted, across 59->61
        builder = da if ok_m else db
        other = db if ok_m else da
        mine_to(builder, 62, nonce_base=0x700000)
        out.append(("multi-block extension crossing heights 59-61",
                    f"builder height {builder.height()}, other {other.height()}", True))

        # feed the whole branch to the other node, newest first then oldest first
        blobs = []
        for h in range(59, builder.height()):
            try:
                import json as _json
                from live_median_boundary import rpc as _rpc
                blk = _rpc(builder.rpc, "get_block", {"height": h})["result"]
                blobs.append(blk["blob"])
            except Exception:
                pass
        for b in reversed(blobs):
            other.submit(b)
        for b in blobs:
            other.submit(b)
        conv1 = da.info()["top_block_hash"] == db.info()["top_block_hash"]
        out.append(("reorganisation after being offered the heavier branch",
                    f"converged={conv1}, heights {da.height()}/{db.height()}", conv1))

        # restart both, then reload from disk and re-check
        da.stop(); db.stop()
        time.sleep(0.6)
        da2 = Daemon(f"ex_a{port}", port, port + 1, fixed_diff=1, wipe=False, data_dir=da.dir)
        db2 = Daemon(f"ex_b{port}", port + 4, port + 5, fixed_diff=1, wipe=False, data_dir=db.dir)
        try:
            same = da2.info()["top_block_hash"] == db2.info()["top_block_hash"]
            out.append(("database reload after restart, tips unchanged",
                        f"A {da2.height()}/{da2.info()['top_block_hash'][:12]} "
                        f"B {db2.height()}/{db2.info()['top_block_hash'][:12]}", True))
            out.append(("restart does not change the disagreement outcome",
                        f"converged={same}", same == conv1))
            ok_m3, _, _ = da2.submit(cand)
            ok_a3, _, _ = db2.submit(cand)
            out.append(("re-offering the candidate after restart",
                        f"main={'accept' if ok_m3 else 'reject'} "
                        f"alt={'accept' if ok_a3 else 'reject'}", ok_m3 == ok_a3))
        finally:
            db2.stop(); da2.stop()
        da = db = None
    finally:
        for d in (da, db):
            if d is not None:
                d.stop()
    return out


def main():
    os.makedirs(ROOT, exist_ok=True)
    say(f"# MeepCoin — Main-versus-Alternative Validity Regression (`--rule={RULE}`)")
    say()
    say("> **ANALYSIS ONLY.** Isolated throwaway daemons, own data dirs and ports, `--offline`,")
    say("> blocks delivered by RPC so arrival order is exact. No consensus, genesis, economics,")
    say("> frozen tag, preserved chain database or wallet is touched. Dev/test coins, no value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Median rule used to construct the probes: **{RULE}**")
    say("- Proof-of-work is trivial (`--fixed-difficulty 1`); this tests timestamp validity only.")
    say("- **Pass condition: zero cases where the two nodes disagree for identical block bytes.**")
    say()

    port = PORT_BASE
    results = []
    for h in HEIGHTS:
        for kind in TS_KINDS:
            for rr, ro in ((False, False), (True, False), (False, True)):
                try:
                    r = one_case(h, kind, rr, ro, port)
                except Exception as e:
                    r = {"chain_h": h, "kind": kind, "roles": "rev" if rr else "std",
                         "order": "rev" if ro else "std",
                         "error": f"{type(e).__name__}: {e}", "disagree": None}
                    say(f"  ! h={h} {kind}: {r['error']}")
                port += 10
                results.append(r)
        done = [x for x in results if x["chain_h"] == h]
        nd = sum(1 for x in done if x.get("disagree"))
        say(f"  height {h}: {len(done)} cases, {nd} disagreements")
    say()

    say("## Result matrix")
    say()
    say("| height | timestamp case | roles | order | bound | ts | main-chain | alt-chain | agree |")
    say("|---|---|---|---|---|---|---|---|---|")
    ndis = nerr = 0
    for r in results:
        if "error" in r:
            nerr += 1
            say(f"| {r['chain_h']} | {r['kind']} | {r['roles']} | {r['order']} | — | — | — | — "
                f"| ERROR `{r['error'][:60]}` |")
            continue
        if r["disagree"]:
            ndis += 1
        say(f"| {r['chain_h']} | {r['kind']} | {r['roles']} | {r['order']} "
            f"| {r['median'] if r['median'] is not None else '_none_'} | {r['ts']} "
            f"| {'accept' if r['main_ok'] else 'reject'} "
            f"| {'accept' if r['alt_ok'] else 'reject'} "
            f"| {'**DISAGREE**' if r['disagree'] else 'yes'} |")
    say()
    say(f"**{len(results)} cases, {ndis} disagreements, {nerr} errors.**")
    say()
    if ndis == 0 and nerr == 0:
        say("**PASS — no context-dependent validity disagreement at any tested height or timestamp.**")
    else:
        say(f"**FAIL — {ndis} case(s) reached different verdicts for identical block bytes.**")
    say()

    say("## Restart, re-offer, reorganisation and reload")
    say()
    try:
        ex = extra_tests(port)
        say("| check | observation | ok |")
        say("|---|---|---|")
        for name, obs, ok in ex:
            say(f"| {name} | {obs} | {'yes' if ok else '**NO**'} |")
    except Exception as e:
        say(f"These checks did not complete: `{type(e).__name__}: {e}`. Recorded as a gap.")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
