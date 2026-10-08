#!/usr/bin/env python3
"""Task 2 — does T4 fix the alternative-path future-limit defect, and at what cost?

T4 moves the future-time check into the shared timestamp overload so both the main-chain and the
alternative-chain path enforce it. The future-time limit is local-clock relative, so this test asks
the question that matters: does enforcing it on alternative blocks create TIME-DEPENDENT validity or
DATABASE/RESTART inconsistency?

Per height, with the same serialized block and the same parent history, the block is offered as:
  1. a main-chain extension
  2. an alternative-chain block
  3. a stored alternative block (re-queried after storage)
  4. an alternative block promoted by a reorganisation
  5. re-offered after wall-clock time advances past the bound
  6. re-offered after a daemon restart

The probe timestamp sits only a few seconds beyond the limit, so "wait for it to become legal" is a
few seconds rather than two hours. The exact boundary was measured separately (+7200 accept,
+7201 reject).

MEEP_DAEMON selects the binary. LOCALHOST / PRIVATE THROWAWAY CHAINS, dev/test coins, no value.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, rpc, DAEMON, ROOT, TS_WINDOW  # noqa

FTL = 7200
OVERSHOOT = 6          # seconds beyond the limit: small enough to age out during the test
HEIGHTS = [1, 30, 31, 59, 60, 61, 90, 200, 400]
REPORT = "docs/T4_REORG_ANALYSIS.md"
for _a in sys.argv[1:]:
    if _a.startswith("--report="):
        REPORT = _a.split("=", 1)[1]
    if _a.startswith("--heights="):
        HEIGHTS = [int(x) for x in _a.split("=", 1)[1].split(",")]

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def mine_to(d, target, nonce_base=0):
    blobs = []
    while d.height() < target:
        t = d.template()
        h = d.height()
        for i in range(60):
            b = rebuild(t["blocktemplate_blob"], nonce=nonce_base + h * 7919 + i)
            ok, err, _ = d.submit(b)
            if ok:
                blobs.append(b); break
        else:
            raise RuntimeError(f"stuck at {h}: {err}")
    return blobs


def one_height(h, port):
    a = Daemon(f"t4a{port}", port, port + 1, fixed_diff=1)
    b = Daemon(f"t4b{port}", port + 4, port + 5, fixed_diff=1)
    r = {"height": h}
    try:
        blobs = mine_to(a, h)
        for x in blobs:
            ok, err, _ = b.submit(x)
            if not ok:
                raise RuntimeError(f"replay failed: {err}")
        if a.info()["top_block_hash"] != b.info()["top_block_hash"]:
            raise RuntimeError("histories differ")

        now = int(time.time())
        ts = now + FTL + OVERSHOOT               # just beyond the limit
        t = a.template()
        cand = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0x7A4001)
        sib = rebuild(t["blocktemplate_blob"], nonce=0x7A4002)
        r["ts"] = ts
        r["overshoot"] = OVERSHOOT

        # (2) make it an ALT block on b by giving b a sibling first
        ok_s, _, _ = b.submit(sib)
        r["sibling"] = ok_s
        ok_main, err_main, _ = a.submit(cand)
        ok_alt, err_alt, _ = b.submit(cand)
        r["main"] = (ok_main, err_main)
        r["alt"] = (ok_alt, err_alt)
        r["agree_initial"] = (ok_main == ok_alt)

        # (3) is it stored as an alt block?
        from live_median_boundary import rest
        r["alt_stored"] = len(rest(b.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or [])

        # (5) wait past the bound, then re-offer to both
        time.sleep(OVERSHOOT + 4)
        ok_main2, err_main2, _ = a.submit(cand)
        ok_alt2, err_alt2, _ = b.submit(cand)
        r["main_after_wait"] = (ok_main2, err_main2)
        r["alt_after_wait"] = (ok_alt2, err_alt2)
        r["agree_after_wait"] = (ok_main2 == ok_alt2)

        # (4) promote by reorganisation: build a heavier branch on the candidate's parent on a,
        #     then feed it to b
        promoted = None
        if ok_main2 or ok_main:
            extra = mine_to(a, a.height() + 3, nonce_base=0x50000)
            for x in extra:
                b.submit(x)
            promoted = (a.info()["top_block_hash"] == b.info()["top_block_hash"])
        r["reorg_converged"] = promoted

        # (6) restart both and re-check
        ha, hb = a.height(), b.height()
        ta, tb = a.info()["top_block_hash"], b.info()["top_block_hash"]
        a.stop(); b.stop(); time.sleep(0.8)
        a2 = Daemon(f"t4a{port}", port, port + 1, fixed_diff=1, wipe=False, data_dir=a.dir)
        b2 = Daemon(f"t4b{port}", port + 4, port + 5, fixed_diff=1, wipe=False, data_dir=b.dir)
        try:
            r["restart_same"] = (a2.height() == ha and b2.height() == hb and
                                 a2.info()["top_block_hash"] == ta and
                                 b2.info()["top_block_hash"] == tb)
            ok_m3, _, _ = a2.submit(cand)
            ok_a3, _, _ = b2.submit(cand)
            r["agree_after_restart"] = (ok_m3 == ok_a3)
            r["final"] = (a2.height(), a2.info()["top_block_hash"][:16],
                          b2.height(), b2.info()["top_block_hash"][:16])
            r["converged_final"] = (a2.info()["top_block_hash"] == b2.info()["top_block_hash"])
        finally:
            b2.stop(); a2.stop()
        a = b = None
    finally:
        for d in (a, b):
            if d is not None:
                d.stop()
    return r


def main():
    os.makedirs(ROOT, exist_ok=True)
    say("# MeepCoin — Candidate T4: Future-Time Limit on Both Paths (task 2)")
    say()
    say("> **ANALYSIS ONLY.** Isolated throwaway daemons, `--offline`, RPC delivery so arrival order")
    say("> is exact. No consensus, genesis, economics, frozen tag, preserved database or wallet is")
    say("> touched. Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Daemon under test: `{DAEMON}`")
    say(f"- Probe timestamp: `now + {FTL} + {OVERSHOOT}` — just past the limit, so it ages into")
    say("  legality within seconds rather than two hours.")
    say("- Proof-of-work trivial (`--fixed-difficulty 1`); this tests timestamp validity only.")
    say()

    port = 29400
    out = []
    for h in HEIGHTS:
        try:
            r = one_height(h, port)
            say(f"  height {h}: main={'accept' if r['main'][0] else 'reject'} "
                f"alt={'accept' if r['alt'][0] else 'reject'} "
                f"agree={r['agree_initial']} after_wait={r['agree_after_wait']} "
                f"after_restart={r['agree_after_restart']}")
        except Exception as e:
            r = {"height": h, "error": f"{type(e).__name__}: {e}"}
            say(f"  height {h}: ERROR {r['error']}")
        out.append(r)
        port += 20
    say()

    say("## Result matrix")
    say()
    say("| height | main path | alt path | agree | alt blocks stored | agree after time advances "
        "| reorg converged | restart preserves tips | agree after restart |")
    say("|---|---|---|---|---|---|---|---|---|")
    nbad = 0
    for r in out:
        if "error" in r:
            nbad += 1
            say(f"| {r['height']} | — | — | — | — | — | — | — | ERROR `{r['error'][:50]}` |")
            continue
        if not r["agree_initial"] or not r["agree_after_wait"] or not r["agree_after_restart"]:
            nbad += 1
        say(f"| {r['height']} | {'accept' if r['main'][0] else 'reject'} "
            f"| {'accept' if r['alt'][0] else 'reject'} "
            f"| {'yes' if r['agree_initial'] else '**NO**'} | {r['alt_stored']} "
            f"| {'yes' if r['agree_after_wait'] else '**NO**'} "
            f"| {r.get('reorg_converged')} "
            f"| {'yes' if r.get('restart_same') else '**NO**'} "
            f"| {'yes' if r['agree_after_restart'] else '**NO**'} |")
    say()
    say(f"**{len(out)} heights, {nbad} with a disagreement or error.**")
    say()
    say("## Reading")
    say()
    say("The future-time limit is local-clock relative, so it is time-dependent on both paths by")
    say("construction. The dependence is **one-directional**: a block that is too far in the future")
    say("becomes valid as the clock advances, and never the reverse. A block already accepted cannot")
    say("be invalidated by it.")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    os.makedirs(os.path.dirname(REPORT) or ".", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
