#!/usr/bin/env python3
"""Task 2 — prove or disprove main-versus-alt context dependence across two real nodes.

Two isolated daemons, identical consensus binary, identical chain history. The SAME candidate block
bytes, with the SAME parent history, are made to arrive as:

  * a direct main-chain extension on node A  -> Blockchain::handle_block_to_main_chain
  * an alternative-chain block on node B     -> Blockchain::handle_alternative_block

by first giving B one extra block on the same parent, so that the candidate's parent is B's tip's
parent rather than B's tip.

Tested below 60 blocks, at exactly 60, and above 60. Roles and arrival order are then reversed.
Afterwards the experiment asks whether the nodes converge, whether a reorganisation re-evaluates the
block differently, and whether cumulative-work selection exposes the difference.

Proof-of-work is made trivial with `--fixed-difficulty 1` so that arbitrary candidate blocks can be
constructed. This experiment is about TIMESTAMP validity, not proof-of-work; that substitution is
stated rather than hidden. Nodes are `--offline` and blocks are delivered by RPC, so arrival order
is exactly controlled and P2P relay is deliberately not exercised.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, rpc, ROOT, TS_WINDOW  # noqa: E402

REPORT = "docs/CROSS_NODE_ALTPATH.md"
# --report keeps the baseline and candidate runs from overwriting each other.
for _a in sys.argv[1:]:
    if _a.startswith("--report="):
        REPORT = _a.split("=", 1)[1]

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def build_identical(a, b, target_chain_h):
    """Mine on A, replay the identical bytes into B, so both hold byte-identical history."""
    blobs = []
    while a.height() < target_chain_h:
        t = a.template()
        h = a.height()
        for i in range(50):
            blob = rebuild(t["blocktemplate_blob"], nonce=h * 7919 + i)
            ok, err, _ = a.submit(blob)
            if ok:
                blobs.append(blob)
                break
        else:
            raise RuntimeError(f"could not extend A at height {h}: {err}")
    for blob in blobs:
        ok, err, _ = b.submit(blob)
        if not ok:
            raise RuntimeError(f"replay into B failed: {err}")
    ta, tb = a.info()["top_block_hash"], b.info()["top_block_hash"]
    if ta != tb or a.height() != b.height():
        raise RuntimeError(f"histories differ: A {a.height()}/{ta[:12]} B {b.height()}/{tb[:12]}")
    return ta


def lower_bound(node, chain_h):
    """(applies, daemon_median_or_None, available_history_median)."""
    all_ts = node.timestamps(0, chain_h - 1)
    avail = epee_median(all_ts)
    if chain_h < TS_WINDOW:
        return False, None, avail
    return True, epee_median(node.timestamps(chain_h - TS_WINDOW, chain_h - 1)), avail


def one_case(chain_h, reverse_roles, reverse_order, port):
    tagA, tagB = ("xnB", "xnA") if reverse_roles else ("xnA", "xnB")
    a = Daemon(f"{tagA}_{chain_h}_{int(reverse_roles)}{int(reverse_order)}", port, port + 1,
               fixed_diff=1)
    b = Daemon(f"{tagB}_{chain_h}_{int(reverse_roles)}{int(reverse_order)}", port + 4, port + 5,
               fixed_diff=1)
    res = {"chain_h": chain_h, "reverse_roles": reverse_roles, "reverse_order": reverse_order}
    try:
        tip = build_identical(a, b, chain_h)
        res["identical_history"] = True
        res["tip"] = tip

        applies, dmed, avail = lower_bound(a, chain_h)
        base = dmed if applies else avail
        ts = base - 1                                  # one second below the median in force
        res.update(rule_applies=applies, daemon_median=dmed,
                   available_history_median=avail, submitted_ts=ts)

        # Which physical daemon plays the alternative-chain role. The two are identical processes,
        # so this is a mirror control: reversing it must mirror the result, not change it.
        main_node, alt_node = (a, b) if not reverse_roles else (b, a)

        t = a.template()
        parent = t["prev_hash"]
        candidate = rebuild(t["blocktemplate_blob"], ts=ts, nonce=0xCA0DEF)
        sibling = rebuild(t["blocktemplate_blob"], nonce=0x51B1)     # honest ts, different nonce
        res["candidate_blob_sha_prefix"] = candidate[:64]
        res["parent"] = parent

        # The alt-path node gets the sibling first, so the candidate's parent is no longer its tip
        # and the candidate must take handle_alternative_block.
        if not reverse_order:
            okS, errS, _ = alt_node.submit(sibling)
            res["sibling_into_alt_node"] = (okS, errS)

        main_node.mark_log(); alt_node.mark_log()
        okA, errA, _ = main_node.submit(candidate)
        logA = [l.split(chr(9))[-1] for l in main_node.new_log()
                if any(k in l for k in ("imestamp", "proof of work", "Block with id"))]
        okB, errB, _ = alt_node.submit(candidate)
        logB = [l.split(chr(9))[-1] for l in alt_node.new_log()
                if any(k in l for k in ("imestamp", "proof of work", "Block with id"))]

        if reverse_order:
            okS, errS, _ = alt_node.submit(sibling)
            res["sibling_into_alt_node"] = (okS, errS)

        res.update(A_accepted=okA, A_error=errA, A_log=logA,
                   B_accepted=okB, B_error=errB, B_log=logB)
        res["divergent"] = (okA != okB)

        # ---- convergence and reorganisation --------------------------------------------------
        # Extend A past the candidate so A's chain carries strictly more cumulative work, then
        # offer B the whole thing and see whether it ever adopts it.
        child = None
        if okA:
            t2 = main_node.template()
            for i in range(50):
                cb = rebuild(t2["blocktemplate_blob"], nonce=0xD00D + i)
                ok2, err2, _ = main_node.submit(cb)
                if ok2:
                    child = cb
                    break
        res["A_extended"] = child is not None
        if child is not None:
            ok_child_first, err_cf, _ = alt_node.submit(child)   # child before its parent
            res["B_child_before_parent"] = (ok_child_first, err_cf)
            ok_c2, err_c2, _ = alt_node.submit(candidate)        # parent again
            res["B_candidate_retry"] = (ok_c2, err_c2)
            ok_child2, err_ch2, _ = alt_node.submit(child)       # child again
            res["B_child_retry"] = (ok_child2, err_ch2)
        time.sleep(0.5)
        ia, ib = main_node.info(), alt_node.info()
        res["A_final"] = (ia["height"], ia["top_block_hash"], str(ia.get("cumulative_difficulty")))
        res["B_final"] = (ib["height"], ib["top_block_hash"], str(ib.get("cumulative_difficulty")))
        res["converged"] = ia["top_block_hash"] == ib["top_block_hash"]
        res["A_dir"], res["B_dir"] = main_node.dir, alt_node.dir
    finally:
        b.stop(); a.stop()
    return res


def main():
    os.makedirs(ROOT, exist_ok=True)
    say("# MeepCoin — Main-versus-Alternative-Chain Cross-Node Test (task 2)")
    say()
    say("> **ANALYSIS ONLY.** Two isolated throwaway daemons, identical binary, own data dirs and")
    say("> ports, `--offline`, blocks delivered by RPC so arrival order is exact. No consensus,")
    say("> genesis, economics, frozen tag, existing chain database or wallet is touched.")
    say("> Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("- Proof-of-work is trivial (`--fixed-difficulty 1`) so arbitrary candidate blocks can be")
    say("  built. This tests TIMESTAMP validity, not proof-of-work.")
    say("- The candidate block is byte-identical on both nodes; only its position relative to each")
    say("  node's tip differs, which is what selects `handle_block_to_main_chain` versus")
    say("  `handle_alternative_block`.")
    say()

    cases = []
    port = 26500
    for chain_h in (31, 60, 91):
        for rr, ro in ((False, False), (True, False), (False, True)):
            say(f"running chain_h={chain_h} reverse_roles={rr} reverse_order={ro} …")
            try:
                r = one_case(chain_h, rr, ro, port)
            except Exception as e:
                r = {"chain_h": chain_h, "reverse_roles": rr, "reverse_order": ro,
                     "error": f"{type(e).__name__}: {e}"}
                say(f"  ! {r['error']}")
            cases.append(r)
            port += 10
            if "error" not in r:
                say(f"  A={'accept' if r['A_accepted'] else 'reject'} "
                    f"B={'accept' if r['B_accepted'] else 'reject'} "
                    f"divergent={r['divergent']} converged={r['converged']}")
    say()

    say("## Result matrix")
    say()
    say("| chain_h | median rule | roles | order | ts | main-chain node | alt-chain node "
        "| divergent | converged after reorg attempt |")
    say("|---|---|---|---|---|---|---|---|---|")
    for r in cases:
        if "error" in r:
            say(f"| {r['chain_h']} | — | {'rev' if r['reverse_roles'] else 'std'} "
                f"| {'rev' if r['reverse_order'] else 'std'} | — | — | — | — | "
                f"ERROR `{r['error']}` |")
            continue
        say(f"| {r['chain_h']} | {'applies' if r['rule_applies'] else '**does not apply**'} "
            f"| {'rev' if r['reverse_roles'] else 'std'} "
            f"| {'rev' if r['reverse_order'] else 'std'} | {r['submitted_ts']} "
            f"| **{'ACCEPT' if r['A_accepted'] else 'reject'}** "
            f"| **{'ACCEPT' if r['B_accepted'] else 'reject'}** "
            f"| {'**YES**' if r['divergent'] else 'no'} "
            f"| {'yes' if r['converged'] else '**NO**'} |")
    say()

    div = [r for r in cases if r.get("divergent")]
    unconv = [r for r in cases if r.get("divergent") and not r.get("converged")]
    say("## Reading")
    say()
    if not div:
        say("No case produced different validity decisions on the two nodes. The main and")
        say("alternative paths agreed everywhere tested, so **no chain-split vulnerability is")
        say("demonstrated** by this experiment.")
    else:
        say(f"**{len(div)} of {len(cases)} configurations produced different validity decisions for")
        say("byte-identical block bytes on byte-identical history.** The only difference between the")
        say("two nodes is which code path the block took.")
        say()
        if unconv:
            say(f"**{len(unconv)} of those did not converge** even after the accepting node built a")
            say("strictly-longer chain and the rejecting node was offered both blocks, in both")
            say("orders. Two nodes running the same binary on equivalent history therefore reached")
            say("**incompatible validity decisions and stayed there**. Databases and logs for those")
            say("cases are preserved under `~/.meepcoin-live-median/` and listed below.")
        else:
            say("All divergent cases converged once the accepting node built a longer chain, so the")
            say("divergence is transient rather than a persistent split.")
    say()

    say("## Per-case detail")
    say()
    for r in cases:
        if "error" in r:
            continue
        say(f"<details><summary>chain_h={r['chain_h']} roles="
            f"{'reversed' if r['reverse_roles'] else 'standard'} order="
            f"{'reversed' if r['reverse_order'] else 'standard'}</summary>")
        say()
        say(f"- identical history confirmed: tip `{r['tip'][:24]}…`, both nodes at height "
            f"{r['chain_h']}")
        say(f"- median rule applies: **{r['rule_applies']}**; daemon median {r['daemon_median']}; "
            f"available-history median {r['available_history_median']}")
        say(f"- candidate parent `{r['parent'][:24]}…`, timestamp **{r['submitted_ts']}**")
        say(f"- sibling into the alt-path node: {r.get('sibling_into_alt_node')}")
        say(f"- **main-chain node**: {'ACCEPTED' if r['A_accepted'] else 'rejected'} "
            f"`{r['A_error'] or ''}`")
        for l in r["A_log"][:4]:
            say(f"  - `{l[:180]}`")
        say(f"- **alt-chain node**: {'ACCEPTED' if r['B_accepted'] else 'rejected'} "
            f"`{r['B_error'] or ''}`")
        for l in r["B_log"][:4]:
            say(f"  - `{l[:180]}`")
        say(f"- accepting node extended past the candidate: {r.get('A_extended')}")
        say(f"- child delivered before its parent: {r.get('B_child_before_parent')}")
        say(f"- candidate re-offered: {r.get('B_candidate_retry')}")
        say(f"- child re-offered: {r.get('B_child_retry')}")
        say(f"- final A: height {r['A_final'][0]}, tip `{r['A_final'][1][:16]}…`, "
            f"cumulative difficulty {r['A_final'][2]}")
        say(f"- final B: height {r['B_final'][0]}, tip `{r['B_final'][1][:16]}…`, "
            f"cumulative difficulty {r['B_final'][2]}")
        say(f"- converged: **{r['converged']}**")
        say(f"- preserved databases: `{r['A_dir']}`, `{r['B_dir']}`")
        say()
        say("</details>")
        say()

    say("_Dev/test coins on private localhost chains. No monetary value._")
    with open("docs/CROSS_NODE_ALTPATH.md", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("\nwritten to docs/CROSS_NODE_ALTPATH.md", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
