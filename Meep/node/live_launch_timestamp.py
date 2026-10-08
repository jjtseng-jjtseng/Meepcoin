#!/usr/bin/env python3
"""Live check of the launch-window consequence the corrected median rule exposes.

The round-3 simulator, once its median rule was corrected against live daemon behaviour, produced
a launch-window result that had not been seen before: because `Blockchain::check_block_timestamp`
performs NO median check while the chain holds fewer than BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW blocks,
a miner may write a timestamp of ZERO. Alternating a zero timestamp with a now+FTL timestamp gives
`next_difficulty` a time span of ~1.79e9 seconds, which pins difficulty at 1.

A simulator finding is not evidence. This script decides it on a live throwaway daemon:

  probe 1  timestamp 0 below 60 blocks, main chain          -- is it accepted?
  probe 2  timestamp 1 below 60 blocks, main chain
  probe 3  timestamp 0 at or above 60 blocks, main chain    -- must now be rejected
  probe 4  a full alternating launch: build a real chain, no --fixed-difficulty, alternating
           timestamp 0 / now+FTL, and record the daemon's OWN difficulty at every height
  probe 5  an honest control launch on an identical fresh chain, for contrast

Difficulty is NOT forced in probes 4 and 5: the daemon computes it from the chain it is given, so
the trajectory recorded is the daemon's own arithmetic, not the simulator's.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, rebuild, epee_median, ROOT, TS_WINDOW   # noqa: E402

FTL = 7200
NONCE_BUDGET = 400          # submit attempts per block before giving up on proof-of-work
OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/LIVE_LAUNCH_TIMESTAMP.md"

lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def try_mine(d, ts=None, budget=NONCE_BUDGET, nonce0=0):
    """Submit blocks with increasing nonces until one is accepted or the budget runs out.
    Returns (accepted, attempts, difficulty_the_daemon_asked_for, last_error)."""
    t = d.template()
    diff = int(t["difficulty"])
    for i in range(budget):
        ok, err, _ = d.submit(rebuild(t["blocktemplate_blob"], ts=ts, nonce=nonce0 + i))
        if ok:
            return True, i + 1, diff, None
        if err and "not accepted" not in err.lower():
            return False, i + 1, diff, err
    return False, budget, diff, "proof-of-work budget exhausted"


def launch_chain(tag, port, alternating, nblocks):
    """Mine a fresh chain at REAL difficulty. If `alternating`, use the attacker's timestamps."""
    # fixed_diff=0 disables the override: Blockchain::get_difficulty_for_next_block only short
    # circuits when m_fixed_difficulty is non-zero, so 0 means "compute it for real".
    d = Daemon(tag, port, port + 1, fixed_diff=0)
    traj = []
    try:
        for h in range(nblocks):
            chain_h = d.height()
            if alternating:
                if chain_h < TS_WINDOW:
                    lo = 0                            # no median check below 60 blocks
                else:
                    win = d.timestamps(chain_h - TS_WINDOW, chain_h - 1)
                    lo = epee_median(win)
                ts = (int(time.time()) + FTL) if (chain_h % 2 == 0) else lo
            else:
                ts = None                             # daemon's own template timestamp
            ok, tries, diff, err = try_mine(d, ts=ts, nonce0=h * 1000)
            traj.append((chain_h, diff, ts, ok, tries, err))
            if not ok:
                break
        final_h = d.height()
        final_diff = int(d.template()["difficulty"])
    finally:
        d.stop()
    return traj, final_h, final_diff


def main():
    os.makedirs(ROOT, exist_ok=True)
    say("# MeepCoin — Live Launch-Window Timestamp Check")
    say()
    say("> **ANALYSIS ONLY.** Throwaway private chains, own data dirs and ports. No consensus,")
    say("> genesis, economics, frozen tag or public infrastructure touched. Dev/test coins,")
    say("> no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` = {TS_WINDOW}, `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`"
        f" = {FTL}")
    say()
    say("## Probes 1–3 — is a timestamp of zero actually legal?")
    say()
    say("| probe | chain_h | rule applies | submitted ts | daemon verdict | daemon error |")
    say("|---|---|---|---|---|---|")

    probes = []
    # below 60 blocks
    d = Daemon("lt_low", 26300, 26301, fixed_diff=1)
    try:
        d.mine(30 - d.height() + 1, nonce_base=500)
        for label, ts in [("ts = 0, chain under 60 blocks", 0), ("ts = 1, chain under 60 blocks", 1)]:
            h = d.height()
            t = d.template()
            ok, err, _ = d.submit(rebuild(t["blocktemplate_blob"], ts=ts, nonce=0xC0DE00 + ts))
            probes.append((label, h, False, ts, ok, err))
            say(f"| {label} | {h} | **no** | {ts} | **{'ACCEPTED' if ok else 'rejected'}** "
                f"| `{err or ''}` |")
    finally:
        d.stop()
    # at/above 60 blocks
    d = Daemon("lt_high", 26310, 26311, fixed_diff=1)
    try:
        d.mine(90 - d.height() + 1, nonce_base=600)
        h = d.height()
        win = d.timestamps(h - TS_WINDOW, h - 1)
        med = epee_median(win)
        t = d.template()
        ok, err, _ = d.submit(rebuild(t["blocktemplate_blob"], ts=0, nonce=0xC0DE99))
        probes.append(("ts = 0, chain at 91 blocks", h, True, 0, ok, err))
        say(f"| ts = 0, chain at 91 blocks | {h} | yes (median {med}) | 0 "
            f"| **{'ACCEPTED' if ok else 'rejected'}** | `{err or ''}` |")
    finally:
        d.stop()
    say()

    zero_ok = probes[0][4]
    if zero_ok:
        say("**A timestamp of zero is accepted on a chain shorter than 60 blocks.** That is the")
        say("daemon's documented behaviour -- `check_block_timestamp` returns true before computing")
        say("any median -- and it is what makes the launch-window span manipulation below possible.")
    else:
        say("**A timestamp of zero was NOT accepted.** The simulator's launch-window result does")
        say("not transfer to the live daemon, and must be treated as a model artefact.")
    say()

    say("## Probes 4–5 — difficulty trajectory on a real chain, difficulty NOT forced")
    say()
    say("Both chains are mined without `--fixed-difficulty`, so every difficulty below is the")
    say("daemon's own `next_difficulty()` output for the chain it was given. Proof-of-work is")
    say(f"brute-forced through `submit_block`, at most {NONCE_BUDGET} nonces per block, so a chain")
    say("stops as soon as its difficulty rises beyond what this method can solve. That stopping")
    say("point is itself the contrast being measured.")
    say()
    atk, atk_h, atk_d = launch_chain("lt_attack", 26320, True, 200)
    ctl, ctl_h, ctl_d = launch_chain("lt_control", 26330, False, 200)

    say("| chain | blocks reached | final difficulty | first difficulty above 100 | stopped because |")
    say("|---|---|---|---|---|")
    for name, traj, fh, fd in (("alternating 0 / now+FTL", atk, atk_h, atk_d),
                               ("honest timestamps", ctl, ctl_h, ctl_d)):
        first_big = next((h for h, dd, *_ in traj if dd > 100), None)
        why = traj[-1][5] if traj and not traj[-1][3] else "reached the block limit"
        say(f"| {name} | {fh} | {fd} | {first_big if first_big is not None else '_never_'} | {why} |")
    say()
    say("Per-height difficulty, first 40 heights of each chain:")
    say()
    say("| height | alternating: difficulty | ts written | honest: difficulty |")
    say("|---|---|---|---|")
    for i in range(min(40, max(len(atk), len(ctl)))):
        a = atk[i] if i < len(atk) else None
        c = ctl[i] if i < len(ctl) else None
        say(f"| {i} | {a[1] if a else '—'} | {a[2] if a else '—'} | {c[1] if c else '—'} |")
    say()

    say("### What this does and does not establish")
    say()
    say("- It establishes what the **live daemon** accepts, and the difficulty **the live daemon**")
    say("  computes, for a chain built with these timestamps. Both are its own arithmetic.")
    say("- It is a **single-miner** experiment with no competing honest hashrate, so it does not")
    say("  measure what fraction of hashrate an attacker would need. It bounds the rule, not the")
    say("  adversary.")
    say("- It covers the **launch window only**. Nothing here says anything about an attack on an")
    say("  established chain that already carries a high difficulty.")
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
