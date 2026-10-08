#!/usr/bin/env python3
"""Task 7 — would the preserved private chain still be valid under T1 / T2 / T3a?

Reads every block timestamp from a COPY of the preserved devnet chain and re-evaluates each block
against each candidate rule. The original database at ~/.meepcoin-devnet is never opened: the copy
at ~/.meepcoin-compat-copy is what the daemon is pointed at, so nothing is rewritten or migrated.

LOCALHOST / PRIVATE CHAIN. Dev/test coins with no monetary value.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, epee_median, rpc, TS_WINDOW  # noqa: E402

COPY = os.path.expanduser("~/.meepcoin-compat-copy")
GENESIS_TS = 1785283200
lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def fetch_all_timestamps(d):
    h = d.height()
    ts = []
    for lo in range(0, h, 500):
        hi = min(lo + 499, h - 1)
        ts.extend(d.timestamps(lo, hi))
    return ts


def upstream_ok(ts, i):
    """Blockchain::check_block_timestamp as it stands today, for the block at height i."""
    chain_h = i                      # blocks already present when block i was added
    if chain_h < TS_WINDOW:
        return True, None
    med = epee_median(ts[chain_h - TS_WINDOW:chain_h])
    return ts[i] >= med, med


def t1_ok(ts, i):
    """T1 / T2 shared window: median of heights [max(0, i-60) .. i-1], genesis included."""
    if i == 0:
        return True, None
    lo = max(0, i - TS_WINDOW)
    med = epee_median(ts[lo:i])
    return ts[i] >= med, med


def t3a_ok(ts, i):
    return ts[i] >= GENESIS_TS, GENESIS_TS


def main():
    if not os.path.isdir(COPY):
        say(f"copy not found at {COPY}"); return 1
    say("# MeepCoin — Existing-Chain Compatibility Under the Timestamp Candidates (task 7)")
    say()
    say("> **ANALYSIS ONLY.** Evaluated against a **copy** of the preserved private devnet chain.")
    say("> The original database at `~/.meepcoin-devnet` is never opened, rewritten or migrated.")
    say("> Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Copy under evaluation: `{COPY}`")
    say()

    d = Daemon("compat", 26700, 26701, fixed_diff=0, wipe=False, data_dir=COPY)
    try:
        h = d.height()
        say(f"- Chain height (block count): **{h}**, tip `{d.info()['top_block_hash'][:24]}…`")
        ts = fetch_all_timestamps(d)
        say(f"- Timestamps read: {len(ts)}")
        say()
        assert len(ts) == h

        rules = [("current rule (upstream)", upstream_ok),
                 ("T1 / T2 shared window", t1_ok),
                 ("T3a genesis floor", t3a_ok)]
        say("| rule | blocks that would be REJECTED | first offending height | verdict |")
        say("|---|---|---|---|")
        detail = {}
        for name, fn in rules:
            bad = []
            for i in range(1, len(ts)):
                ok, med = fn(ts, i)
                if not ok:
                    bad.append((i, ts[i], med))
            detail[name] = bad
            say(f"| {name} | **{len(bad)}** | {bad[0][0] if bad else '—'} | "
                f"{'**chain stays valid**' if not bad else '**chain would be invalidated**'} |")
        say()

        for name, bad in detail.items():
            if not bad:
                continue
            say(f"### Offending blocks under {name}")
            say()
            say("| height | timestamp | bound in force | shortfall (s) |")
            say("|---|---|---|---|")
            for i, t, med in bad[:40]:
                say(f"| {i} | {t} | {med} | {med - t if med else '—'} |")
            if len(bad) > 40:
                say(f"| … | … | … | {len(bad) - 40} more |")
            say()

        say("### First 12 timestamps, for orientation")
        say()
        say("| height | timestamp | delta from previous |")
        say("|---|---|---|")
        for i in range(min(12, len(ts))):
            say(f"| {i} | {ts[i]} | {ts[i] - ts[i-1] if i else '—'} |")
        say()
        n_same = sum(1 for i in range(1, len(ts)) if ts[i] == ts[i - 1])
        n_back = sum(1 for i in range(1, len(ts)) if ts[i] < ts[i - 1])
        say(f"- blocks sharing their parent's timestamp: **{n_same}**")
        say(f"- blocks with a timestamp strictly BELOW their parent's: **{n_back}** "
            f"(this is what candidate T3b, strict monotonicity, would have rejected)")
        say()
    finally:
        d.stop()

    say("_Dev/test coins on a private chain. No monetary value._")
    with open("docs/EXISTING_CHAIN_COMPAT.md", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("\nwritten to docs/EXISTING_CHAIN_COMPAT.md", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
