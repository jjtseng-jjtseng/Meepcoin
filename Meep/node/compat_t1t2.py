#!/usr/bin/env python3
"""Task 6 — does the preserved 2,245-block chain still load and validate under T1+T2?

Runs the T1+T2 daemon against a FRESH COPY of the preserved devnet database. The original at
~/.meepcoin-devnet is never opened, never rewritten and never migrated.

Steps:
  1. copy the preserved database
  2. start the T1+T2 daemon on the copy, confirm height and tip
  3. stop and restart it, confirm the same height and tip after a database reload
  4. exercise stored alternative-chain data
  5. independently replay every main-chain block through the T1+T2 timestamp helper
  6. confirm no block changes validity between the current rule and T1+T2

LOCALHOST / PRIVATE CHAIN. Dev/test coins with no monetary value.
"""
import os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_median_boundary import Daemon, epee_median, rpc, rest, DAEMON, TS_WINDOW  # noqa: E402

ORIG = os.path.expanduser("~/.meepcoin-devnet/nodeA")
COPY = os.path.expanduser("~/.meepcoin-t1t2-compat")
REPORT = "docs/COMPAT_T1T2_T4.md"
lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def upstream_ok(ts, i):
    if i < TS_WINDOW:
        return True, None
    med = epee_median(ts[i - TS_WINDOW:i])
    return ts[i] >= med, med


def t1t2_ok(ts, i):
    if i == 0:
        return True, None
    lo = max(0, i - TS_WINDOW)
    med = epee_median(ts[lo:i])
    return ts[i] >= med, med


def fetch_all(d):
    h = d.height()
    out = []
    for lo in range(0, h, 500):
        out.extend(d.timestamps(lo, min(lo + 499, h - 1)))
    return out


def main():
    if not os.path.isdir(ORIG):
        say(f"preserved chain not found at {ORIG}"); return 1
    say("# MeepCoin — Preserved-Chain Compatibility Under T1+T2 (task 6)")
    say()
    say("> **ANALYSIS ONLY.** The preserved database at `~/.meepcoin-devnet` is **copied**, never")
    say("> opened in place, never rewritten and never migrated. Dev/test coins, no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Daemon under test: `{DAEMON}`")
    try:
        h = subprocess.run(["sha256sum", DAEMON], capture_output=True, text=True).stdout.split()[0]
        say(f"- Daemon sha256: `{h}`")
    except Exception:
        pass
    say()

    # ---- 1. copy
    before = subprocess.run(["stat", "-c", "%Y", ORIG], capture_output=True, text=True).stdout.strip()
    if os.path.isdir(COPY):
        shutil.rmtree(COPY)
    subprocess.run(["cp", "-a", "--sparse=always", ORIG, COPY], check=True)
    say(f"- Copied `{ORIG}` -> `{COPY}` with `cp -a --sparse=always`")
    say(f"- Original directory mtime before the run: `{before}`")
    say()

    ok_all = True
    # ---- 2. first start
    d = Daemon("t1t2compat", 26900, 26901, fixed_diff=0, wipe=False, data_dir=COPY)
    try:
        h1, tip1 = d.height(), d.info()["top_block_hash"]
        cum1 = str(d.info().get("cumulative_difficulty"))
        say("## Load, restart and reload")
        say()
        say("| step | height | tip | cumulative difficulty |")
        say("|---|---|---|---|")
        say(f"| first start under T1+T2 | {h1} | `{tip1[:24]}…` | {cum1} |")
        ts = fetch_all(d)
        # get_alt_blocks_hashes is a REST endpoint, not a json_rpc method
        alt = rest(d.rpc, "/get_alt_blocks_hashes")
        alt_hashes = alt.get("blks_hashes", []) or []
    finally:
        d.stop()
    time.sleep(1.0)

    # ---- 3. restart
    d2 = Daemon("t1t2compat", 26900, 26901, fixed_diff=0, wipe=False, data_dir=COPY)
    try:
        h2, tip2 = d2.height(), d2.info()["top_block_hash"]
        cum2 = str(d2.info().get("cumulative_difficulty"))
        say(f"| after stop and restart | {h2} | `{tip2[:24]}…` | {cum2} |")
        same = (h1 == h2 and tip1 == tip2 and cum1 == cum2)
        ok_all = ok_all and same
        say()
        say(f"- Height, tip and cumulative difficulty unchanged across the reload: "
            f"**{'yes' if same else 'NO'}**")
        say(f"- Expected height 2245: **{'yes' if h2 == 2245 else 'NO, got ' + str(h2)}**")
        ok_all = ok_all and (h2 == 2245)
        say()

        # ---- 4. alternative-chain data
        say("## Stored alternative-chain data")
        say()
        say(f"- alternative blocks held by the daemon: **{len(alt_hashes)}**")
        if alt_hashes:
            say(f"- first few: {', '.join(x[:16] + '…' for x in alt_hashes[:4])}")
            say("- these are re-parsed on load; the daemon started cleanly with them present")
        else:
            say("- none stored. The alternative-chain code path therefore could **not** be")
            say("  exercised from this database, and that is a stated gap rather than a pass:")
            say("  `docs/SPLIT_REGRESSION_T1T2.md` covers the alt path directly instead.")
        say()
    finally:
        d2.stop()

    # ---- 5/6. offline replay of every main-chain block
    say("## Independent replay of every main-chain block")
    say()
    say(f"- timestamps read: {len(ts)}")
    changed, bad_up, bad_t1 = [], 0, 0
    for i in range(1, len(ts)):
        u, _ = upstream_ok(ts, i)
        t, med = t1t2_ok(ts, i)
        if not u: bad_up += 1
        if not t: bad_t1 += 1
        if u != t: changed.append((i, ts[i], med))
    say("| rule | blocks rejected |")
    say("|---|---|")
    say(f"| current (upstream) | **{bad_up}** |")
    say(f"| T1+T2 | **{bad_t1}** |")
    say()
    say(f"- blocks whose validity **changes** between the two rules: **{len(changed)}**")
    if changed:
        ok_all = False
        say()
        say("| height | timestamp | T1+T2 bound |")
        say("|---|---|---|")
        for i, t, m in changed[:40]:
            say(f"| {i} | {t} | {m} |")
    say()

    after = subprocess.run(["stat", "-c", "%Y", ORIG], capture_output=True, text=True).stdout.strip()
    say(f"- Original directory mtime after the run: `{after}` — "
        f"**{'unchanged' if after == before else 'CHANGED, investigate'}**")
    ok_all = ok_all and (after == before)
    say()
    say(f"## Verdict: {'**PASS**' if ok_all else '**FAIL**'}")
    say()
    say("_Dev/test coins on a private chain. No monetary value._")

    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
