#!/usr/bin/env python3
"""EXPERIMENTAL: set MEEPCOIN_GENESIS_TIMESTAMP for a throwaway test build.

Changes ONE constant in ~/meepcoin-node/src/cryptonote_config.h. That constant is used in exactly one
place, cryptonote_tx_utils.cpp:711, where it becomes the genesis block's timestamp. Changing it
changes the genesis block hash, so a chain mined by such a build is incompatible with any other --
which is exactly what is wanted here: each genesis age gets its own isolated experimental chain.

This is for the fresh-versus-stale genesis experiment ONLY. It must never be left applied, and it is
never used to produce a real genesis. The final public-testnet genesis is not generated here.

Usage:
  patch_genesis_ts.py --set <unix_ts>
  patch_genesis_ts.py --offset <seconds_from_now>
  patch_genesis_ts.py --revert
  patch_genesis_ts.py --show
"""
import hashlib, io, os, re, sys, time

SRC = os.path.expanduser("~/meepcoin-node/src/cryptonote_config.h")
ORIGINAL = 1785283200
PAT = re.compile(r"(#define\s+MEEPCOIN_GENESIS_TIMESTAMP\s+)(\d+)(ULL)")


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def current(s):
    m = PAT.search(s)
    return int(m.group(2)) if m else None


def main():
    if not os.path.exists(SRC):
        print(f"not found: {SRC}"); return 1
    s = io.open(SRC, encoding="utf-8").read()
    cur = current(s)
    if cur is None:
        print("FAIL: MEEPCOIN_GENESIS_TIMESTAMP not found"); return 1

    if "--show" in sys.argv:
        now = int(time.time())
        print(f"current genesis timestamp: {cur}")
        print(f"now: {now}   age: {now - cur} s ({(now - cur) / 86400.0:.2f} days)")
        print(f"config sha256: {sha256(SRC)}")
        return 0

    want = None
    if "--revert" in sys.argv:
        want = ORIGINAL
    for i, a in enumerate(sys.argv):
        if a == "--set" and i + 1 < len(sys.argv):
            want = int(sys.argv[i + 1])
        if a == "--offset" and i + 1 < len(sys.argv):
            want = int(time.time()) + int(sys.argv[i + 1])
    if want is None:
        print(__doc__); return 1

    out = PAT.sub(lambda m: m.group(1) + str(want) + m.group(3), s, count=1)
    io.open(SRC, "w", encoding="utf-8", newline="\n").write(out)
    now = int(time.time())
    print(f"MEEPCOIN_GENESIS_TIMESTAMP {cur} -> {want}")
    print(f"  that is {now - want} s relative to now ({'stale' if now > want else 'in the future'})")
    print(f"  config sha256 {sha256(SRC)}")
    if want == ORIGINAL:
        print("  (this is the original value: reverted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
