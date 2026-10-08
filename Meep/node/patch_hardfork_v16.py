#!/usr/bin/env python3
"""MeepCoin starts at hard-fork/major version 16 from genesis.

Monero's inherited hard-fork tables begin at version 1, which is the PRE-RINGCT transaction era:
no RingCT, no bulletproofs, no view tags. MeepCoin has no legacy chain to replay, so it starts at
the modern ruleset directly.

MeepHash-W v2 remains unconditional at every height -- the CryptoNight/RandomX version branch was
already removed (node/patch_pow_unconditional.py) and is NOT restored here. The hard-fork version
now governs transaction rules only, never PoW selection.

Idempotent.
"""
import os, re, sys

ROOT = os.path.expanduser("~/meepcoin-node")
MARK = "MeepCoin: single hard-fork schedule"
GENESIS_TS = 1785283200
ok = True


def patch(path, old, new, label):
    global ok
    p = os.path.join(ROOT, path)
    s = open(p).read()
    if new in s:
        print(f"  = {label} (already)")
        return
    if old not in s:
        print(f"  ! {label} ANCHOR MISSING")
        ok = False
        return
    open(p, "w").write(s.replace(old, new, 1))
    print(f"  + {label}")


# 1) genesis block version
patch("src/cryptonote_config.h",
      "#define CURRENT_BLOCK_MAJOR_VERSION                     1\n"
      "#define CURRENT_BLOCK_MINOR_VERSION                     0",
      "#define CURRENT_BLOCK_MAJOR_VERSION                     16  // MeepCoin: modern ruleset from genesis\n"
      "#define CURRENT_BLOCK_MINOR_VERSION                     16",
      "CURRENT_BLOCK_MAJOR/MINOR_VERSION -> 16")

# 2) replace all three hard-fork tables with a single MeepCoin schedule
p = os.path.join(ROOT, "src/hardforks/hardforks.cpp")
s = open(p).read()
if MARK in s:
    print("  = hard-fork tables (already)")
else:
    header = f"""// {MARK}: version 16 active from height 0 (genesis inclusive), on every network.
//
// MeepCoin does not replay Monero's fork history. There is no v1..v15 era, so there are no
// pre-RingCT transactions, no pre-bulletproof range proofs and no untagged outputs on this chain.
// Genesis (height 0) carries CURRENT_BLOCK_MAJOR_VERSION, which is also 16.
//
// This governs TRANSACTION rules only. Proof-of-work is MeepHash-W v2 unconditionally at every
// height; the version-dependent CryptoNight/RandomX branch has been removed from
// get_block_longhash and must not be reintroduced.

"""
    for name in ("mainnet_hard_forks", "testnet_hard_forks", "stagenet_hard_forks"):
        m = re.search(r"const hardfork_t " + name + r"\[\] = \{.*?\n\};", s, re.S)
        if not m:
            print(f"  ! {name} not found")
            ok = False
            continue
        s = s[:m.start()] + ("const hardfork_t %s[] = {\n  { 16, 0, 0, %d },\n};" % (name, GENESIS_TS)) + s[m.end():]
        print(f"  + {name} -> single entry {{16, 0, 0, {GENESIS_TS}}}")
    s = header + s
    open(p, "w").write(s)

print("HARDFORK_V16_OK" if ok else "HARDFORK_V16_FAILED")
sys.exit(0 if ok else 1)
