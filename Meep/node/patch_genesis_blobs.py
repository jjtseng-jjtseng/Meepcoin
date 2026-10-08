#!/usr/bin/env python3
"""Install the generated MeepCoin genesis coinbase blobs into cryptonote_config.h.

These replace Monero's genesis transaction entirely -- different output key, different tx public
key, MeepCoin unlock time -- rather than editing one byte of Monero's. Each was produced by
src/meepcoin_genesis from a published nothing-up-my-sleeve derivation string; see
docs/GENESIS.md for the derivation and the resulting block hashes.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
CFG = os.path.join(ROOT, "src/cryptonote_config.h")

# Monero's inherited blobs (mainnet/testnet share one; stagenet has its own), already carrying our
# earlier one-byte unlock-time edit.
OLD_SHARED = ("010a01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101"
              "7767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1")
OLD_STAGE  = ("010a01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101"
              "168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b")

# MeepCoin genesis coinbases (meepcoin-genesis <label> 17592186044415 <nonce> 1785283200)
NEW_MAIN = ("010a01ff0001ffffffffffff0302c7f9b2ec8fc915503e9ddc8d9b384a7950654249d1a2959acfefeaaa243dbff72101"
            "bd110f0da95fd1640ee6988d74a81c87f4191bd66407a09845e353551f424921")
NEW_DEV  = ("010a01ff0001ffffffffffff0302efd912a0ef6860c071bb98d0478b3daeb525744ef97a4a1c47499f760e1631eb2101"
            "ee31591d0d4f6436a2ccec0c349dee5a2fdfdcdad8e62f80b0f388049125443f")
NEW_STAGE = ("010a01ff0001ffffffffffff030295372f1c3ad1a6160392c804f8d5175f24908a922ff6707f07259c619255393721014"
             "eb8346861d7466e7032e8f89e537451e9076d19e6974a1dba77f6b7ce8a030c")

s = open(CFG).read()
orig = s

if NEW_DEV in s:
    print("= genesis blobs already installed")
    sys.exit(0)

n = s.count(OLD_SHARED)
if n != 2:
    print(f"! expected 2 occurrences of the shared Monero genesis blob, found {n}")
    sys.exit(1)

# First occurrence is the mainnet slot, second is the devnet (testnet) slot.
i = s.index(OLD_SHARED)
s = s[:i] + NEW_MAIN + s[i + len(OLD_SHARED):]
j = s.index(OLD_SHARED)
s = s[:j] + NEW_DEV + s[j + len(OLD_SHARED):]

if OLD_STAGE not in s:
    print("! stagenet genesis blob not found")
    sys.exit(1)
s = s.replace(OLD_STAGE, NEW_STAGE, 1)

open(CFG, "w").write(s)
print("+ mainnet-slot genesis  -> c7f9b2ec...")
print("+ devnet genesis        -> efd912a0...")
print("+ stagenet-slot genesis -> 95372f1c...")
print("GENESIS_BLOBS_OK")
