#!/usr/bin/env python3
"""Make MeepCoin block PoW unconditionally MeepHash-W v2.

BUG THIS FIXES
--------------
Monero selects its PoW by block major_version:

    if (major_version >= RX_BLOCK_VERSION)   // 12
        rx_slow_hash(...)                    // RandomX  -> replaced by meep_slow_hash
    else
        cn_slow_hash(...)                    // CryptoNight

MeepCoin inherits Monero's hard-fork table, which starts at major_version 1. A fresh MeepCoin
chain therefore mines blocks at version 1 and takes the **CryptoNight** branch. The MeepHash-W v2
bridge was linked and correct but was never reached.

Observed directly: block 1 had major_version 1, and its daemon-reported pow_hash did not match a
MeepHash-W v2 computation over the same inputs.

MeepCoin has no CryptoNight or RandomX history to remain compatible with -- it is a new chain whose
entire premise is MeepHash-W. The version branch is therefore removed: every block, at every
height, uses MeepHash-W v2.

This changes MeepCoin's block PoW rule. It does NOT touch the frozen MeepHash-W v2 algorithm.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_core/cryptonote_tx_utils.cpp")
MARK = "MeepCoin: MeepHash-W v2 is the ONLY block PoW"

OLD = """    if (major_version >= RX_BLOCK_VERSION)
    {
      crypto::hash hash;
      if (pbc != NULL)
      {
        const uint64_t seed_height = rx_seedheight(height);
        hash = seed_hash ? *seed_hash : pbc->get_pending_block_id_by_height(seed_height);
      } else
      {
        memset(&hash, 0, sizeof(hash));  // only happens when generating genesis block
      }
      // MeepCoin: MeepHash-W v2 replaces RandomX (mining AND verification).
      meep_slow_hash(hash.data, height, bd.data(), bd.size(), res.data);
    } else {
      const int pow_variant = major_version >= 7 ? major_version - 6 : 0;
      crypto::cn_slow_hash(bd.data(), bd.size(), res, pow_variant, height);
    }
    return true;"""

NEW = """    // """ + MARK + """, at every height and every block version.
    //
    // Monero switches PoW on major_version (CryptoNight below 12, RandomX at/above). MeepCoin
    // inherits the hard-fork table, so a fresh chain mines at version 1 and would silently take
    // the CryptoNight branch -- which is exactly what happened before this fix. MeepCoin has no
    // CryptoNight or RandomX history to stay compatible with, so the branch is removed entirely.
    {
      crypto::hash hash;
      if (pbc != NULL)
      {
        const uint64_t seed_height = rx_seedheight(height);
        hash = seed_hash ? *seed_hash : pbc->get_pending_block_id_by_height(seed_height);
      } else
      {
        memset(&hash, 0, sizeof(hash));  // only happens when generating the genesis block
      }
      meep_slow_hash(hash.data, height, bd.data(), bd.size(), res.data);
    }
    (void)major_version;
    return true;"""

s = open(P).read()
if MARK in s:
    print("= PoW already unconditional")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found -- inspect get_block_longhash manually")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ block PoW is now unconditionally MeepHash-W v2 (CryptoNight branch removed)")
print("POW_UNCONDITIONAL_OK")
