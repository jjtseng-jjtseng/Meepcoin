#!/usr/bin/env python3
"""HardFork::get_ideal_version must consult the FIRST table entry.

    for (unsigned int n = heights.size() - 1; n > 0; --n) { ... }
    return original_version;

The loop stops before index 0, so the first entry is never consulted; upstream relies on index 0
always being {version 1, height 1}, which is also `original_version`. For Monero that is harmless.

MeepCoin's table has a SINGLE entry {version 16, height 0}. heights.size()-1 == 0, the loop body
never runs, and the function returns original_version == 1 for EVERY height.

Consequence: the alternate-block path uses

    const uint8_t hf_version = m_hardfork->get_ideal_version(block_height);
    ... prevalidate_miner_transaction(b, bei.height, hf_version)

so every alternate block was validated as version 1 and its coinbase rejected:

    wrong variant type: txout_to_tagged_key, expected txout_to_key
    miner transaction has invalid output type(s)

That breaks alternate-chain acceptance and therefore reorg handling on a v16 chain -- observed
directly: sibling blocks that lost a mining race were rejected instead of stored as alternatives.

The fix scans every entry including index 0. For a dense Monero-style table the result is
unchanged: index 0 is {1, height 1} and original_version is also 1, so heights >= 1 return 1 either
way and height 0 still falls through to original_version.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_basic/hardfork.cpp")
MARK = "MeepCoin: scan every entry, including index 0"

OLD = """  for (unsigned int n = heights.size() - 1; n > 0; --n) {
    if (height >= heights[n].height) {
      return heights[n].version;
    }
  }
  return original_version;"""

NEW = """  // """ + MARK + """. The original loop stopped before index 0,
  // relying on the first entry always being {version 1, height 1} (== original_version). MeepCoin
  // has a single {16, height 0} entry, so that loop never executed and this returned 1 for every
  // height -- which made the alternate-block path validate coinbases as version 1 and reject
  // txout_to_tagged_key outputs. Behaviour on a dense table is unchanged.
  for (unsigned int n = heights.size(); n-- > 0; ) {
    if (height >= heights[n].height) {
      return heights[n].version;
    }
  }
  return original_version;"""

s = open(P).read()
if MARK in s:
    print("= get_ideal_version already patched")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found in get_ideal_version")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ HardFork::get_ideal_version now consults index 0 (sparse-schedule safe)")
print("IDEAL_VERSION_OK")
