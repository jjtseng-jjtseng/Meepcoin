#!/usr/bin/env python3
"""Empty-chain boundary fix required by starting at hard-fork version 16.

Monero's long-term block weight logic activates at HF_VERSION_LONG_TERM_BLOCK_WEIGHT (11). In stock
Monero, genesis is version 1, so at genesis the function returns early and the window is never
consulted. MeepCoin starts at version 16, so genesis takes the v11+ path with an EMPTY chain:

    db_height = 0  ->  nblocks = 0  ->  get_long_term_block_weight_median(0, 0)
    -> CHECK_AND_ASSERT_THROW_MES(count > 0, "count == 0")   -> genesis rejected

Observed as: `Error adding block with hash: <...> to blockchain, what = count == 0`.

With no blocks there is no window and no median to compute, so the long-term weight is simply the
block's own weight -- exactly what the pre-v11 path returns. This is a boundary fix for an empty
chain, not a change to the weight algorithm: for db_height >= 1 the behaviour is untouched.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_core/blockchain.cpp")
MARK = "MeepCoin: empty chain has no long-term weight window"

OLD = """  const uint8_t hf_version = get_current_hard_fork_version();
  if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT)
    return block_weight;

  uint64_t long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);"""

NEW = """  const uint8_t hf_version = get_current_hard_fork_version();
  if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT)
    return block_weight;

  // """ + MARK + """. MeepCoin starts at version 16, so
  // unlike stock Monero (whose genesis is version 1) this path is reached while the chain is still
  // empty. nblocks is then 0 and get_long_term_block_weight_median throws "count == 0", rejecting
  // genesis. With no blocks there is no median to take, so the long-term weight is the block's own
  // weight -- identical to what the pre-v11 branch above returns. Behaviour for db_height >= 1 is
  // unchanged.
  if (nblocks == 0)
    return block_weight;

  uint64_t long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);"""

s = open(P).read()
if MARK in s:
    print("= empty-chain boundary already patched")
elif OLD not in s:
    print("! anchor not found in get_next_long_term_block_weight")
    sys.exit(1)
else:
    open(P, "w").write(s.replace(OLD, NEW, 1))
    print("+ get_next_long_term_block_weight guards the empty chain (nblocks == 0)")

# ---------------------------------------------------------------------------------------------
# Second empty-chain boundary: BlockchainLMDB::add_block computes the cumulative RingCT output
# count by reading the PREVIOUS block's info whenever major_version >= 4:
#
#     uint64_t last_height = m_height - 1;      // m_height == 0 at genesis -> UINT64_MAX
#
# Stock Monero never reaches this at genesis (version 1 < 4). At version 16 it underflows and the
# lookup fails with MDB_NOTFOUND, rejecting genesis. With no previous block the cumulative count is
# just this block's own, which is what skipping the branch already produces.
P2 = os.path.join(ROOT, "src/blockchain_db/lmdb/db_lmdb.cpp")
MARK2 = "MeepCoin: genesis has no previous block"
OLD2 = """  if (blk.major_version >= 4)
  {
    uint64_t last_height = m_height-1;"""
NEW2 = """  // """ + MARK2 + """ to accumulate from; m_height-1 would underflow.
  // Stock Monero never reaches this at genesis because its genesis is version 1 (< 4).
  if (blk.major_version >= 4 && m_height > 0)
  {
    uint64_t last_height = m_height-1;"""

s2 = open(P2).read()
if MARK2 in s2:
    print("= lmdb add_block boundary already patched")
elif OLD2 not in s2:
    print("! lmdb add_block anchor not found")
    sys.exit(1)
else:
    open(P2, "w").write(s2.replace(OLD2, NEW2, 1))
    print("+ BlockchainLMDB::add_block guards m_height == 0 at genesis")

print("V16_GENESIS_BOUNDARY_OK")
