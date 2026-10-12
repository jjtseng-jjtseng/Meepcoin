// MeepCoin: the central wallet fork-rule activation predicate.
//
// wallet2::use_fork_rules(version, early_blocks) asks one question -- "should this wallet use the
// rules of fork <version> at the current height?" -- and EVERY wallet-side rule selection goes
// through it: the fee algorithm, the dynamic fee, 2021 fee scaling, ring size, bulletproofs,
// bulletproof+, CLSAG and view tags. The arithmetic it used was inherited unchanged from Monero:
//
//     height >= (int64_t)earliest_height - early_blocks
//
// `early_blocks` is a TRANSITION OFFSET: positive means "start using the rules that many blocks
// BEFORE the fork", negative means "wait that many blocks AFTER it" (Monero's callers pass -10,
// -30 and -420 to stay clear of a live fork boundary).
//
// THE DEFECT THAT PATCH 0007 FIXES. MeepCoin does not replay Monero's fork history: its schedule is
// ONE sparse entry, v16 from height 0, so the daemon answers `earliest_height = 0` for EVERY known
// rule version. Subtracting a negative offset from zero then produces a threshold ABOVE genesis --
// 10, 30, even 420 -- for rules that are in fact active in the genesis block. On this chain at
// height 25 that made
//
//     v8  per-byte fee      (offset   0) -> active
//     v4  dynamic fee       (offset -30) -> INACTIVE
//     v15 2021 fee scaling  (offset -30) -> INACTIVE
//
// so wallet2::get_base_fee() returned the pre-v8 legacy FEE_PER_KB (2,000,000,000) while
// create_transactions_2() was on the per-byte path and multiplied it by the estimated 1,492 bytes:
// a demanded fee of 2,984,000,000,000 atomic units (30.84 MEEP) for a 1 MEEP transfer, against the
// daemon's real 40,000/byte (59,680,000). The wallet refused the spend as "not enough money". No
// consensus rule, no fee constant and no decoy selection was involved: the wallet simply asked the
// wrong question about a fork that was never in transition.
//
// THE RULE. A fork whose earliest height is 0 is active at every height, because there is no
// transition to be early or late for. A fork that is absent from the schedule is never active. A
// fork at a non-zero height keeps Monero's semantics EXACTLY, including the post-fork delays --
// only now computed without wrap-around.
//
// This header holds the whole predicate so the production wallet and the regression binary run the
// SAME code, not two copies that can drift.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#pragma once

#include <cstdint>
#include <limits>

namespace tools
{
  // true iff the rules of a fork whose earliest height is `earliest_height` are to be used at
  // `height`, for a caller that asked for a transition offset of `early_blocks`.
  inline bool fork_rules_active(uint64_t height, uint64_t earliest_height, int64_t early_blocks)
  {
    // Not in the schedule at all. The daemon reports uint64 max for a version it does not know,
    // and an unknown fork is never active -- whatever offset the caller passed.
    if (earliest_height == std::numeric_limits<uint64_t>::max())
      return false;

    // Scheduled at genesis. There is no fork boundary to keep clear of, so the rules hold at every
    // height including 0, and a negative (post-fork delay) offset must not hold them off. This is
    // the whole of the MeepCoin repair: every version <= 16 reports earliest height 0 here.
    if (earliest_height == 0)
      return true;

    // Non-zero fork height: upstream semantics, evaluated so that neither end can wrap.
    if (early_blocks >= 0)
    {
      // Start early, but never before genesis.
      const uint64_t early = (uint64_t)early_blocks;
      const uint64_t threshold = earliest_height > early ? earliest_height - early : 0;
      return height >= threshold;
    }

    // early_blocks < 0: a post-fork delay. Negating it as int64_t would overflow for INT64_MIN, so
    // the magnitude is taken in unsigned arithmetic.
    const uint64_t delay = (uint64_t)(-(early_blocks + 1)) + 1;
    if (delay > std::numeric_limits<uint64_t>::max() - earliest_height)
      return false;   // the delayed threshold is past the end of the number line: never active
    return height >= earliest_height + delay;
  }
}
