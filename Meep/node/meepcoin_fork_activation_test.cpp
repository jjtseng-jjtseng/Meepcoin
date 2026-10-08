// meepcoin-fork-activation-test -- the wallet fork-rule activation predicate (patch 0007).
//
// This runs the PRODUCTION predicate: tools::fork_rules_active() out of src/wallet/fork_rules.h is
// the entire body of wallet2::use_fork_rules(), so there is no second copy of the rule to drift.
// The schedule half uses the real cryptonote::HardFork over the real src/blockchain_db/testdb.h and
// the real mainnet_hard_forks table, and the fee half calls the production weight estimator
// (wallet2::estimate_tx_weight_for_shape) and the production rounding (cryptonote::round_money_up).
//
// Why a standalone binary rather than tests/unit_tests: the pinned build configures
// BUILD_TESTS=OFF, so a case added there would never run, and a test that never runs is worse than
// no test because it looks like coverage.
//
// WHAT IT DOES NOT DO. It opens no wallet, reads no key, starts no daemon, makes no RPC call,
// constructs no transaction and spends nothing. Every number below is arithmetic on constants or on
// the compiled schedule.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "blockchain_db/testdb.h"
#include "hardforks/hardforks.h"
#include "wallet/fork_rules.h"
#include "wallet/wallet2.h"

using namespace cryptonote;

namespace
{

const uint64_t ABSENT = std::numeric_limits<uint64_t>::max();

int g_pass = 0, g_fail = 0;

void chk(bool cond, const std::string &label)
{
  if (cond) { ++g_pass; std::printf("  [PASS] %s\n", label.c_str()); }
  else      { ++g_fail; std::printf("  [FAIL] %s\n", label.c_str()); }
}

// The INHERITED expression, kept here as the witness of the defect and of nothing else. It is not a
// second implementation of the rule: it is what the rule used to be, and every place it is used
// below asserts that it gives the WRONG answer on this chain. If patch 0007 is reverted, the
// production predicate becomes this function and those assertions fail.
bool upstream_expression(uint64_t height, uint64_t earliest_height, int64_t early_blocks)
{
  return (int64_t)height >= (int64_t)earliest_height - early_blocks && earliest_height != ABSENT;
}

class TestDB : public cryptonote::BaseTestDB
{
public:
  virtual uint64_t height() const override { return 0; }
  virtual crypto::hash get_block_hash_from_height(const uint64_t &h) const override
  {
    crypto::hash hash = crypto::null_hash;
    *(uint64_t *)&hash = h;
    return hash;
  }
};

// The real schedule, installed through the production installer the daemon's Blockchain::init()
// uses, and read back exactly as the hard_fork_info RPC reads it.
struct Schedule
{
  TestDB db;
  cryptonote::HardFork hf;
  bool installed;
  Schedule() : hf(db, 16, 0), installed(false)
  {
    std::vector<::hardfork_t> s;
    for (size_t i = 0; i < num_mainnet_hard_forks; ++i)
      s.push_back(mainnet_hard_forks[i]);
    std::string err;
    installed = cryptonote::install_and_verify_hardfork_schedule(hf, s, 16, err);
  }
  // What the daemon's hard_fork_info RPC reports as earliest_height, and what the wallet feeds to
  // the predicate.
  uint64_t earliest(uint8_t version) const { return hf.get_earliest_ideal_height_for_version(version); }
};

// The failed round's exact transfer shape: 1 input, ring 16 (mixin 15), 2 outputs, no extra,
// bulletproof+, CLSAG, view tags -- all of which the v16 rules select.
const int      SHAPE_INPUTS  = 1;
const int      SHAPE_MIXIN   = 15;
const int      SHAPE_OUTPUTS = 2;
const size_t   SHAPE_EXTRA   = 0;
const uint64_t SHAPE_WEIGHT  = 1492;

// Measured on the daemon that refused the spend, at height 25: raw 39,735/byte, rounded to two
// significant places by Blockchain::get_dynamic_base_fee_estimate_2021_scaling(). The rounding is
// re-run below with the production function; the daemon-side value itself is cross-checked by the
// read-only get_fee_estimate probe recorded with this patch, not asserted from thin air here.
const uint64_t DAEMON_RAW_FEE_PER_BYTE     = 39735;
const uint64_t DAEMON_ROUNDED_FEE_PER_BYTE = 40000;

// Wallet B's balance at the failure, in atomic units (11.92092327073 MEEP).
const uint64_t WALLET_B_BALANCE = 1192092327073ULL;

} // namespace

// The compiled fee constants the two paths land on. If any of these moves, the arithmetic below is
// describing a different chain and the BUILD fails rather than a test run.
static_assert(COIN == 100000000000ULL, "MeepCoin: 11 decimals");
static_assert(FEE_PER_KB == 2000000000ULL, "MeepCoin: the inherited legacy per-kB fee");
static_assert(HF_VERSION_DYNAMIC_FEE == 4, "");
static_assert(HF_VERSION_PER_BYTE_FEE == 8, "");
static_assert(HF_VERSION_SMALLER_BP == 10, "");
static_assert(HF_VERSION_CLSAG == 13, "");
static_assert(HF_VERSION_2021_SCALING == 15, "");
static_assert(HF_VERSION_BULLETPROOF_PLUS == 15, "");
static_assert(HF_VERSION_MIN_MIXIN_15 == 15, "");

int main()
{
  std::printf("MeepCoin wallet fork-rule activation test (patch 0007)\n");
  std::printf("======================================================\n\n");

  set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

  // ------------------------------------------------------------------ 1. a fork at genesis
  std::printf("1. earliest height 0 -- active everywhere, whatever the transition offset\n");
  {
    const int64_t offsets[] = { -420, -30, -10, 0, 10, 30 };
    const uint64_t heights[] = { 0, 1, 25, 29, 30, 1000 };
    bool all = true;
    for (int64_t off : offsets)
      for (uint64_t h : heights)
        all = all && tools::fork_rules_active(h, 0, off);
    chk(all, "every offset in {-420,-30,-10,0,10,30} is active at heights 0,1,25,29,30,1000");
    chk(tools::fork_rules_active(0, 0, -30), "offset -30 active at the genesis block itself");
    chk(tools::fork_rules_active(25, 0, -30), "offset -30 active at height 25 (the failed height)");
    chk(tools::fork_rules_active(29, 0, -30), "offset -30 active at height 29");
    chk(tools::fork_rules_active(30, 0, -30), "offset -30 active at height 30");
    chk(tools::fork_rules_active(25, 0, -420), "offset -420 active at height 25");
    chk(tools::fork_rules_active(25, 0, -10), "offset -10 active at height 25");
    chk(tools::fork_rules_active(25, 0, 0) && tools::fork_rules_active(25, 0, 10),
        "zero and positive offsets active at height 25");
    // The defect, reproduced.
    chk(!upstream_expression(25, 0, -30), "WITNESS: the inherited expression was FALSE at height 25 (-30)");
    chk(!upstream_expression(29, 0, -30), "WITNESS: the inherited expression was FALSE at height 29 (-30)");
    chk(upstream_expression(30, 0, -30), "WITNESS: the inherited expression only became true at height 30");
    chk(!upstream_expression(25, 0, -420), "WITNESS: the inherited expression held v3 rules off until height 420");
    chk(!upstream_expression(5, 0, -10), "WITNESS: the inherited expression held -10 rules off until height 10");
  }

  // ------------------------------------------------------------------ 2. a fork that is absent
  std::printf("\n2. earliest height uint64 max -- never active\n");
  {
    const int64_t offsets[] = { -420, -30, -10, 0, 10, 30,
                                std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max() };
    bool none = false;
    for (int64_t off : offsets)
    {
      none = none || tools::fork_rules_active(0, ABSENT, off);
      none = none || tools::fork_rules_active(25, ABSENT, off);
      none = none || tools::fork_rules_active(ABSENT, ABSENT, off);
    }
    chk(!none, "absent fork is inactive at heights 0, 25 and uint64 max for every offset");
  }

  // ------------------------------------------------------------------ 3. a fork at a real height
  std::printf("\n3. earliest height 100 -- upstream semantics, preserved exactly\n");
  {
    chk(!tools::fork_rules_active(129, 100, -30), "offset -30: inactive at 129");
    chk(tools::fork_rules_active(130, 100, -30),  "offset -30: active at 130");
    chk(!tools::fork_rules_active(89, 100, 10),   "offset +10: inactive at 89");
    chk(tools::fork_rules_active(90, 100, 10),    "offset +10: active at 90");
    chk(!tools::fork_rules_active(99, 100, 0),    "offset 0: inactive at 99");
    chk(tools::fork_rules_active(100, 100, 0),    "offset 0: active at 100");
    chk(!tools::fork_rules_active(0, 100, -420) && tools::fork_rules_active(520, 100, -420),
        "offset -420: inactive at 0, active at 520");

    // The non-zero cases must agree with the inherited expression, value for value: patch 0007 is a
    // repair of the genesis case only.
    bool agree = true;
    const int64_t offs[] = { -420, -30, -10, 0, 10, 30 };
    for (int64_t off : offs)
      for (uint64_t h = 0; h <= 600; ++h)
        agree = agree && (tools::fork_rules_active(h, 100, off) == upstream_expression(h, 100, off));
    chk(agree, "heights 0..600 x offsets {-420..30} agree with the inherited expression at earliest 100");
  }

  // ------------------------------------------------------------------ 4. arithmetic extremes
  std::printf("\n4. arithmetic extremes -- no wrap-around either way\n");
  {
    const int64_t MINV = std::numeric_limits<int64_t>::min();
    const int64_t MAXV = std::numeric_limits<int64_t>::max();
    const uint64_t two63 = (uint64_t)1 << 63;
    chk(!tools::fork_rules_active(two63 + 99, 100, MINV),
        "a delay of 2^63 from height 100: inactive one block below the threshold");
    chk(tools::fork_rules_active(two63 + 100, 100, MINV),
        "a delay of 2^63 from height 100: active exactly at the threshold, not wrapped");
    chk(!tools::fork_rules_active(ABSENT - 1, two63, MINV),
        "a delay of 2^63 from height 2^63 runs off the end: inactive, not a wrapped 'active'");
    chk(tools::fork_rules_active(0, 100, MAXV), "an early start of 2^63-1 clamps to genesis, active at 0");
    chk(!tools::fork_rules_active(ABSENT - 2, ABSENT - 1, -1),
        "earliest uint64max-1 with a one-block delay: inactive, and no overflow");
    chk(tools::fork_rules_active(ABSENT - 1, ABSENT - 1, 0), "earliest uint64max-1, offset 0: active at that height");
    chk(!tools::fork_rules_active(ABSENT - 2, ABSENT - 1, 0), "earliest uint64max-1, offset 0: inactive one below");
    chk(tools::fork_rules_active(ABSENT - 1, 1, MAXV), "huge early start, huge height: still active");
    chk(tools::fork_rules_active(0, 0, MINV) && tools::fork_rules_active(0, 0, MAXV),
        "genesis fork is active at height 0 for both int64 extremes");
  }

  // ------------------------------------------------------------------ 5. the MeepCoin schedule
  std::printf("\n5. the compiled MeepCoin schedule, through the real HardFork\n");
  {
    Schedule s;
    chk(s.installed, "the production installer accepted the compiled schedule");
    const uint8_t zero_versions[] = { 1, 2, 3, 4, 5, 8, 10, 13, 15, 16 };
    bool all_zero = true;
    for (uint8_t v : zero_versions)
      all_zero = all_zero && s.earliest(v) == 0;
    chk(all_zero, "v1..v16 (incl. 4, 8, 10, 13, 15, 16) all report earliest height 0");
    chk(s.earliest(17) == ABSENT, "v17 is absent from the schedule (uint64 max)");
    chk(s.earliest(255) == ABSENT, "v255 is absent from the schedule (uint64 max)");
    chk(num_mainnet_hard_forks == 1 && mainnet_hard_forks[0].version == 16 && mainnet_hard_forks[0].height == 0,
        "the schedule is still the single sparse entry {v16, height 0}");
  }

  // ------------------------------------------------------------------ 6. the production callers
  std::printf("\n6. what wallet2's own call sites select, at heights 0, 25, 29 and 30\n");
  {
    Schedule s;
    struct Caller { const char *what; uint8_t version; int64_t offset; };
    // Exactly the (version, offset) pairs wallet2.cpp passes for rule selection.
    const Caller callers[] = {
      { "v4  dynamic fee            (-30)", HF_VERSION_DYNAMIC_FEE,      -30 },
      { "v8  per-byte fee           (  0)", HF_VERSION_PER_BYTE_FEE,       0 },
      { "v15 2021 fee scaling       (-30)", HF_VERSION_2021_SCALING,     -30 },
      { "v3  fee algorithm 1        (-420)", 3,                          -420 },
      { "v15 bulletproof+           (-10)", HF_VERSION_BULLETPROOF_PLUS, -10 },
      { "v13 CLSAG                  (-10)", HF_VERSION_CLSAG,            -10 },
      { "v10 smaller bulletproof    (-10)", HF_VERSION_SMALLER_BP,       -10 },
      { "v15 min ring size 16       (  0)", HF_VERSION_MIN_MIXIN_15,       0 },
      { "v15 view tags              (  0)", HF_VERSION_VIEW_TAGS,          0 },
      { "v4  RingCT                 (  0)", 4,                             0 },
    };
    const uint64_t heights[] = { 0, 25, 29, 30 };
    for (const Caller &c : callers)
    {
      bool all = true;
      for (uint64_t h : heights)
        all = all && tools::fork_rules_active(h, s.earliest(c.version), c.offset);
      chk(all, std::string("active at 0/25/29/30: ") + c.what);
    }
    // And the defect, per caller, at the height the transfer actually failed at.
    chk(!upstream_expression(25, s.earliest(HF_VERSION_DYNAMIC_FEE), -30),
        "WITNESS: v4 dynamic fee was inactive at height 25 before the fix");
    chk(!upstream_expression(25, s.earliest(HF_VERSION_2021_SCALING), -30),
        "WITNESS: v15 2021 fee scaling was inactive at height 25 before the fix");
    chk(upstream_expression(25, s.earliest(HF_VERSION_PER_BYTE_FEE), 0),
        "WITNESS: v8 per-byte fee WAS active at height 25 -- the inconsistency that priced the transfer");
    // A version the schedule does not contain must stay off, fix or no fix.
    chk(!tools::fork_rules_active(25, s.earliest(17), 0) && !tools::fork_rules_active(25, s.earliest(17), -30),
        "a future v17 is not switched on by the repair");
  }

  // ------------------------------------------------------------------ 7. the fee that failed
  std::printf("\n7. the exact transfer that was refused, priced both ways\n");
  {
    const uint64_t weight = tools::wallet2::estimate_tx_weight_for_shape(
        /*use_rct*/ true, SHAPE_INPUTS, SHAPE_MIXIN, SHAPE_OUTPUTS, SHAPE_EXTRA,
        /*bulletproof*/ true, /*clsag*/ true, /*bulletproof_plus*/ true, /*use_view_tags*/ true);
    std::printf("   estimated weight            = %llu bytes\n", (unsigned long long)weight);
    chk(weight == SHAPE_WEIGHT, "the production estimator gives 1492 bytes for 1-in/2-out ring 16 BP+ CLSAG view-tag");

    chk(cryptonote::round_money_up(DAEMON_RAW_FEE_PER_BYTE, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES)
          == DAEMON_ROUNDED_FEE_PER_BYTE,
        "the production rounding turns the daemon's raw 39,735/byte into 40,000/byte");

    const uint64_t fixed_fee = weight * DAEMON_ROUNDED_FEE_PER_BYTE;
    const uint64_t broken_fee = weight * FEE_PER_KB;   // per-byte path x the legacy per-kB constant
    std::printf("   fee with the v16 rate       = %llu atomic = %s MEEP\n",
                (unsigned long long)fixed_fee, print_money(fixed_fee).c_str());
    std::printf("   fee the wallet demanded     = %llu atomic = %s MEEP\n",
                (unsigned long long)broken_fee, print_money(broken_fee).c_str());
    chk(fixed_fee == 59680000ULL, "1492 x 40,000 = 59,680,000 atomic");
    chk(broken_fee == 2984000000000ULL, "1492 x 2,000,000,000 = 2,984,000,000,000 atomic (the bogus demand)");
    chk(DAEMON_ROUNDED_FEE_PER_BYTE != FEE_PER_KB, "the base rate is the 40,000/byte one, not the 2e9 one");

    const uint64_t one_meep = COIN;
    chk(one_meep + fixed_fee <= WALLET_B_BALANCE,
        "1 MEEP + 59,680,000 fits inside the 11.92092327073 MEEP balance");
    chk(one_meep + broken_fee > WALLET_B_BALANCE,
        "WITNESS: 1 MEEP + the bogus fee did not -- which is the -17 'not enough money' that was reported");
  }

  std::printf("\n======================================================\n");
  std::printf("passed %d, failed %d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
