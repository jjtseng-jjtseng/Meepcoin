// meepcoin-econ-dump — print AND ASSERT the actually compiled economics, and project emission.
//
// This links the real consensus headers and calls the real get_block_reward(). It exists because
// documentation and Python simulations are not evidence about what the daemon does.
//
// The approved values are asserted twice over:
//   * static_assert for everything knowable at compile time -- so a wrong constant FAILS THE BUILD
//   * runtime checks for the reward figures, which come from calling the real function
// Any mismatch is a non-zero exit.
//
// Usage:
//   meepcoin-econ-dump              print constants + rewards, assert the approved values
//   meepcoin-econ-dump --project    additionally project emission from the compiled rules
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

using namespace cryptonote;

// ---------------------------------------------------------------------------------------------
// The approved economics. These are the numbers the project owner signed off on; they are written
// here once and then asserted against the compiled constants.
// ---------------------------------------------------------------------------------------------
static const unsigned  APPROVED_DECIMALS        = 11;
static const uint64_t  APPROVED_COIN            = 100000000000ULL;        // 10^11
static const uint64_t  APPROVED_MONEY_SUPPLY    = 2500000000000000000ULL; // 2.5 x 10^18 atomic
static const int       APPROVED_SHIFT           = 21;                     // effective, at 60 s
static const uint64_t  APPROVED_TAIL_PER_BLOCK  = 12500000000ULL;         // 0.125 MEEP
static const uint64_t  APPROVED_GENESIS_REWARD  = 1192092895507ULL;
static const int       APPROVED_UNLOCK_WINDOW   = 10;                     // dev value
static const int       APPROVED_BLOCK_TARGET    = 60;                     // seconds

// Blocks per year at a 60-second target: 365.25 * 24 * 60.
static const uint64_t  BLOCKS_PER_YEAR          = 525960;
static const uint64_t  BLOCKS_PER_DAY           = 1440;

// ---------------------------------------------------------------------------------------------
// Compile-time assertions: a wrong constant must fail the BUILD, not just the test run.
// ---------------------------------------------------------------------------------------------
static_assert(CRYPTONOTE_DISPLAY_DECIMAL_POINT == 11,
              "MeepCoin: display decimals must be 11");
static_assert(COIN == 100000000000ULL,
              "MeepCoin: COIN must be 100,000,000,000 (10^11)");
static_assert(MONEY_SUPPLY == 2500000000000000000ULL,
              "MeepCoin: MONEY_SUPPLY must be 2,500,000,000,000,000,000 atomic");
static_assert(DIFFICULTY_TARGET_V2 == 60,
              "MeepCoin: block target must be 60 seconds");
static_assert(EMISSION_SPEED_FACTOR_PER_MINUTE - (DIFFICULTY_TARGET_V2 / 60 - 1) == 21,
              "MeepCoin: effective emission shift must be 21 at the 60 s target");
static_assert(FINAL_SUBSIDY_PER_MINUTE * (DIFFICULTY_TARGET_V2 / 60) == 12500000000ULL,
              "MeepCoin: tail reward must be 12,500,000,000 atomic per block (0.125 MEEP)");
static_assert(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW == 10,
              "MeepCoin dev chain: mined-money unlock window must be 10 blocks");
static_assert((MONEY_SUPPLY >> 21) == 1192092895507ULL,
              "MeepCoin: MONEY_SUPPLY >> 21 must be 1,192,092,895,507 atomic");

static int g_fail = 0;

static std::string fmt_atomic(uint64_t v, unsigned decimals) {
    // Render an atomic amount with the COMPILED decimal count, no rounding.
    uint64_t div = 1;
    for (unsigned i = 0; i < decimals; ++i) div *= 10;
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%llu.%0*llu",
                  (unsigned long long)(v / div), (int)decimals, (unsigned long long)(v % div));
    return buf;
}

static void assert_u64(const char *what, uint64_t got, uint64_t want) {
    if (got == want) {
        std::printf("  [OK]     %-38s = %llu\n", what, (unsigned long long)got);
    } else {
        std::printf("  [FAILED] %-38s = %llu, approved value is %llu\n",
                    what, (unsigned long long)got, (unsigned long long)want);
        ++g_fail;
    }
}

// ---------------------------------------------------------------------------------------------
// Emission projection, driven entirely by the real get_block_reward().
// ---------------------------------------------------------------------------------------------
struct Projection {
    uint64_t tail_start_height = 0;      // first height paying exactly the tail floor
    uint64_t supply_at_tail_start = 0;   // emitted supply entering that height
    uint64_t cross_25m_height = 0;       // first height where emitted supply >= 25,000,000 MEEP
    uint64_t supply_at_25m = 0;
    std::vector<std::pair<uint64_t, uint64_t> > milestones;   // (height, emitted supply before it)
    std::vector<std::pair<uint64_t, uint64_t> > rewards_at;   // (height, reward paid at it)
};

static bool project(Projection &p, const std::vector<uint64_t> &milestone_heights,
                    uint64_t horizon_blocks) {
    const uint64_t target_25m = 25000000ULL * APPROVED_COIN;
    uint64_t already = 0;
    size_t next_ms = 0;

    for (uint64_t h = 0; h < horizon_blocks; ++h) {
        uint64_t reward = 0;
        if (!get_block_reward(0, 0, already, reward, 16)) return false;

        // Record the reward paid AT a milestone height, and the supply before it is added.
        if (next_ms < milestone_heights.size() && h == milestone_heights[next_ms]) {
            p.milestones.push_back(std::make_pair(h, already));
            p.rewards_at.push_back(std::make_pair(h, reward));
            ++next_ms;
        }

        if (p.tail_start_height == 0 && reward == APPROVED_TAIL_PER_BLOCK) {
            p.tail_start_height = h;
            p.supply_at_tail_start = already;
        }

        already += reward;

        if (p.cross_25m_height == 0 && already >= target_25m) {
            p.cross_25m_height = h;
            p.supply_at_25m = already;
        }

        // Everything of interest is recorded; the rest of the tail era is constant arithmetic.
        if (p.tail_start_height != 0 && p.cross_25m_height != 0
            && next_ms >= milestone_heights.size())
            return true;
    }
    return true;
}

int main(int argc, char **argv) {
    const bool do_project = (argc > 1 && std::strcmp(argv[1], "--project") == 0);

    const int target_minutes  = DIFFICULTY_TARGET_V2 / 60;
    const int effective_shift = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1);
    const unsigned decimals   = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
    const uint64_t tail_per_block = (uint64_t)FINAL_SUBSIDY_PER_MINUTE * target_minutes;

    std::printf("=== MeepCoin COMPILED economics (from the linked consensus headers) ===\n\n");

    std::printf("COIN                                = %llu atomic units per coin\n",
                (unsigned long long)COIN);
    std::printf("CRYPTONOTE_DISPLAY_DECIMAL_POINT    = %u\n", decimals);
    std::printf("MONEY_SUPPLY                        = %llu atomic\n",
                (unsigned long long)MONEY_SUPPLY);
    std::printf("MONEY_SUPPLY (displayed)            = %s MEEP\n",
                fmt_atomic(MONEY_SUPPLY, decimals).c_str());
    std::printf("EMISSION_SPEED_FACTOR_PER_MINUTE    = %d\n", EMISSION_SPEED_FACTOR_PER_MINUTE);
    std::printf("DIFFICULTY_TARGET_V2                = %d seconds  (target_minutes = %d)\n",
                DIFFICULTY_TARGET_V2, target_minutes);
    std::printf("effective emission shift            = %d   [ESF_PER_MINUTE - (target_minutes-1)]\n",
                effective_shift);
    std::printf("FINAL_SUBSIDY_PER_MINUTE            = %llu atomic\n",
                (unsigned long long)FINAL_SUBSIDY_PER_MINUTE);
    std::printf("tail reward per block               = %llu atomic = %s MEEP\n",
                (unsigned long long)tail_per_block,
                fmt_atomic(tail_per_block, decimals).c_str());
    std::printf("CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW= %d blocks\n",
                CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    std::printf("HF_VERSION_EXACT_COINBASE           = %d\n", HF_VERSION_EXACT_COINBASE);
    std::printf("CURRENT_BLOCK_MAJOR_VERSION         = %d\n", CURRENT_BLOCK_MAJOR_VERSION);
    std::printf("CURRENT_BLOCK_MINOR_VERSION         = %d\n", CURRENT_BLOCK_MINOR_VERSION);

    std::printf("\n=== Rewards from the REAL get_block_reward() ===\n");
    std::printf("(src/cryptonote_basic/cryptonote_basic_impl.cpp)\n\n");

    uint64_t genesis_reward = 0;
    if (!get_block_reward(0, 0, 0, genesis_reward, 16)) {
        std::printf("get_block_reward FAILED at height 0\n");
        return 1;
    }
    std::printf("genesis reward (already=0)          = %llu atomic = %s MEEP\n",
                (unsigned long long)genesis_reward,
                fmt_atomic(genesis_reward, decimals).c_str());

    // Block 1 is computed with already_generated_coins == the genesis amount, i.e. AFTER genesis.
    uint64_t block1_reward = 0;
    if (!get_block_reward(0, 0, genesis_reward, block1_reward, 16)) {
        std::printf("get_block_reward FAILED at height 1\n");
        return 1;
    }
    std::printf("block-1 reward (already=genesis)    = %llu atomic = %s MEEP\n",
                (unsigned long long)block1_reward,
                fmt_atomic(block1_reward, decimals).c_str());
    std::printf("  (calculated after the genesis amount, so it is %llu atomic lower)\n",
                (unsigned long long)(genesis_reward - block1_reward));

    const uint64_t manual = (MONEY_SUPPLY - 0) >> effective_shift;
    std::printf("\nmanual (MONEY_SUPPLY >> %d)          = %llu atomic  [%s]\n",
                effective_shift, (unsigned long long)manual,
                manual == genesis_reward ? "MATCHES get_block_reward" : "DIFFERS -- investigate");

    // -----------------------------------------------------------------------------------------
    std::printf("\n=== Assertions against the APPROVED economics ===\n\n");
    assert_u64("display decimals",           decimals,                  APPROVED_DECIMALS);
    assert_u64("COIN",                       COIN,                      APPROVED_COIN);
    assert_u64("MONEY_SUPPLY",               MONEY_SUPPLY,              APPROVED_MONEY_SUPPLY);
    assert_u64("effective emission shift",   (uint64_t)effective_shift, (uint64_t)APPROVED_SHIFT);
    assert_u64("tail reward per 60 s block", tail_per_block,            APPROVED_TAIL_PER_BLOCK);
    assert_u64("genesis reward",             genesis_reward,            APPROVED_GENESIS_REWARD);
    assert_u64("mined-money unlock window",  CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
                                             (uint64_t)APPROVED_UNLOCK_WINDOW);
    assert_u64("block target (seconds)",     DIFFICULTY_TARGET_V2,
                                             (uint64_t)APPROVED_BLOCK_TARGET);

    // Block-1 is not a fixed approved figure; what matters is that it is derived from the genesis
    // amount. Check that relationship rather than a magic number.
    {
        const uint64_t expected_b1 = (MONEY_SUPPLY - genesis_reward) >> effective_shift;
        if (block1_reward == expected_b1 && block1_reward < genesis_reward) {
            std::printf("  [OK]     %-38s = %llu  (= (MONEY_SUPPLY - genesis) >> %d)\n",
                        "block-1 reward after genesis",
                        (unsigned long long)block1_reward, effective_shift);
        } else {
            std::printf("  [FAILED] %-38s = %llu, expected %llu\n",
                        "block-1 reward after genesis",
                        (unsigned long long)block1_reward, (unsigned long long)expected_b1);
            ++g_fail;
        }
    }
    // COIN must be exactly 10^decimals or every displayed amount is misscaled.
    {
        uint64_t p10 = 1;
        for (unsigned i = 0; i < decimals; ++i) p10 *= 10;
        if (p10 == COIN)
            std::printf("  [OK]     %-38s = 10^%u\n", "COIN matches the decimal point", decimals);
        else {
            std::printf("  [FAILED] %-38s: COIN=%llu but 10^%u=%llu\n",
                        "COIN matches the decimal point",
                        (unsigned long long)COIN, decimals, (unsigned long long)p10);
            ++g_fail;
        }
    }

    // -----------------------------------------------------------------------------------------
    if (do_project) {
        std::printf("\n=== Emission projection from the COMPILED rules ===\n");
        std::printf("(every figure below comes from iterating the real get_block_reward();\n");
        std::printf(" %llu blocks per year at the compiled %d-second target)\n\n",
                    (unsigned long long)BLOCKS_PER_YEAR, DIFFICULTY_TARGET_V2);

        std::vector<uint64_t> ms;
        ms.push_back(0);
        ms.push_back(BLOCKS_PER_DAY);          // 1 day
        ms.push_back(30 * BLOCKS_PER_DAY);     // 30 days
        ms.push_back(1  * BLOCKS_PER_YEAR);
        ms.push_back(5  * BLOCKS_PER_YEAR);
        ms.push_back(10 * BLOCKS_PER_YEAR);
        ms.push_back(15 * BLOCKS_PER_YEAR);
        ms.push_back(20 * BLOCKS_PER_YEAR);
        ms.push_back(25 * BLOCKS_PER_YEAR);

        Projection p;
        if (!project(p, ms, 80 * BLOCKS_PER_YEAR)) {
            std::printf("projection FAILED: get_block_reward returned false\n");
            return 1;
        }

        std::printf("%-12s %-9s %-20s %s\n",
                    "height", "years", "reward at height", "emitted supply before it");
        std::printf("%-12s %-9s %-20s %s\n",
                    "------", "-----", "----------------", "------------------------");
        for (size_t i = 0; i < p.milestones.size(); ++i) {
            const uint64_t h = p.milestones[i].first;
            char yr[32];
            std::snprintf(yr, sizeof(yr), "%.4f", (double)h / (double)BLOCKS_PER_YEAR);
            std::printf("%-12llu %-9s %-20s %s\n",
                        (unsigned long long)h, yr,
                        fmt_atomic(p.rewards_at[i].second, decimals).c_str(),
                        fmt_atomic(p.milestones[i].second, decimals).c_str());
        }

        std::printf("\ntail-start height                   = %llu  (%.4f years)\n",
                    (unsigned long long)p.tail_start_height,
                    (double)p.tail_start_height / (double)BLOCKS_PER_YEAR);
        std::printf("emitted supply at tail start        = %s MEEP\n",
                    fmt_atomic(p.supply_at_tail_start, decimals).c_str());
        std::printf("height crossing 25,000,000 MEEP     = %llu  (%.4f years)\n",
                    (unsigned long long)p.cross_25m_height,
                    (double)p.cross_25m_height / (double)BLOCKS_PER_YEAR);
        std::printf("emitted supply at that height       = %s MEEP\n",
                    fmt_atomic(p.supply_at_25m, decimals).c_str());

        const uint64_t annual_tail = APPROVED_TAIL_PER_BLOCK * BLOCKS_PER_YEAR;
        std::printf("annual tail issuance                = %s MEEP/year\n",
                    fmt_atomic(annual_tail, decimals).c_str());
        std::printf("burned genesis reward               = %s MEEP  (emitted, NOT circulating)\n",
                    fmt_atomic(genesis_reward, decimals).c_str());
        std::printf("\nMeepCoin is NOT hard-capped: approximately 25 million MEEP of main emission,\n");
        std::printf("followed by permanent tail emission of %s MEEP per block.\n",
                    fmt_atomic(tail_per_block, decimals).c_str());
    }

    std::printf("\n=== RESULT: %s ===\n", g_fail == 0
                ? "compiled economics MATCH the approved values"
                : "compiled economics DIFFER from the approved values");
    return g_fail == 0 ? 0 : 1;
}
