// meepcoin-emission-probe — probe get_block_reward() around already_generated_coins == MONEY_SUPPLY.
//
// Why this exists: Monero sets MONEY_SUPPLY = 2^64 - 1, which already_generated_coins can never
// exceed, so `MONEY_SUPPLY - already_generated_coins` can never underflow. MeepCoin sets
// MONEY_SUPPLY = 2.5e18 atomic AND pays a permanent tail reward, so cumulative emission DOES
// eventually pass MONEY_SUPPLY. At that point the subtraction underflows and the base reward
// explodes instead of staying at the tail.
//
// This probe reports the reward at, just below, and just above that boundary. Every value at or
// above MONEY_SUPPLY must equal the tail reward exactly.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

using namespace cryptonote;

static std::string fmt_atomic(uint64_t v, unsigned decimals) {
    uint64_t div = 1;
    for (unsigned i = 0; i < decimals; ++i) div *= 10;
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%llu.%0*llu",
                  (unsigned long long)(v / div), (int)decimals, (unsigned long long)(v % div));
    return buf;
}

int main() {
    const unsigned decimals = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
    const int target_minutes = DIFFICULTY_TARGET_V2 / 60;
    const uint64_t tail = (uint64_t)FINAL_SUBSIDY_PER_MINUTE * target_minutes;
    const uint64_t M = MONEY_SUPPLY;

    std::printf("MeepCoin emission boundary probe\n");
    std::printf("================================\n\n");
    std::printf("MONEY_SUPPLY = %llu atomic (%s MEEP)\n", (unsigned long long)M,
                fmt_atomic(M, decimals).c_str());
    std::printf("tail reward  = %llu atomic (%s MEEP)\n\n", (unsigned long long)tail,
                fmt_atomic(tail, decimals).c_str());

    struct Case { const char *label; uint64_t already; bool must_be_tail; };
    std::vector<Case> cases;
    cases.push_back(Case{"MONEY_SUPPLY - 2*tail",   M - 2 * tail,     true});
    cases.push_back(Case{"MONEY_SUPPLY - tail",     M - tail,         true});
    cases.push_back(Case{"MONEY_SUPPLY - 1",        M - 1,            true});
    cases.push_back(Case{"MONEY_SUPPLY  (exact)",   M,                true});
    cases.push_back(Case{"MONEY_SUPPLY + 1",        M + 1,            true});
    cases.push_back(Case{"MONEY_SUPPLY + tail",     M + tail,         true});
    cases.push_back(Case{"MONEY_SUPPLY + 1 MEEP",   M + COIN,         true});
    cases.push_back(Case{"MONEY_SUPPLY + 1000 MEEP",M + 1000 * COIN,  true});

    int fail = 0;
    std::printf("%-26s %-22s %-22s %s\n", "already_generated_coins", "atomic", "MEEP", "verdict");
    std::printf("%-26s %-22s %-22s %s\n", "-----------------------", "------", "----", "-------");
    for (size_t i = 0; i < cases.size(); ++i) {
        uint64_t reward = 0;
        if (!get_block_reward(0, 0, cases[i].already, reward, 16)) {
            std::printf("%-26s get_block_reward returned FALSE\n", cases[i].label);
            ++fail;
            continue;
        }
        const bool ok = !cases[i].must_be_tail || reward == tail;
        if (!ok) ++fail;
        std::printf("%-26s %-22llu %-22s %s\n", cases[i].label,
                    (unsigned long long)reward, fmt_atomic(reward, decimals).c_str(),
                    ok ? "OK" : "*** WRONG: expected the tail reward ***");
    }

    std::printf("\nRESULT: %d boundary case(s) wrong\n", fail);
    std::printf("EMISSION BOUNDARY: %s\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}
