// meepcoin-fee-fallback-test — the wallet's dynamic-fee RPC fallback at 11 decimals.
//
// FEE_PER_BYTE is what wallet2 falls back to when the daemon's dynamic-fee RPC fails. It is used at
// three sites, all wallet-side (wallet2.cpp:8573, :8611, :8616); it appears nowhere in consensus.
//
// The point being pinned down: its meaning is a SAFETY MARGIN ABOVE THE NETWORK MINIMUM, not an
// amount of coin. The v16 minimum is reward-derived, so rescaling this constant when the decimal
// point changes moves it independently of the thing it has to exceed. A plausible-looking "one
// fewer decimal, so divide by ten" gives 30,000 -- below MeepCoin's ~37,750/byte minimum, and every
// transaction priced with it would be rejected for insufficient fee.
//
// This binary checks the compiled value and its derivation. The live half -- forcing the wallet's
// RPC to actually fail and confirming the fallback is entered -- is node/fee_fallback_live_test.py.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <cstdint>
#include <cstdio>
#include <string>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;

static int g_pass = 0, g_fail = 0;

static void chk(bool cond, const std::string &label) {
    if (cond) { ++g_pass; std::printf("  [PASS] %s\n", label.c_str()); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", label.c_str()); }
}

// Reproduce Blockchain::get_dynamic_base_fee exactly (HF_VERSION_2021_SCALING branch):
//   lo = reward * ref_weight; lo /= median; lo /= median; lo -= lo/20
static uint64_t reference_fee_per_byte(uint64_t reward, uint64_t median) {
    uint64_t lo = reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT;
    lo /= median;
    lo /= median;
    lo -= lo / 20;
    return lo == 0 ? 1 : lo;
}

// ---------------------------------------------------------------------------------------------
// Compile-time: the derivation must be intact, and a naive coin-denominated rescale must be
// provably unsafe. If either changes, the BUILD fails rather than a test run.
// ---------------------------------------------------------------------------------------------
static_assert(MEEPCOIN_FEE_FALLBACK_MARGIN == 15,
              "MeepCoin: the fee fallback margin is Monero's effective 15x; state it, do not drift");
static_assert(FEE_PER_BYTE == (uint64_t)(MEEPCOIN_FEE_REFERENCE_PER_BYTE * 15),
              "MeepCoin: FEE_PER_BYTE must be the reward-derived reference times the margin");
static_assert(FEE_PER_BYTE > MEEPCOIN_FEE_REFERENCE_PER_BYTE,
              "MeepCoin: the fallback must exceed the network minimum, or every transaction priced "
              "with it is rejected for insufficient fee");
// The value a naive decimal rescale would have produced, shown to be below the minimum.
static_assert(30000ULL < MEEPCOIN_FEE_REFERENCE_PER_BYTE,
              "MeepCoin: 30,000/byte is below the reward-derived minimum -- if this ever stops "
              "being true the audit reasoning needs revisiting");

int main() {
    std::printf("MeepCoin wallet fee-fallback test (compiled constants)\n");
    std::printf("=====================================================\n\n");

    set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

    const uint64_t initial_reward = MONEY_SUPPLY >> MEEPCOIN_EFFECTIVE_EMISSION_SHIFT;
    const uint64_t median = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
    const uint64_t ref = reference_fee_per_byte(initial_reward, median);

    std::printf("1. Inputs\n");
    std::printf("   COIN                        = %llu\n", (unsigned long long)COIN);
    std::printf("   decimals                    = %d\n", CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    std::printf("   effective emission shift    = %d\n", MEEPCOIN_EFFECTIVE_EMISSION_SHIFT);
    std::printf("   initial block reward        = %llu atomic = %s MEEP\n",
                (unsigned long long)initial_reward, print_money(initial_reward).c_str());
    std::printf("   min_block_weight (v16)      = %llu bytes\n", (unsigned long long)median);
    std::printf("   ref transaction weight      = %llu\n",
                (unsigned long long)DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT);
    std::printf("\n");

    std::printf("2. The reward-derived network minimum\n");
    std::printf("   reference (recomputed here) = %llu atomic/byte\n", (unsigned long long)ref);
    std::printf("   MEEPCOIN_FEE_REFERENCE_PER_BYTE = %llu atomic/byte\n",
                (unsigned long long)MEEPCOIN_FEE_REFERENCE_PER_BYTE);
    chk(ref == MEEPCOIN_FEE_REFERENCE_PER_BYTE,
        "the config macro reproduces get_dynamic_base_fee's arithmetic exactly");
    std::printf("\n");

    std::printf("3. The fallback\n");
    std::printf("   FEE_PER_BYTE                = %llu atomic/byte = %s MEEP/byte\n",
                (unsigned long long)FEE_PER_BYTE, print_money(FEE_PER_BYTE).c_str());
    std::printf("   margin over the minimum     = %.2fx\n", (double)FEE_PER_BYTE / (double)ref);
    chk(FEE_PER_BYTE == ref * MEEPCOIN_FEE_FALLBACK_MARGIN,
        "FEE_PER_BYTE == reference * margin");
    chk(FEE_PER_BYTE > ref, "the fallback EXCEEDS the reward-derived minimum");
    chk(MEEPCOIN_FEE_FALLBACK_MARGIN == 15,
        "the margin is 15, matching Monero's effective 15.79x");
    std::printf("\n");

    std::printf("4. The naive coin-denominated rescale would have been unsafe\n");
    // Monero: FEE_PER_BYTE 300,000 at 12 decimals = 3e-7 XMR/byte. Preserving that coin-denominated
    // value at 11 decimals gives 30,000 -- which is the value this test exists to rule out.
    const uint64_t naive = 30000;
    std::printf("   naive value (3e-7 coin/byte at 11 dp) = %llu atomic/byte\n",
                (unsigned long long)naive);
    std::printf("   the reward-derived minimum            = %llu atomic/byte\n",
                (unsigned long long)ref);
    chk(naive < ref,
        "30,000/byte is BELOW the minimum -- transactions priced with it would be rejected");
    chk(FEE_PER_BYTE > naive * 10,
        "the derived fallback is more than 10x the naive value, not a tenth of the old one");
    std::printf("\n");

    std::printf("5. Displayed MEEP value is correct at 11 decimals\n");
    // 566250 atomic at 11 decimals = 0.00000566250 MEEP per byte.
    const std::string shown = print_money(FEE_PER_BYTE);
    std::printf("   print_money(FEE_PER_BYTE)   = %s MEEP\n", shown.c_str());
    chk(shown.find('.') != std::string::npos, "the displayed value has a decimal point");
    chk(shown.size() == shown.find('.') + 1 + CRYPTONOTE_DISPLAY_DECIMAL_POINT,
        "the displayed value has exactly 11 fractional digits");
    {
        uint64_t back = 0;
        chk(parse_amount(back, shown) && back == FEE_PER_BYTE,
            "the displayed value parses back to the same atomic amount");
    }
    // A realistic transaction: ring-16 Bulletproof+ transfers on this chain run ~2300 bytes.
    {
        const uint64_t tx_bytes = 2300;
        const uint64_t fee_fallback = FEE_PER_BYTE * tx_bytes;
        const uint64_t fee_dynamic = ref * tx_bytes;
        std::printf("   a %llu-byte transaction:\n", (unsigned long long)tx_bytes);
        std::printf("     at the fallback           = %s MEEP\n", print_money(fee_fallback).c_str());
        std::printf("     at the dynamic minimum    = %s MEEP\n", print_money(fee_dynamic).c_str());
        chk(fee_fallback > fee_dynamic, "the fallback over-pays rather than under-pays");
        chk(fee_fallback < COIN, "the fallback fee for a normal transaction is still under 1 MEEP");
    }
    std::printf("\n");

    std::printf("6. Scale awareness: the fallback tracks the minimum, not the decimal point\n");
    // Re-derive at a hypothetical 12 decimals with the same 25M coin supply: MONEY_SUPPLY would be
    // 10x larger, so the reward and the minimum both scale by 10 -- and so does the fallback.
    {
        const uint64_t supply_12dp = 25000000ULL * 1000000000000ULL;
        const uint64_t reward_12dp = supply_12dp >> MEEPCOIN_EFFECTIVE_EMISSION_SHIFT;
        const uint64_t ref_12dp = reference_fee_per_byte(reward_12dp, median);
        const uint64_t fallback_12dp = ref_12dp * MEEPCOIN_FEE_FALLBACK_MARGIN;
        std::printf("   hypothetical 12 dp: minimum %llu, fallback %llu\n",
                    (unsigned long long)ref_12dp, (unsigned long long)fallback_12dp);
        std::printf("   actual        11 dp: minimum %llu, fallback %llu\n",
                    (unsigned long long)ref, (unsigned long long)FEE_PER_BYTE);
        chk(fallback_12dp > ref_12dp,
            "at 12 decimals the derived fallback would STILL exceed the minimum");
        // The ratio is what must be invariant, not the absolute value.
        const double r11 = (double)FEE_PER_BYTE / (double)ref;
        const double r12 = (double)fallback_12dp / (double)ref_12dp;
        chk(r11 > 14.9 && r11 < 15.1 && r12 > 14.9 && r12 < 15.1,
            "the margin is invariant across decimal choices -- that is the property that matters");
    }

    std::printf("\n=====================================================\n");
    std::printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("FEE FALLBACK TEST: %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
