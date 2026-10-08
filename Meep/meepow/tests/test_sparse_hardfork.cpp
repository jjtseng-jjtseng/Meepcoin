/*
 * Unit tests for the SPARSE hard-fork version lookup.
 *
 * MeepCoin patches Monero's check_block_hard_fork_version(), which indexed the fork table BY
 * VERSION (wallet_hard_forks[hf_version - 1]) and therefore assumed a dense 1..N schedule. With
 * MeepCoin's single {version 16, height 0} entry that made the wallet declare itself outdated on
 * every block and silently refuse to scan.
 *
 * The patched logic is reproduced here EXACTLY and tested directly, because the wallet-level
 * behaviour is expensive to exercise and easy to get wrong at the boundaries. Both the MeepCoin
 * sparse schedule and a Monero-style dense schedule are tested: the replacement must give identical
 * answers on a dense table, or it would be a regression for anyone reusing this code.
 *
 * Build/run: part of meepow-unit (doctest).
 */
#include <cstdint>
#include <ctime>
#include <cstddef>
#include <vector>

#include "doctest.h"

namespace {

struct hardfork_t {
    uint8_t version;
    uint64_t height;
    uint8_t threshold;
    time_t time;
};

// ---- the patched implementation, verbatim in behaviour -----------------------------------------
void check_block_hard_fork_version(const hardfork_t* forks, size_t n, uint8_t hf_version,
                                   uint64_t height, bool& wallet_is_outdated,
                                   bool& daemon_is_outdated) {
    uint8_t max_known_version = 0;
    for (size_t i = 0; i < n; ++i)
        if (forks[i].version > max_known_version) max_known_version = forks[i].version;

    wallet_is_outdated = hf_version > max_known_version;
    if (wallet_is_outdated) return;

    uint8_t expected_version = 0;
    for (size_t i = 0; i < n; ++i)
        if (forks[i].height <= height && forks[i].version > expected_version)
            expected_version = forks[i].version;

    daemon_is_outdated = hf_version != expected_version;
}

// ---- the ORIGINAL upstream implementation, for the dense-table equivalence check ----------------
void check_block_hard_fork_version_upstream(const hardfork_t* forks, size_t n, uint8_t hf_version,
                                            uint64_t height, bool& wallet_is_outdated,
                                            bool& daemon_is_outdated) {
    wallet_is_outdated = static_cast<size_t>(hf_version) > n;
    if (wallet_is_outdated) return;
    uint64_t start_height = hf_version == 1 ? 0 : forks[hf_version - 1].height;
    uint64_t end_height = static_cast<size_t>(hf_version) + 1 > n
                              ? UINT64_MAX
                              : forks[hf_version].height;
    daemon_is_outdated = height < start_height || height >= end_height;
}

// MeepCoin: one entry, version 16 active from genesis.
const hardfork_t MEEP[] = {{16, 0, 0, 1785283200}};

// A Monero-style dense schedule (versions 1..16 at increasing heights).
const hardfork_t DENSE[] = {
    {1, 0, 0, 0},     {2, 10, 0, 0},   {3, 20, 0, 0},   {4, 30, 0, 0},
    {5, 40, 0, 0},    {6, 50, 0, 0},   {7, 60, 0, 0},   {8, 70, 0, 0},
    {9, 80, 0, 0},    {10, 90, 0, 0},  {11, 100, 0, 0}, {12, 110, 0, 0},
    {13, 120, 0, 0},  {14, 130, 0, 0}, {15, 140, 0, 0}, {16, 150, 0, 0},
};

bool accepted(const hardfork_t* f, size_t n, uint8_t v, uint64_t h) {
    bool wo = false, dio = false;
    check_block_hard_fork_version(f, n, v, h, wo, dio);
    return !wo && !dio;
}

}  // namespace

TEST_CASE("sparse schedule accepts v16 at every required height") {
    // The heights the checkpoint calls out explicitly.
    for (uint64_t h : {0ull, 1ull, 15ull, 16ull, 63ull, 64ull, 2048ull, 2113ull}) {
        CAPTURE(h);
        CHECK(accepted(MEEP, 1, 16, h));
    }
}

TEST_CASE("sparse schedule rejects wrong versions at legitimate heights") {
    // A daemon reporting anything other than 16 on a v16 chain must be rejected.
    for (uint8_t v : {1, 2, 12, 15}) {
        CAPTURE(v);
        CHECK_FALSE(accepted(MEEP, 1, v, 0));
        CHECK_FALSE(accepted(MEEP, 1, v, 2113));
    }
}

TEST_CASE("sparse schedule flags the WALLET as outdated for unknown future versions") {
    bool wo = false, dio = false;
    check_block_hard_fork_version(MEEP, 1, 17, 100, wo, dio);
    CHECK(wo);          // version beyond anything the wallet knows
    CHECK_FALSE(dio);   // and it must not blame the daemon instead
}

TEST_CASE("sparse schedule flags the DAEMON as outdated for a stale version") {
    bool wo = false, dio = false;
    check_block_hard_fork_version(MEEP, 1, 15, 100, wo, dio);
    CHECK_FALSE(wo);
    CHECK(dio);         // 15 is known but wrong for this chain
}

TEST_CASE("upstream implementation would REJECT the MeepCoin schedule (regression evidence)") {
    // This is the defect the patch fixes: with a 1-entry table, 16 > 1 so the wallet declares
    // itself outdated and never scans. Kept as a test so the reason for the patch is not lost.
    bool wo = false, dio = false;
    check_block_hard_fork_version_upstream(MEEP, 1, 16, 0, wo, dio);
    CHECK(wo);
}

TEST_CASE("patched and upstream agree on a DENSE schedule") {
    // The replacement must not change behaviour for a Monero-style table.
    const size_t n = sizeof(DENSE) / sizeof(DENSE[0]);
    for (uint8_t v = 1; v <= 16; ++v) {
        for (uint64_t h : {0ull, 5ull, 10ull, 55ull, 95ull, 149ull, 150ull, 151ull, 5000ull}) {
            bool wo_a = false, dio_a = false, wo_b = false, dio_b = false;
            check_block_hard_fork_version(DENSE, n, v, h, wo_a, dio_a);
            check_block_hard_fork_version_upstream(DENSE, n, v, h, wo_b, dio_b);
            CAPTURE(v); CAPTURE(h);
            CHECK(wo_a == wo_b);
            CHECK((!wo_a ? (dio_a == dio_b) : true));
        }
    }
}

TEST_CASE("dense schedule still selects the right version per height") {
    const size_t n = sizeof(DENSE) / sizeof(DENSE[0]);
    CHECK(accepted(DENSE, n, 1, 0));
    CHECK(accepted(DENSE, n, 1, 9));
    CHECK(accepted(DENSE, n, 2, 10));
    CHECK(accepted(DENSE, n, 16, 150));
    CHECK(accepted(DENSE, n, 16, 100000));
    CHECK_FALSE(accepted(DENSE, n, 16, 149));   // v16 not active yet
    CHECK_FALSE(accepted(DENSE, n, 1, 10));     // v1 no longer active
}

TEST_CASE("an empty schedule accepts nothing") {
    bool wo = false, dio = false;
    check_block_hard_fork_version(nullptr, 0, 16, 0, wo, dio);
    CHECK(wo);   // max known version is 0, so any version is beyond the wallet
}
