// libFuzzer target: difficulty/target conversion and comparison invariants (spec §10).
#include <cstdint>
#include <cstddef>
#include <cstring>

#include "endian.hpp"
#include "target.hpp"

using namespace meepow;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;
    uint64_t difficulty = load_u64_le(data);
    uint8_t target[32];
    bool ok = difficulty_to_target(difficulty, target);
    if (difficulty == 0) {
        if (ok) __builtin_trap();  // zero must be rejected
        return 0;
    }
    if (!ok) __builtin_trap();

    // A hash of all zeros always meets any valid target; all-ones only meets difficulty 1.
    uint8_t zero[32] = {0}, ones[32];
    std::memset(ones, 0xff, 32);
    if (!hash_meets_target(zero, target)) __builtin_trap();
    if (difficulty > 1 && hash_meets_target(ones, target)) __builtin_trap();
    // Target meets itself (equality passes).
    if (!hash_meets_target(target, target)) __builtin_trap();

    // An arbitrary hash from the input must not crash the comparison.
    uint8_t h[32];
    for (int i = 0; i < 32; ++i) h[i] = data[(8 + i) % size];
    (void)hash_meets_target(h, target);
    return 0;
}
