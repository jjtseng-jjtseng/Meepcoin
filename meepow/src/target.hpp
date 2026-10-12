// Difficulty/target 256-bit math (spec §10). Targets are 32-byte little-endian.
#ifndef MEEPOW_TARGET_HPP
#define MEEPOW_TARGET_HPP

#include <cstdint>
#include <cstring>

#include "endian.hpp"

namespace meepow {

// target(difficulty) = floor((2^256 - 1) / difficulty), difficulty >= 1. Returns false if
// difficulty == 0 (invalid, spec §10). Output is 32-byte little-endian.
//
// Uses __uint128_t for the 256/64 division. This helper is not on the per-hash consensus path;
// it runs on gcc/clang/Emscripten (all current targets), and is differentially tested
// native-vs-Wasm. An MSVC-portable long-division fallback is a Phase-3 item (MSVC deferred).
inline bool difficulty_to_target(uint64_t difficulty, uint8_t out_target[32]) {
    if (difficulty == 0) return false;
    // Numerator 2^256 - 1 as four u64 limbs (all ones), limb[3] most significant.
    uint64_t num[4] = {~0ULL, ~0ULL, ~0ULL, ~0ULL};
    uint64_t q[4];
    unsigned __int128 rem = 0;
    for (int i = 3; i >= 0; --i) {
        unsigned __int128 cur = (rem << 64) | (unsigned __int128)num[i];
        q[i] = (uint64_t)(cur / difficulty);
        rem = cur % difficulty;
    }
    for (int i = 0; i < 4; ++i) store_u64_le(out_target + i * 8, q[i]);  // little-endian
    return true;
}

// Returns true iff hash <= target, both interpreted as little-endian 256-bit integers.
inline bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32]) {
    // Compare from most-significant limb (offset 24) down to least (offset 0).
    for (int off = 24; off >= 0; off -= 8) {
        uint64_t h = load_u64_le(hash + off);
        uint64_t t = load_u64_le(target + off);
        if (h < t) return true;
        if (h > t) return false;
    }
    return true;  // exactly equal passes (spec §10)
}

}  // namespace meepow

#endif  // MEEPOW_TARGET_HPP
