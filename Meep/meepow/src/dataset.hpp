// Epoch dataset generation, constructions A and B (spec §4). Header-only so the reference
// library and the TMTO adversarial track share one definition of the construction.
#ifndef MEEPOW_DATASET_HPP
#define MEEPOW_DATASET_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include "blake3_xof.hpp"
#include "endian.hpp"
#include "params.hpp"

namespace meepow {

// Construction B mixing function (spec §4.2).
inline uint64_t mixB(uint64_t a, uint64_t b, uint64_t w) {
    uint64_t x = a + b;
    x ^= rotl64(x, 32);
    x = x * (b | 1ULL);
    x ^= w;
    x = rotl64(x, 23);
    x = x + a;
    return x;
}

// Fill `words[0..word_count)` for construction A: independent 64 KiB chunks (spec §4.1).
inline void dataset_fill_A(uint64_t* words, size_t word_count, const uint8_t epoch_key[32],
                           uint8_t param_id) {
    std::vector<uint8_t> tmp(CHUNK_WORDS * 8);
    size_t num_chunks = word_count / CHUNK_WORDS;
    for (size_t i = 0; i < num_chunks; ++i) {
        uint8_t idx_le[8];
        store_u64_le(idx_le, (uint64_t)i);
        Field fields[2] = {{idx_le, 8}, {epoch_key, 32}};  // header LE64(i), material epochKey
        meep_xof(CTX_DATASET, param_id, fields, 2, tmp.data(), tmp.size());
        uint64_t* base = words + i * CHUNK_WORDS;
        for (size_t w = 0; w < CHUNK_WORDS; ++w) base[w] = load_u64_le(tmp.data() + w * 8);
    }
}

// Fill `words[0..word_count)` for construction B: sequential dependent (spec §4.2).
inline void dataset_fill_B(uint64_t* words, size_t word_count, const uint8_t epoch_key[32],
                           uint8_t param_id) {
    std::vector<uint8_t> tmp(SEED_WORDS * 8);
    uint8_t idx_le[8];
    store_u64_le(idx_le, 0);
    Field fields[2] = {{idx_le, 8}, {epoch_key, 32}};
    meep_xof(CTX_DATASET, param_id, fields, 2, tmp.data(), tmp.size());
    for (size_t w = 0; w < SEED_WORDS; ++w) words[w] = load_u64_le(tmp.data() + w * 8);
    for (size_t w = SEED_WORDS; w < word_count; ++w) {
        uint64_t prev = words[w - 1];
        uint64_t back = prev % (uint64_t)w;  // data-dependent backward reference
        words[w] = mixB(prev, words[back], (uint64_t)w);
    }
}

}  // namespace meepow

#endif  // MEEPOW_DATASET_HPP
