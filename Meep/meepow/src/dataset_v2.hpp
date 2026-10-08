// MeepHash-W v2 epoch dataset constructions (algoVersion 2). Redesign to fix v1's TMTO failure:
// each word depends on MULTIPLE, widely-separated, DATA-DEPENDENT parents with NO adjacent (w-1)
// dependency, so retaining regularly-spaced words does not make missing words cheaply
// reconstructible from a neighbor. The SAME single-word function is used for generation (get =
// direct array) and for reconstruction (get = a storage backend) — no transcription drift.
#ifndef MEEPOW_DATASET_V2_HPP
#define MEEPOW_DATASET_V2_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include "blake3_xof.hpp"
#include "endian.hpp"

namespace meepow {

constexpr const char* CTX_DATASET_V2 = "MEEP/DATASET/v2";
constexpr size_t V2_SEED_WORDS = 8192;  // BLAKE3-seeded prefix (64 KiB), cheaply regenerable from
                                        // epochKey; an attacker keeps the 32-byte key for free.

inline uint64_t v2_splitmix(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
inline uint64_t v2_mix(uint64_t a, uint64_t b, uint64_t w) {
    uint64_t x = a + b;
    x ^= rotl64(x, 29);
    x = x * (b | 1ULL);
    x ^= w;
    x = rotl64(x, 17);
    return x + a;
}

// Compute word w's `nparents` data-dependent, widely-separated parents and combine (spec above).
// `get(idx)` fetches an earlier word (idx < w). `ops` counts mix operations (reconstruction cost).
// The first parent index derives from w alone (so it is locatable without any value); parents 2..N
// depend on fetched VALUES, so they are data-dependent and scattered.
template <class Get>
inline uint64_t v2_word(size_t w, uint64_t seedconst, int nparents, Get&& get, uint64_t& ops) {
    uint64_t h = v2_splitmix((uint64_t)w ^ seedconst);
    size_t p1 = (size_t)(h % (uint64_t)w);
    uint64_t d1 = get(p1);
    uint64_t val = v2_mix(d1, h, (uint64_t)w);
    ++ops;
    if (nparents >= 2) {
        size_t p2 = (size_t)((d1 ^ (h >> 13)) % (uint64_t)w);
        uint64_t d2 = get(p2);
        val = v2_mix(val, d2, (uint64_t)w ^ rotl64(d1, 32));
        ++ops;
        if (nparents >= 3) {
            size_t p3 = (size_t)((d1 ^ d2 ^ (h >> 29)) % (uint64_t)w);
            uint64_t d3 = get(p3);
            val = v2_mix(val, d3, (uint64_t)w ^ rotl64(d2, 17));
            ++ops;
            if (nparents >= 4) {
                size_t p4 = (size_t)((d2 ^ d3 ^ (h >> 7)) % (uint64_t)w);
                uint64_t d4 = get(p4);
                val = v2_mix(val, d4, (uint64_t)w ^ rotl64(d3, 41));
                ++ops;
            }
        }
    }
    return val;
}

// Fill the BLAKE3 seed region [0, V2_SEED_WORDS) from epochKey (domain-separated).
inline void v2_fill_seed(uint64_t* words, size_t count, const uint8_t epoch_key[32]) {
    std::vector<uint8_t> tmp(V2_SEED_WORDS * 8);
    uint8_t idx0[8];
    store_u64_le(idx0, 0);
    Field f[2] = {{idx0, 8}, {epoch_key, 32}};
    meep_xof(CTX_DATASET_V2, 0, f, 2, tmp.data(), tmp.size());
    size_t n = count < V2_SEED_WORDS ? count : V2_SEED_WORDS;
    for (size_t w = 0; w < n; ++w) words[w] = load_u64_le(tmp.data() + w * 8);
}

// Generate the full v2 dataset sequentially (get = direct access to already-filled words).
inline void v2_dataset_fill(uint64_t* words, size_t count, const uint8_t epoch_key[32],
                            int nparents) {
    v2_fill_seed(words, count, epoch_key);
    uint64_t seedconst = words[0];
    for (size_t w = V2_SEED_WORDS; w < count; ++w) {
        uint64_t ops = 0;
        words[w] = v2_word(w, seedconst, nparents, [&](size_t idx) { return words[idx]; }, ops);
    }
}

}  // namespace meepow

#endif  // MEEPOW_DATASET_V2_HPP
