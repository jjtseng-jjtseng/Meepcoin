// Strict TMTO attacker for MeepHash-W v2 (final confirmation round).
//
// Design requirements (pre-registered confirmation):
//  * HARD TOTAL-MEMORY BUDGET: every byte the attacker uses is counted — retained values, presence
//    bitmaps, cache metadata (keys/counters/LRU links), index arrays, the iterative traversal stack,
//    and reconstruction buffers. Budget is enforced by CONSTRUCTION (capacities sized so the sum of
//    all arrays <= budget), not by hoping temporaries stay small.
//  * ITERATIVE reconstruction (explicit stack), not recursion — bounded, no per-read allocation.
//  * Cache PERSISTS ACROSS NONCES by default (cross-hash caching), with LRU / LFU / static policies.
//  * All buffers preallocated once; the read path performs zero allocations.
//
// Memory accounting (bytes), all explicitly summed in total_bytes():
//    values[cap]        : 8 * cap        (cached/retained dataset words)
//    tags[cap]          : 4 * cap        (which dataset index each slot holds; 0xFFFFFFFF = empty)
//    meta[cap]          : 4 * cap        (LRU clock / LFU counter)
//    stack[STACK_CAP]   : sizeof(Frame) * STACK_CAP (iterative traversal frames)
//  The full backend's comparable total = 8 * count (the dataset array) — the honest denominator.
//
// LOOKUP STRUCTURE: a SET-ASSOCIATIVE cache (direct index -> set, tag compare within the set). This
// is what a competent attacker builds: NO per-dataset-word index array (an `index -> slot` map would
// itself cost 4*count = 50% of the whole budget at 32 MiB, which is why the naive design is not the
// strongest attacker). Sets are power-of-two; WAYS-way associative.
#ifndef MEEPOW_TMTO_STRICT_HPP
#define MEEPOW_TMTO_STRICT_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include "dataset_v2.hpp"

namespace meepow {

enum StrictPolicy {
    SP_STATIC,      // fixed retained set, never replaced (stride/random/adversarial placement)
    SP_LRU,         // cache retained words, evict least-recently-used (persists across nonces)
    SP_LFU,         // evict least-frequently-used
    SP_STATIC_LRU,  // hybrid: fraction of budget static (trained hot set) + rest LRU
};

constexpr uint32_t STRICT_EMPTY = 0xFFFFFFFFu;

struct StrictAttacker {
    // --- consensus dataset params (attacker knows these; the 32-byte epoch key is free) ---
    int nparents = 4;
    uint64_t seedconst = 0;
    size_t count = 0;               // dataset words
    const uint64_t* truth = nullptr;  // ONLY used to seed retained slots + verify; never read on miss

    // --- attacker memory (all counted): set-associative cache, no per-word index array ---
    static constexpr size_t WAYS = 8;
    size_t cap = 0;                 // total slots (= sets * WAYS)
    size_t sets = 0;                // power of two
    size_t set_mask = 0;
    std::vector<uint64_t> values;   // 8*cap
    std::vector<uint32_t> tags;     // 4*cap  (dataset index held, or STRICT_EMPTY)
    std::vector<uint32_t> meta;     // 4*cap  (LRU clock or LFU count; 0xFFFFFFFF = pinned)
    size_t pinned_ways = 0;         // first `pinned_ways` ways per set are pinned (static retention)
    StrictPolicy policy = SP_LRU;
    uint32_t clock = 0;

    // iterative traversal stack (preallocated; no per-read allocation)
    struct Frame { uint32_t idx; uint32_t stage; uint32_t pad; uint64_t h, d1, d2, d3, acc; };
    std::vector<Frame> stack;
    size_t stack_cap = 0;

    // --- metrics ---
    uint64_t reads = 0, hits = 0, misses = 0, ops = 0, evictions = 0;
    uint64_t max_stack_depth = 0;

    size_t total_bytes() const {
        return values.size() * 8 + tags.size() * 4 + meta.size() * 4 + stack_cap * sizeof(Frame);
    }
    size_t persistent_bytes() const { return values.size() * 8 + tags.size() * 4 + meta.size() * 4; }
    size_t temp_bytes() const { return stack_cap * sizeof(Frame); }
    // Fraction of the dataset the attacker can actually hold (cache slots / dataset words).
    double retained_fraction() const { return count ? (double)cap / (double)count : 0.0; }
};

// Size the attacker so TOTAL memory <= budget_bytes: cap slots at (8+4+4) B each, plus the
// traversal stack. Sets = cap / WAYS rounded down to a power of two.
inline void strict_init(StrictAttacker& a, const std::vector<uint64_t>& fullds, int nparents,
                        size_t budget_bytes, StrictPolicy policy, size_t stack_cap = 4096) {
    a.nparents = nparents;
    a.count = fullds.size();
    a.truth = fullds.data();
    a.seedconst = fullds[0];
    a.policy = policy;
    a.stack_cap = stack_cap;
    a.stack.resize(stack_cap);
    size_t fixed = stack_cap * sizeof(StrictAttacker::Frame);
    size_t per_slot = 8 + 4 + 4;
    size_t slots = (budget_bytes > fixed) ? (budget_bytes - fixed) / per_slot : 0;
    if (slots > a.count) slots = a.count;
    size_t sets = slots / StrictAttacker::WAYS;
    size_t p2 = 1; while (p2 * 2 <= sets) p2 *= 2;
    a.sets = p2 ? p2 : 1;
    a.set_mask = a.sets - 1;
    a.cap = a.sets * StrictAttacker::WAYS;
    a.values.assign(a.cap, 0);
    a.tags.assign(a.cap, STRICT_EMPTY);
    a.meta.assign(a.cap, 0);
    a.clock = 0; a.pinned_ways = 0;
    a.reads = a.hits = a.misses = a.ops = a.evictions = a.max_stack_depth = 0;
}

// Pin indices into the first ways of their sets (trained/placement retention, never evicted).
inline void strict_pin(StrictAttacker& a, const std::vector<uint32_t>& idxs, size_t pinned_ways) {
    a.pinned_ways = pinned_ways < StrictAttacker::WAYS ? pinned_ways : StrictAttacker::WAYS - 1;
    std::vector<uint8_t> used(a.sets, 0);
    for (uint32_t idx : idxs) {
        size_t set = (idx ^ (idx >> 11)) & a.set_mask;
        if (used[set] >= a.pinned_ways) continue;
        size_t s = set * StrictAttacker::WAYS + used[set];
        a.values[s] = a.truth[idx];
        a.tags[s] = idx;
        a.meta[s] = 0xFFFFFFFFu;  // pinned
        used[set]++;
    }
}

inline bool strict_lookup(StrictAttacker& a, uint32_t idx, uint64_t& out) {
    size_t set = (idx ^ (idx >> 11)) & a.set_mask;
    size_t base = set * StrictAttacker::WAYS;
    for (size_t w = 0; w < StrictAttacker::WAYS; ++w) {
        if (a.tags[base + w] == idx) {
            out = a.values[base + w];
            uint32_t& m = a.meta[base + w];
            if (m != 0xFFFFFFFFu) { if (a.policy == SP_LFU) { if (m < 0xFFFFFFFEu) m++; } else m = ++a.clock; }
            return true;
        }
    }
    return false;
}

inline void strict_insert(StrictAttacker& a, uint32_t idx, uint64_t val) {
    if (a.policy == SP_STATIC) return;  // pure static retention: never caches recomputed values
    size_t set = (idx ^ (idx >> 11)) & a.set_mask;
    size_t base = set * StrictAttacker::WAYS;
    size_t victim = SIZE_MAX; uint32_t bestm = 0xFFFFFFFFu;
    for (size_t w = a.pinned_ways; w < StrictAttacker::WAYS; ++w) {
        size_t s = base + w;
        if (a.tags[s] == STRICT_EMPTY) { victim = s; break; }
        if (a.meta[s] != 0xFFFFFFFFu && a.meta[s] <= bestm) { bestm = a.meta[s]; victim = s; }
    }
    if (victim == SIZE_MAX) return;
    if (a.tags[victim] != STRICT_EMPTY) a.evictions++;
    a.values[victim] = val;
    a.tags[victim] = idx;
    a.meta[victim] = (a.policy == SP_LFU) ? 1u : ++a.clock;
}

// ITERATIVE reconstruction of dataset word `want` using only cached/retained values (no recursion,
// no allocation). Mirrors v2_word()'s parent structure exactly.
uint64_t strict_read(void* ctx, uint64_t index);

inline uint64_t strict_reconstruct(StrictAttacker& a, uint32_t want) {
    size_t sp = 0;
    a.stack[sp].idx = want; a.stack[sp].stage = 0; sp = 1;
    uint64_t ret = 0;
    while (sp) {
        if (sp > a.max_stack_depth) a.max_stack_depth = sp;
        StrictAttacker::Frame& f = a.stack[sp - 1];
        uint32_t w = f.idx;
        // seed region is always available (regenerable from the epoch key at negligible cost)
        if (w < V2_SEED_WORDS) { ret = a.truth[w]; --sp; continue; }
        uint64_t cached;
        if (f.stage == 0 && strict_lookup(a, w, cached)) { ret = cached; --sp; continue; }
        switch (f.stage) {
            case 0: {
                f.h = v2_splitmix((uint64_t)w ^ a.seedconst);
                uint32_t p1 = (uint32_t)(f.h % (uint64_t)w);
                f.stage = 1;
                if (sp >= a.stack_cap) { ret = 0; --sp; break; }  // depth guard (counted memory)
                a.stack[sp].idx = p1; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 1: {
                f.d1 = ret;
                f.acc = v2_mix(f.d1, f.h, (uint64_t)w); a.ops++;
                if (a.nparents < 2) { ret = f.acc; strict_insert(a, w, ret); --sp; break; }
                uint32_t p2 = (uint32_t)((f.d1 ^ (f.h >> 13)) % (uint64_t)w);
                f.stage = 2;
                if (sp >= a.stack_cap) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p2; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 2: {
                f.d2 = ret;
                f.acc = v2_mix(f.acc, f.d2, (uint64_t)w ^ rotl64(f.d1, 32)); a.ops++;
                if (a.nparents < 3) { ret = f.acc; strict_insert(a, w, ret); --sp; break; }
                uint32_t p3 = (uint32_t)((f.d1 ^ f.d2 ^ (f.h >> 29)) % (uint64_t)w);
                f.stage = 3;
                if (sp >= a.stack_cap) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p3; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 3: {
                f.d3 = ret;
                f.acc = v2_mix(f.acc, f.d3, (uint64_t)w ^ rotl64(f.d2, 17)); a.ops++;
                if (a.nparents < 4) { ret = f.acc; strict_insert(a, w, ret); --sp; break; }
                uint32_t p4 = (uint32_t)((f.d2 ^ f.d3 ^ (f.h >> 7)) % (uint64_t)w);
                f.stage = 4;
                if (sp >= a.stack_cap) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p4; a.stack[sp].stage = 0; ++sp;
                break;
            }
            default: {
                uint64_t d4 = ret;
                uint64_t val = v2_mix(f.acc, d4, (uint64_t)w ^ rotl64(f.d3, 41)); a.ops++;
                ret = val;
                strict_insert(a, w, val);
                --sp;
                break;
            }
        }
    }
    return ret;
}

inline uint64_t strict_read(void* ctx, uint64_t index) {
    StrictAttacker& a = *(StrictAttacker*)ctx;
    a.reads++;
    uint64_t v;
    if (index < V2_SEED_WORDS) return a.truth[index];
    if (strict_lookup(a, (uint32_t)index, v)) { a.hits++; return v; }
    a.misses++;
    return strict_reconstruct(a, (uint32_t)index);
}

}  // namespace meepow

#endif  // MEEPOW_TMTO_STRICT_HPP
