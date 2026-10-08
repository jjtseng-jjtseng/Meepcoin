// MeepHash-W v2 — CORRECTED strict TMTO attacker: multiple cache representations, each sized to
// SATURATE its hard total-memory budget (target >= 99% utilization).
//
// Bug fixed vs tmto_strict.hpp: the set count was rounded DOWN to a power of two, discarding up to
// 49.3% of affordable capacity (a "50% budget" attacker used only 25.7% of memory / 12.5% of words).
// Here set indexing uses fastrange (multiply-shift), so ANY set count is allowed, and `ways` absorbs
// the remainder — no rounding waste.
//
// EXACT BYTE ACCOUNTING (every byte the attacker holds is charged):
//   seed region      : SEED_BYTES = V2_SEED_WORDS * 8                 (regenerable, but charged)
//   static values    : 8 * R_static                                   (packed, arithmetic address)
//   dynamic values   : 8 * cap_dyn
//   dynamic tags     : 4 * cap_dyn                                    (u32 dataset index)
//   dynamic meta     : meta_bytes_per_slot * cap_dyn                  (0, 1, or 4; or 1 bit/set)
//   set-LRU bitvec   : ceil(sets/8)                                   (REP_SA2 only)
//   traversal stack  : STACK_FRAMES * sizeof(Frame)
//   total_bytes()    = sum of the above (no other allocation on the read path)
// Denominator (unchanged, as pre-registered): the full backend's dataset array = 8 * D bytes.
#ifndef MEEPOW_TMTO_STRICT2_HPP
#define MEEPOW_TMTO_STRICT2_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "dataset_v2.hpp"

namespace meepow {

enum CacheRep : int {
    REP_SA8 = 0,     // 8-way set-assoc, u32 tag + u32 LRU/LFU clock       -> 16 B/word
    REP_DIRECT,      // direct-mapped, u32 tag, no replacement metadata    -> 12 B/word
    REP_SA2,         // 2-way set-assoc, u32 tag + 1 bit per set (LRU)     -> ~12.06 B/word
    REP_LFU8,        // 8-way, u32 tag + u8 frequency counter              -> 13 B/word
    REP_STATIC,      // arithmetic static subset, NO tags, NO metadata     -> 8 B/word
    REP_HYBRID,      // static subset (most of budget) + small tagged memo -> ~8.5 B/word blended
    REP_PREFIX,      // retain the LOWEST-index words (idx < R): parents are uniform in [0,w), so
                     // low indices are referenced far more during reconstruction -> 8 B/word
    REP_PREFIX_MEMO, // prefix retention + small tagged memo
};
inline const char* rep_name(CacheRep r) {
    switch (r) {
        case REP_SA8: return "8-way SA (u32 tag+meta)";
        case REP_DIRECT: return "direct-mapped (u32 tag)";
        case REP_SA2: return "2-way SA (tag+1bit/set)";
        case REP_LFU8: return "8-way LFU (tag+u8 ctr)";
        case REP_STATIC: return "static arith subset";
        case REP_HYBRID: return "hybrid static+memo";
        case REP_PREFIX: return "prefix retention (low idx)";
        case REP_PREFIX_MEMO: return "prefix + memo";
    }
    return "?";
}

constexpr uint32_t S2_EMPTY = 0xFFFFFFFFu;
constexpr size_t S2_STACK_FRAMES = 4096;
constexpr uint32_t S2_PERIOD_LOG = 12;             // static subset period = 4096 (power of two)
constexpr uint32_t S2_PERIOD = 1u << S2_PERIOD_LOG;

struct Attacker2 {
    struct Frame { uint32_t idx, stage, pad; uint64_t h, d1, d2, d3, acc; };

    CacheRep rep = REP_STATIC;
    int nparents = 4;
    uint64_t seedconst = 0;
    size_t D = 0;                       // dataset words
    const uint64_t* truth = nullptr;    // used ONLY to populate retained slots + verify

    // --- static (arithmetic-addressed) region ---
    //   periodic mode : retain idx iff (idx & (P-1)) < keep     (uniform coverage)
    //   prefix mode   : retain idx iff idx < prefix             (low indices; slot = idx)
    uint32_t keep = 0;                  // words retained per period (periodic mode)
    size_t prefix = 0;                  // words retained from index 0 (prefix mode)
    std::vector<uint64_t> svals;        // 8 * R_static (owned)
    // Shared retained region: when set, this attacker READS a retained set owned elsewhere (one
    // global cache shared by all concurrent hashes) instead of owning its own copy. Used by the
    // throughput harness so N in-flight nonces cannot each get a private full-size cache.
    const uint64_t* svals_shared = nullptr;
    const uint64_t* seed_shared = nullptr;

    // --- dynamic (tagged) cache: fastrange set index, `ways` per set ---
    size_t sets = 0, ways = 0, cap_dyn = 0;
    std::vector<uint64_t> dvals;
    std::vector<uint32_t> dtags;
    std::vector<uint32_t> dmeta32;      // REP_SA8
    std::vector<uint8_t> dmeta8;        // REP_LFU8
    std::vector<uint8_t> setbit;        // REP_SA2: 1 bit per set
    uint32_t clock = 0;

    // --- seed region (charged) ---
    std::vector<uint64_t> seedvals;

    // --- traversal stack (charged) ---
    std::vector<Frame> stack;

    // --- metrics ---
    uint64_t reads = 0, hits = 0, misses = 0, ops = 0, max_depth = 0;

    size_t static_bytes() const { return svals.size() * 8; }
    size_t dyn_bytes() const {
        return dvals.size() * 8 + dtags.size() * 4 + dmeta32.size() * 4 + dmeta8.size() + setbit.size();
    }
    size_t seed_bytes() const { return seedvals.size() * 8; }
    size_t stack_bytes() const { return stack.size() * sizeof(Frame); }
    size_t total_bytes() const { return static_bytes() + dyn_bytes() + seed_bytes() + stack_bytes(); }
    size_t words_held() const { return svals.size() + cap_dyn; }
    double meta_bytes_per_word() const {
        size_t w = words_held();
        return w ? (double)(total_bytes() - w * 8) / (double)w : 0.0;
    }
};

// fastrange: map a 32-bit hash to [0, n) without modulo or power-of-two restriction.
inline uint32_t s2_set_of(uint32_t idx, size_t n) {
    uint32_t h = idx * 2654435761u;
    return (uint32_t)(((uint64_t)h * (uint64_t)n) >> 32);
}
inline bool s2_static_has(const Attacker2& a, uint32_t idx) {
    if (a.prefix) return (size_t)idx < a.prefix;
    return a.keep && (idx & (S2_PERIOD - 1)) < a.keep;
}
inline size_t s2_static_slot(const Attacker2& a, uint32_t idx) {
    if (a.prefix) return (size_t)idx;
    return (size_t)(idx >> S2_PERIOD_LOG) * a.keep + (idx & (S2_PERIOD - 1));
}
// Read a retained word (shared region if present, else the owned vector).
inline uint64_t s2_sval(const Attacker2& a, size_t slot) {
    return a.svals_shared ? a.svals_shared[slot] : a.svals[slot];
}
inline uint64_t s2_seed(const Attacker2& a, uint32_t idx) {
    return a.seed_shared ? a.seed_shared[idx] : a.seedvals[idx];
}

// Size the attacker to saturate `budget` bytes for the chosen representation.
inline void a2_init(Attacker2& a, const std::vector<uint64_t>& ds, int nparents, size_t budget,
                    CacheRep rep, double hybrid_dyn_frac = 0.25) {
    a.rep = rep;
    a.nparents = nparents;
    a.D = ds.size();
    a.truth = ds.data();
    a.seedconst = ds[0];
    a.stack.assign(S2_STACK_FRAMES, Attacker2::Frame{});
    a.seedvals.assign(ds.begin(), ds.begin() + V2_SEED_WORDS);
    a.clock = 0;
    a.reads = a.hits = a.misses = a.ops = a.max_depth = 0;
    a.keep = 0; a.prefix = 0; a.svals.clear(); a.dvals.clear(); a.dtags.clear();
    a.dmeta32.clear(); a.dmeta8.clear(); a.setbit.clear();
    a.sets = a.ways = a.cap_dyn = 0;

    size_t fixed = a.seed_bytes() + a.stack_bytes();
    size_t avail = budget > fixed ? budget - fixed : 0;
    size_t blocks = a.D >> S2_PERIOD_LOG;  // periods in the dataset

    auto build_static = [&](size_t bytes) {
        size_t words = bytes / 8;
        uint32_t k = (uint32_t)(words / (blocks ? blocks : 1));
        if (k > S2_PERIOD) k = S2_PERIOD;
        a.keep = k;
        a.svals.assign((size_t)blocks * k, 0);
        for (size_t b = 0; b < blocks; ++b)
            for (uint32_t r = 0; r < k; ++r) {
                size_t idx = (b << S2_PERIOD_LOG) + r;
                a.svals[b * k + r] = a.truth[idx];
            }
    };
    auto build_prefix = [&](size_t bytes) {
        size_t words = bytes / 8;
        if (words > a.D) words = a.D;
        a.prefix = words;
        a.svals.assign(words, 0);
        for (size_t i = 0; i < words; ++i) a.svals[i] = a.truth[i];
    };
    auto build_dyn = [&](size_t bytes, size_t ways_target, size_t meta_per_slot, bool bit_per_set) {
        // per-slot cost; the 1-bit-per-set variant adds ~1/(8*ways) bytes per slot
        double per_slot = 8.0 + 4.0 + (double)meta_per_slot + (bit_per_set ? 1.0 / (8.0 * ways_target) : 0.0);
        size_t slots = (size_t)((double)bytes / per_slot);
        if (slots > a.D) slots = a.D;
        size_t nsets = slots / ways_target;
        if (nsets == 0) nsets = 1;
        a.sets = nsets;
        a.ways = ways_target;
        a.cap_dyn = a.sets * a.ways;
        a.dvals.assign(a.cap_dyn, 0);
        a.dtags.assign(a.cap_dyn, S2_EMPTY);
        if (meta_per_slot == 4) a.dmeta32.assign(a.cap_dyn, 0);
        if (meta_per_slot == 1) a.dmeta8.assign(a.cap_dyn, 0);
        if (bit_per_set) a.setbit.assign((a.sets + 7) / 8, 0);
    };

    switch (rep) {
        case REP_SA8:    build_dyn(avail, 8, 4, false); break;
        case REP_DIRECT: build_dyn(avail, 1, 0, false); break;
        case REP_SA2:    build_dyn(avail, 2, 0, true);  break;
        case REP_LFU8:   build_dyn(avail, 8, 1, false); break;
        case REP_STATIC: build_static(avail); break;
        case REP_HYBRID: {
            size_t dynb = (size_t)(avail * hybrid_dyn_frac);
            build_dyn(dynb, 4, 0, false);
            size_t used = a.dyn_bytes();
            build_static(avail > used ? avail - used : 0);
            break;
        }
        case REP_PREFIX: build_prefix(avail); break;
        case REP_PREFIX_MEMO: {
            size_t dynb = (size_t)(avail * hybrid_dyn_frac);
            build_dyn(dynb, 4, 0, false);
            size_t used = a.dyn_bytes();
            build_prefix(avail > used ? avail - used : 0);
            break;
        }
    }
}

// Lookup in the dynamic cache (returns true + value, updates replacement state).
inline bool a2_dyn_lookup(Attacker2& a, uint32_t idx, uint64_t& out) {
    if (!a.cap_dyn) return false;
    uint32_t set = s2_set_of(idx, a.sets);
    size_t base = (size_t)set * a.ways;
    for (size_t w = 0; w < a.ways; ++w) {
        if (a.dtags[base + w] == idx) {
            out = a.dvals[base + w];
            if (a.rep == REP_SA8) a.dmeta32[base + w] = ++a.clock;
            else if (a.rep == REP_LFU8) { uint8_t& m = a.dmeta8[base + w]; if (m < 255) m++; }
            else if (a.rep == REP_SA2) {  // 1 bit per set marks the MRU way
                size_t bit = set; uint8_t& by = a.setbit[bit >> 3];
                if (w == 0) by &= ~(uint8_t)(1u << (bit & 7)); else by |= (uint8_t)(1u << (bit & 7));
            }
            return true;
        }
    }
    return false;
}

inline void a2_dyn_insert(Attacker2& a, uint32_t idx, uint64_t val) {
    if (!a.cap_dyn) return;
    uint32_t set = s2_set_of(idx, a.sets);
    size_t base = (size_t)set * a.ways;
    size_t victim = base;
    if (a.rep == REP_DIRECT) {
        victim = base;  // single way
    } else if (a.rep == REP_SA2) {
        size_t bit = set;
        bool mru_is_w1 = (a.setbit[bit >> 3] >> (bit & 7)) & 1u;
        victim = base + (mru_is_w1 ? 0 : 1);  // evict the LRU way
        if (victim == base) a.setbit[bit >> 3] &= ~(uint8_t)(1u << (bit & 7));
        else a.setbit[bit >> 3] |= (uint8_t)(1u << (bit & 7));
    } else if (a.rep == REP_LFU8) {
        uint8_t best = 255;
        for (size_t w = 0; w < a.ways; ++w) {
            size_t s = base + w;
            if (a.dtags[s] == S2_EMPTY) { victim = s; best = 0; break; }
            if (a.dmeta8[s] <= best) { best = a.dmeta8[s]; victim = s; }
        }
        a.dmeta8[victim] = 1;
    } else {  // REP_SA8 / REP_HYBRID (LRU clock)
        uint32_t best = 0xFFFFFFFFu;
        for (size_t w = 0; w < a.ways; ++w) {
            size_t s = base + w;
            if (a.dtags[s] == S2_EMPTY) { victim = s; break; }
            uint32_t m = a.dmeta32.empty() ? 0 : a.dmeta32[s];
            if (m <= best) { best = m; victim = s; }
        }
        if (!a.dmeta32.empty()) a.dmeta32[victim] = ++a.clock;
    }
    a.dvals[victim] = val;
    a.dtags[victim] = idx;
}

uint64_t a2_read(void* ctx, uint64_t index);

// Iterative (non-recursive) exact reconstruction; mirrors v2_word()'s parent structure.
inline uint64_t a2_reconstruct(Attacker2& a, uint32_t want) {
    size_t sp = 0;
    a.stack[sp].idx = want; a.stack[sp].stage = 0; sp = 1;
    uint64_t ret = 0;
    while (sp) {
        if (sp > a.max_depth) a.max_depth = sp;
        Attacker2::Frame& f = a.stack[sp - 1];
        uint32_t w = f.idx;
        if (w < V2_SEED_WORDS) { ret = s2_seed(a, w); --sp; continue; }
        if (f.stage == 0) {
            if (s2_static_has(a, w)) { ret = s2_sval(a, s2_static_slot(a, w)); --sp; continue; }
            uint64_t cv;
            if (a2_dyn_lookup(a, w, cv)) { ret = cv; --sp; continue; }
        }
        switch (f.stage) {
            case 0: {
                f.h = v2_splitmix((uint64_t)w ^ a.seedconst);
                uint32_t p1 = (uint32_t)(f.h % (uint64_t)w);
                f.stage = 1;
                if (sp >= a.stack.size()) { ret = 0; --sp; break; }
                a.stack[sp].idx = p1; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 1: {
                f.d1 = ret;
                f.acc = v2_mix(f.d1, f.h, (uint64_t)w); a.ops++;
                if (a.nparents < 2) { ret = f.acc; a2_dyn_insert(a, w, ret); --sp; break; }
                uint32_t p2 = (uint32_t)((f.d1 ^ (f.h >> 13)) % (uint64_t)w);
                f.stage = 2;
                if (sp >= a.stack.size()) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p2; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 2: {
                f.d2 = ret;
                f.acc = v2_mix(f.acc, f.d2, (uint64_t)w ^ rotl64(f.d1, 32)); a.ops++;
                if (a.nparents < 3) { ret = f.acc; a2_dyn_insert(a, w, ret); --sp; break; }
                uint32_t p3 = (uint32_t)((f.d1 ^ f.d2 ^ (f.h >> 29)) % (uint64_t)w);
                f.stage = 3;
                if (sp >= a.stack.size()) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p3; a.stack[sp].stage = 0; ++sp;
                break;
            }
            case 3: {
                f.d3 = ret;
                f.acc = v2_mix(f.acc, f.d3, (uint64_t)w ^ rotl64(f.d2, 17)); a.ops++;
                if (a.nparents < 4) { ret = f.acc; a2_dyn_insert(a, w, ret); --sp; break; }
                uint32_t p4 = (uint32_t)((f.d2 ^ f.d3 ^ (f.h >> 7)) % (uint64_t)w);
                f.stage = 4;
                if (sp >= a.stack.size()) { ret = f.acc; --sp; break; }
                a.stack[sp].idx = p4; a.stack[sp].stage = 0; ++sp;
                break;
            }
            default: {
                uint64_t d4 = ret;
                uint64_t val = v2_mix(f.acc, d4, (uint64_t)w ^ rotl64(f.d3, 41)); a.ops++;
                ret = val;
                a2_dyn_insert(a, w, val);
                --sp;
                break;
            }
        }
    }
    return ret;
}

inline uint64_t a2_read(void* ctx, uint64_t index) {
    Attacker2& a = *(Attacker2*)ctx;
    a.reads++;
    uint32_t idx = (uint32_t)index;
    if (idx < V2_SEED_WORDS) { a.hits++; return s2_seed(a, idx); }
    if (s2_static_has(a, idx)) { a.hits++; return s2_sval(a, s2_static_slot(a, idx)); }
    uint64_t v;
    if (a2_dyn_lookup(a, idx, v)) { a.hits++; return v; }
    a.misses++;
    return a2_reconstruct(a, idx);
}

}  // namespace meepow

#endif  // MEEPOW_TMTO_STRICT2_HPP
