// Pluggable storage backends for the shared consensus VM (v2 TMTO + corrected store-elision).
// The reference and every adversary call the SAME hash code (meepow_v1.hpp pipeline); only these
// backends differ. Dataset backends serve v2 dataset words with a retention policy + reconstruction
// via the shared v2_word(). Scratchpad backends implement store-elision policies over vm.SP.
#ifndef MEEPOW_DATASET_BACKEND_HPP
#define MEEPOW_DATASET_BACKEND_HPP

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "dataset_v2.hpp"

namespace meepow {

// ---------------- dataset backend (efficient: bitmaps + the true value array) ------------------
// Storage uses O(1) array/bit access (NOT hash maps) so timing reflects true recompute cost, not
// data-structure overhead. `present` selects which words a reduced attacker keeps (values served
// from the true `fullvals`); `memo_*` is the per-hash memo (a smart attacker recomputes each
// missing word once/hash). Reported memory is the LOGICAL popcount, not the measurement arrays.
struct V2DsBackend {
    int nparents = 3;
    uint64_t seedconst = 0;
    size_t count = 0;
    bool is_full = false;
    const uint64_t* fullvals = nullptr;    // all true values (serve retained words directly)
    std::vector<uint8_t> present;          // retained bitmap (seed region set to 1)
    bool memo_enabled = false;
    std::vector<uint8_t> memo_present;      // per-hash memo bitmap
    std::vector<uint64_t> memo_vals;        // per-hash memo values
    std::vector<uint64_t> memo_touched;     // indices to clear at end of hash
    // metrics
    uint64_t ops = 0, reads = 0, misses = 0, cap = 0;
    bool capped = false;
    size_t retained_words = 0;             // logical persistent store (popcount of non-seed present)
    size_t peak_cache = 0;                 // max transient per-hash memo size
    std::vector<uint32_t>* counts = nullptr;
};

uint64_t v2_ds_read(void* ctx, uint64_t index);  // fwd

inline uint64_t v2_ds_resolve(V2DsBackend* b, uint64_t index) {
    if (b->is_full) return b->fullvals[index];
    if (b->present[index]) return b->fullvals[index];  // retained (incl. seed region)
    if (b->memo_enabled && b->memo_present[index]) return b->memo_vals[index];
    b->misses++;
    uint64_t val = v2_word((size_t)index, b->seedconst, b->nparents,
                           [&](size_t idx) { return v2_ds_read(b, idx); }, b->ops);
    if (b->memo_enabled) {
        b->memo_present[index] = 1;
        b->memo_vals[index] = val;
        b->memo_touched.push_back(index);
        if (b->memo_touched.size() > b->peak_cache) b->peak_cache = b->memo_touched.size();
    }
    return val;
}
inline uint64_t v2_ds_read(void* ctx, uint64_t index) {
    V2DsBackend* b = (V2DsBackend*)ctx;
    b->reads++;
    if (b->counts) (*b->counts)[index]++;
    return v2_ds_resolve(b, index);
}
// Clear the per-hash memo (called at the start of each hash).
inline void v2_ds_reset_memo(V2DsBackend* b) {
    if (!b->memo_enabled) return;
    for (uint64_t i : b->memo_touched) b->memo_present[i] = 0;
    b->memo_touched.clear();
}

// Initialize a backend from the full dataset: set fullvals, seedconst, seed-region present bits.
inline void v2_backend_init(V2DsBackend& b, const std::vector<uint64_t>& fullds, int nparents) {
    b.nparents = nparents;
    b.count = fullds.size();
    b.fullvals = fullds.data();
    b.seedconst = fullds[0];
    b.present.assign(fullds.size(), 0);
    for (size_t w = 0; w < V2_SEED_WORDS && w < fullds.size(); ++w) b.present[w] = 1;  // seed free
}
inline void v2_backend_enable_memo(V2DsBackend& b) {
    b.memo_enabled = true;
    b.memo_present.assign(b.count, 0);
    b.memo_vals.assign(b.count, 0);
    b.memo_touched.reserve(1 << 20);
}
// Count logical persistent retained words (non-seed present bits).
inline void v2_backend_count_retained(V2DsBackend& b) {
    size_t r = V2_SEED_WORDS;
    for (size_t w = V2_SEED_WORDS; w < b.count; ++w) r += b.present[w];
    b.retained_words = r;
}

// ---------------- scratchpad backend (store-elision) -------------------------------------------
enum SpPolicy { SP_FULL, SP_NO_STORE, SP_WRITE_BUFFER, SP_DEAD_ORACLE, SP_PARTIAL, SP_RECOMPUTE };
struct V2SpBackend {
    SpPolicy policy = SP_FULL;
    uint64_t* sp = nullptr;      // backing scratchpad (c->scratch), filled by scratch-init
    uint64_t mask = 0;
    std::unordered_map<uint64_t, uint64_t> buf;  // write buffer (deferred/forward/combine)
    const std::vector<uint8_t>* readset = nullptr;  // dead-store oracle: offsets ever read
    uint64_t keepNum = 1, keepDen = 2;           // partial cache fraction
};
inline uint64_t sp_recompute_proxy(uint64_t off) { return v2_splitmix(off); }
inline uint64_t v2_sp_read(void* ctx, uint64_t off) {
    V2SpBackend* b = (V2SpBackend*)ctx;
    switch (b->policy) {
        case SP_WRITE_BUFFER: { auto it = b->buf.find(off); return it != b->buf.end() ? it->second : b->sp[off]; }
        case SP_PARTIAL: return ((off % b->keepDen) < b->keepNum) ? b->sp[off] : 0;
        case SP_RECOMPUTE: return sp_recompute_proxy(off);
        default: return b->sp[off];
    }
}
inline void v2_sp_write(void* ctx, uint64_t off, uint64_t val) {
    V2SpBackend* b = (V2SpBackend*)ctx;
    switch (b->policy) {
        case SP_NO_STORE: return;
        case SP_DEAD_ORACLE: if (b->readset && (*b->readset)[off]) b->sp[off] = val; return;
        case SP_WRITE_BUFFER: b->buf[off] = val; return;
        case SP_PARTIAL: if ((off % b->keepDen) < b->keepNum) b->sp[off] = val; return;
        case SP_RECOMPUTE: return;
        default: b->sp[off] = val; return;
    }
}

}  // namespace meepow

#endif  // MEEPOW_DATASET_BACKEND_HPP
