// MeepCoin proof-of-work bridge: Monero's block-hashing call convention -> frozen MeepHash-W v2.
//
// THIS FILE CONTAINS NO HASHING ALGORITHM. It locates the nonce, manages caches, and calls
// meepow::v2. If you find yourself writing mixing/compression logic here, that is a bug.
//
// Caching, and why it is shaped this way:
//   * the 32 MiB epoch Dataset costs ~350 ms to build and depends only on the epoch key, so it is
//     built once per key and shared immutably across every thread (meepow::v2::Dataset is
//     documented thread-safe once constructed);
//   * the Hasher owns an 8 MiB scratchpad and a derived program and is NOT thread-safe, so each
//     thread keeps its own, rebuilt only when (seed, height, template) changes. Mining varies only
//     the nonce, so the steady-state mining path reuses one Hasher and allocates nothing per hash.

#include "meep-hash.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "meepow/v2.hpp"

namespace {

namespace mv2 = meepow::v2;

// ---- epoch dataset cache (shared, immutable once built) --------------------------------------
struct DatasetEntry {
    uint8_t key[32];
    std::shared_ptr<mv2::Dataset> ds;
};
std::mutex g_ds_mutex;
std::vector<DatasetEntry> g_datasets;   // keep a small ring: current epoch + the previous one

std::shared_ptr<mv2::Dataset> get_dataset(const uint8_t key[32]) {
    std::lock_guard<std::mutex> lock(g_ds_mutex);
    for (const auto& e : g_datasets)
        if (std::memcmp(e.key, key, 32) == 0) return e.ds;

    mv2::Error err = mv2::Error::Ok;
    std::shared_ptr<mv2::Dataset> ds(mv2::Dataset::create(key, &err).release());
    if (!ds) return nullptr;

    DatasetEntry e;
    std::memcpy(e.key, key, 32);
    e.ds = ds;
    g_datasets.push_back(std::move(e));
    if (g_datasets.size() > 2) g_datasets.erase(g_datasets.begin());   // reorg-tolerant: keep 2
    return ds;
}

// ---- per-thread hashing context ---------------------------------------------------------------
struct ThreadCtx {
    std::shared_ptr<mv2::Dataset> ds;
    std::unique_ptr<mv2::Hasher> hasher;
    uint8_t seed[32] = {0};
    uint64_t height = UINT64_MAX;
    std::string tmpl;                 // template blob with the nonce field zeroed
    bool valid = false;
};
thread_local ThreadCtx t_ctx;

// Skip one CryptoNote varint; returns false if the buffer is malformed/truncated.
bool skip_varint(const uint8_t* p, size_t len, size_t& off) {
    while (off < len) {
        uint8_t b = p[off++];
        if ((b & 0x80) == 0) return true;
    }
    return false;
}

// Block hashing blob layout (block_header): varint major, varint minor, varint timestamp,
// 32-byte prev_id, then a FIXED 4-byte little-endian nonce. Returns the nonce offset, or
// SIZE_MAX if the blob is too short / malformed.
size_t nonce_offset(const uint8_t* p, size_t len) {
    size_t off = 0;
    if (!skip_varint(p, len, off)) return SIZE_MAX;   // major_version
    if (!skip_varint(p, len, off)) return SIZE_MAX;   // minor_version
    if (!skip_varint(p, len, off)) return SIZE_MAX;   // timestamp
    if (off + 32 + 4 > len) return SIZE_MAX;          // prev_id + nonce must fit
    return off + 32;
}

}  // namespace

extern "C" void meep_slow_hash(const char *seedhash, uint64_t height,
                               const void *data, size_t length, char *result_hash) {
    std::memset(result_hash, 0, 32);
    if (!seedhash || !data || length == 0) return;

    const uint8_t* blob = static_cast<const uint8_t*>(data);
    const uint8_t* seed = reinterpret_cast<const uint8_t*>(seedhash);

    // Split the blob into (template with nonce zeroed, nonce), per the frozen spec.
    uint32_t nonce = 0;
    std::string tmpl(reinterpret_cast<const char*>(blob), length);
    const size_t noff = nonce_offset(blob, length);
    if (noff != SIZE_MAX) {
        nonce = (uint32_t)blob[noff] | ((uint32_t)blob[noff + 1] << 8) |
                ((uint32_t)blob[noff + 2] << 16) | ((uint32_t)blob[noff + 3] << 24);
        std::memset(&tmpl[noff], 0, 4);
    }
    // If the blob is malformed the nonce stays 0 and the whole blob is the template. The hash is
    // still a deterministic function of the blob, so verification remains consistent; a malformed
    // blob is rejected by the structural checks that run before PoW anyway.

    ThreadCtx& c = t_ctx;
    if (!c.valid || c.height != height || std::memcmp(c.seed, seed, 32) != 0 || c.tmpl != tmpl) {
        c.valid = false;
        c.hasher.reset();
        c.ds = get_dataset(seed);
        if (!c.ds) return;

        mv2::Error err = mv2::Error::Ok;
        c.hasher = mv2::Hasher::create(*c.ds, seed, height,
                                       reinterpret_cast<const uint8_t*>(tmpl.data()), tmpl.size(),
                                       &err);
        if (!c.hasher) return;
        std::memcpy(c.seed, seed, 32);
        c.height = height;
        c.tmpl = tmpl;
        c.valid = true;
    }

    uint8_t out[32];
    if (c.hasher->hash(nonce, out) != mv2::Error::Ok) return;
    std::memcpy(result_hash, out, 32);
}

extern "C" void meep_slow_hash_free_state(void) {
    t_ctx.hasher.reset();
    t_ctx.ds.reset();
    t_ctx.valid = false;
    t_ctx.tmpl.clear();
}
