/*
 * MeepHash-W v2 stable C++ API — implementation.
 *
 * Every function here DELEGATES to the frozen implementation. There is deliberately no algorithm
 * logic in this file: no hashing, no dataset construction, no epoch arithmetic, no 256-bit math is
 * re-expressed here. If you find yourself writing a loop in this file that computes a consensus
 * value, that is a bug — call the frozen code instead.
 *
 * Frozen entry points used:
 *   meepow::v2_dataset_fill()  meepow/src/dataset_v2.hpp
 *   meepow::v2_ctx_create()    meepow/src/meepow_v2.hpp   (which calls v1_ctx_create)
 *   meepow::v2_hash()          meepow/src/meepow_v2.hpp   (the consensus pipeline)
 *   meepow::epoch_*()          meepow/src/epoch.hpp
 *   meepow::difficulty_to_target(), meepow::hash_meets_target()   meepow/src/target.hpp
 */
#include "meepow/v2.hpp"

#include <cstring>
#include <new>
#include <vector>

#include "dataset_v2.hpp"
#include "epoch.hpp"
#include "meepow_v1.hpp"
#include "meepow_v2.hpp"
#include "target.hpp"

namespace meepow {
namespace v2 {

// --- compile-time agreement with the frozen constants -----------------------------------------
// If the frozen implementation ever changes shape, this file must fail to compile rather than
// silently publish a different algorithm through the public API.
static_assert(DATASET_WORDS == V2_SEED_WORDS * 512, "v2 dataset size drifted from the frozen value");
static_assert(DATASET_BYTES == 32u * 1024u * 1024u, "v2 dataset must be 32 MiB");
static_assert(SCRATCHPAD_BYTES == V1_SCRATCH_WORDS * 8, "v2 scratchpad drifted from the frozen value");
static_assert(PROGRAM_LEN == V1_STEPS_PER_ROUND, "program length drifted");
static_assert(ROUNDS == V1_ROUNDS_50X, "round count drifted");
static_assert(TOTAL_VM_STEPS == 102400, "fixed VM step budget drifted");
static_assert(EPOCH_LENGTH == meepow::EPOCH_LENGTH, "epoch length drifted");
static_assert(EPOCH_DELAY == meepow::EPOCH_DELAY, "epoch delay drifted");
static_assert(SEED_BLOCK_DELAY == meepow::SEED_BLOCK_DELAY, "seed block delay drifted");

const char* error_string(Error e) noexcept {
    switch (e) {
        case Error::Ok:                return "ok";
        case Error::NullArgument:      return "null argument";
        case Error::InvalidTemplate:   return "invalid template blob length";
        case Error::InvalidDataset:    return "invalid or unbuilt dataset";
        case Error::AllocationFailed:  return "allocation failed";
        case Error::BufferTooSmall:    return "output buffer too small";
        case Error::InvalidCount:      return "invalid batch count or nonce range overflow";
        case Error::InvalidDifficulty: return "difficulty must be non-zero";
    }
    return "unknown error";
}

// --- epoch helpers: pure delegation to epoch.hpp -----------------------------------------------

uint64_t epoch_index(uint64_t height) noexcept { return meepow::epoch_index(height); }

bool epoch_source_height(uint64_t height, uint64_t* out_height) noexcept {
    if (!out_height || meepow::epoch_uses_genesis(height)) return false;
    *out_height = meepow::epoch_source_height(height);
    return true;
}

bool seed_block_height(uint64_t height, uint64_t* out_height) noexcept {
    if (!out_height || meepow::seed_uses_genesis(height)) return false;
    *out_height = meepow::seed_block_height(height);
    return true;
}

bool epoch_key_changes_on_reorg(uint64_t height, uint64_t fork_point) noexcept {
    return meepow::reorg_changes_epoch_key(height, fork_point);
}

bool seed_block_changes_on_reorg(uint64_t height, uint64_t fork_point) noexcept {
    return meepow::reorg_changes_seed_block(height, fork_point);
}

Error resolve_epoch_key(uint64_t height, BlockHashFn get, void* ctx,
                        uint8_t out_key[EPOCH_KEY_SIZE]) noexcept {
    if (!get || !out_key) return Error::NullArgument;
    return meepow::resolve_epoch_key(height, get, ctx, out_key) ? Error::Ok : Error::NullArgument;
}

Error resolve_seed_block_hash(uint64_t height, BlockHashFn get, void* ctx,
                              uint8_t out_hash[SEED_HASH_SIZE]) noexcept {
    if (!get || !out_hash) return Error::NullArgument;
    return meepow::resolve_seed_block_hash(height, get, ctx, out_hash) ? Error::Ok
                                                                       : Error::NullArgument;
}

// --- Dataset ------------------------------------------------------------------------------------

struct Dataset::Impl {
    std::vector<uint64_t> words;
    uint8_t key[EPOCH_KEY_SIZE];
};

Dataset::Dataset() : p_(new Impl()) {}
Dataset::~Dataset() = default;

std::unique_ptr<Dataset> Dataset::create(const uint8_t epoch_key[EPOCH_KEY_SIZE],
                                         Error* err) noexcept {
    auto set = [&](Error e) { if (err) *err = e; };
    if (!epoch_key) { set(Error::NullArgument); return nullptr; }

    std::unique_ptr<Dataset> ds;
    try {
        ds.reset(new Dataset());
        ds->p_->words.resize(DATASET_WORDS);
    } catch (const std::bad_alloc&) {
        set(Error::AllocationFailed);
        return nullptr;
    }
    std::memcpy(ds->p_->key, epoch_key, EPOCH_KEY_SIZE);

    // FROZEN construction — 4 data-dependent parents, exactly as v2-frozen.
    meepow::v2_dataset_fill(ds->p_->words.data(), ds->p_->words.size(), epoch_key, DATASET_PARENTS);

    set(Error::Ok);
    return ds;
}

size_t Dataset::size_words() const noexcept { return p_->words.size(); }
size_t Dataset::size_bytes() const noexcept { return p_->words.size() * 8; }
const uint8_t* Dataset::epoch_key() const noexcept { return p_->key; }

// --- Hasher -------------------------------------------------------------------------------------

struct Hasher::Impl {
    V1Ctx* ctx = nullptr;
    uint64_t height = 0;
    ~Impl() { if (ctx) meepow::v1_ctx_free(ctx); }
};

Hasher::Hasher() : p_(new Impl()) {}
Hasher::~Hasher() = default;

std::unique_ptr<Hasher> Hasher::create(const Dataset& dataset,
                                       const uint8_t seed_block_hash[SEED_HASH_SIZE],
                                       uint64_t block_height,
                                       const uint8_t* template_blob, size_t template_len,
                                       Error* err) noexcept {
    auto set = [&](Error e) { if (err) *err = e; };
    if (!seed_block_hash || !template_blob) { set(Error::NullArgument); return nullptr; }
    if (template_len == 0 || template_len > MAX_TEMPLATE_BYTES) {
        set(Error::InvalidTemplate);
        return nullptr;
    }
    if (!dataset.p_ || dataset.p_->words.size() != DATASET_WORDS) {
        set(Error::InvalidDataset);
        return nullptr;
    }

    std::unique_ptr<Hasher> h;
    try {
        h.reset(new Hasher());
        // FROZEN context derivation (program from epochKey+seedBlockHash+height, S3 scratchpad).
        h->p_->ctx = meepow::v2_ctx_create(dataset.p_->words, dataset.p_->key, seed_block_hash,
                                           block_height, template_blob, template_len);
    } catch (const std::bad_alloc&) {
        set(Error::AllocationFailed);
        return nullptr;
    }
    if (!h->p_->ctx) { set(Error::AllocationFailed); return nullptr; }
    h->p_->height = block_height;
    set(Error::Ok);
    return h;
}

Error Hasher::hash(uint32_t nonce, uint8_t out_hash[HASH_SIZE]) noexcept {
    if (!out_hash) return Error::NullArgument;
    if (!p_->ctx) return Error::InvalidDataset;
    // FROZEN consensus pipeline. Backends null => direct dataset reads (reference/production path),
    // which is exactly what produced meepow/vectors/vectors_v2.txt.
    meepow::v2_hash(p_->ctx, nonce, out_hash, nullptr, nullptr);
    return Error::Ok;
}

Error Hasher::hash_batch(uint32_t first_nonce, size_t count,
                         uint8_t* out_hashes, size_t out_len) noexcept {
    if (!out_hashes) return Error::NullArgument;
    if (!p_->ctx) return Error::InvalidDataset;
    if (count == 0) return Error::InvalidCount;
    // Reject a range that would wrap the 32-bit nonce space.
    if (count - 1 > (size_t)(UINT32_MAX - first_nonce)) return Error::InvalidCount;
    if (out_len / HASH_SIZE < count) return Error::BufferTooSmall;

    for (size_t i = 0; i < count; ++i) {
        meepow::v2_hash(p_->ctx, (uint32_t)(first_nonce + i), out_hashes + i * HASH_SIZE,
                        nullptr, nullptr);
    }
    return Error::Ok;
}

uint64_t Hasher::block_height() const noexcept { return p_->height; }

// --- difficulty / target: pure delegation to target.hpp -----------------------------------------

Error difficulty_to_target(uint64_t difficulty, uint8_t out_target[HASH_SIZE]) noexcept {
    if (!out_target) return Error::NullArgument;
    return meepow::difficulty_to_target(difficulty, out_target) ? Error::Ok
                                                                : Error::InvalidDifficulty;
}

bool hash_meets_target(const uint8_t hash[HASH_SIZE], const uint8_t target[HASH_SIZE]) noexcept {
    if (!hash || !target) return false;
    return meepow::hash_meets_target(hash, target);
}

}  // namespace v2
}  // namespace meepow
