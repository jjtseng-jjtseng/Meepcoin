/*
 * MeepHash-W v2 C ABI — implementation.
 *
 * This file calls meepow::v2:: (the C++ API) and NOTHING ELSE. It deliberately does not include
 * dataset_v2.hpp, meepow_v2.hpp, epoch.hpp or target.hpp: routing the C ABI through the C++ API
 * guarantees the two public surfaces cannot drift apart, because there is only one path to the
 * frozen implementation.
 */
#include "meepow/v2_c.h"

#include "meepow/v2.hpp"

namespace {

// The C enum and the C++ enum class must stay numerically identical, or callers translating
// between the two surfaces would silently misreport errors.
static_assert((int)meepow::v2::Error::Ok                == MEEPOW_V2_OK, "error code drift");
static_assert((int)meepow::v2::Error::NullArgument      == MEEPOW_V2_ERR_NULL_ARGUMENT, "drift");
static_assert((int)meepow::v2::Error::InvalidTemplate   == MEEPOW_V2_ERR_INVALID_TEMPLATE, "drift");
static_assert((int)meepow::v2::Error::InvalidDataset    == MEEPOW_V2_ERR_INVALID_DATASET, "drift");
static_assert((int)meepow::v2::Error::AllocationFailed  == MEEPOW_V2_ERR_ALLOCATION_FAILED, "drift");
static_assert((int)meepow::v2::Error::BufferTooSmall    == MEEPOW_V2_ERR_BUFFER_TOO_SMALL, "drift");
static_assert((int)meepow::v2::Error::InvalidCount      == MEEPOW_V2_ERR_INVALID_COUNT, "drift");
static_assert((int)meepow::v2::Error::InvalidDifficulty == MEEPOW_V2_ERR_INVALID_DIFFICULTY, "drift");

// The C macros must agree with the C++ constants (which are themselves static_asserted against
// the frozen implementation in v2_api.cpp).
static_assert(MEEPOW_V2_ALGO_VERSION     == meepow::v2::ALGO_VERSION, "constant drift");
static_assert(MEEPOW_V2_PARAM_SET_ID     == meepow::v2::PARAM_SET_ID, "constant drift");
static_assert(MEEPOW_V2_HASH_SIZE        == meepow::v2::HASH_SIZE, "constant drift");
static_assert(MEEPOW_V2_DATASET_BYTES    == meepow::v2::DATASET_BYTES, "constant drift");
static_assert(MEEPOW_V2_SCRATCHPAD_BYTES == meepow::v2::SCRATCHPAD_BYTES, "constant drift");
static_assert(MEEPOW_V2_TOTAL_VM_STEPS   == meepow::v2::TOTAL_VM_STEPS, "constant drift");
static_assert(MEEPOW_V2_EPOCH_LENGTH     == meepow::v2::EPOCH_LENGTH, "constant drift");
static_assert(MEEPOW_V2_EPOCH_DELAY      == meepow::v2::EPOCH_DELAY, "constant drift");
static_assert(MEEPOW_V2_SEED_BLOCK_DELAY == meepow::v2::SEED_BLOCK_DELAY, "constant drift");

inline int rc(meepow::v2::Error e) { return (int)e; }

}  // namespace

// Opaque handles simply carry the owning C++ objects.
struct meepow_v2_dataset { std::unique_ptr<meepow::v2::Dataset> ds; };
struct meepow_v2_hasher  { std::unique_ptr<meepow::v2::Hasher>  h; };

extern "C" {

const char* meepow_v2_error_string(int err) {
    return meepow::v2::error_string((meepow::v2::Error)err);
}

// --- dataset ---------------------------------------------------------------------------------

int meepow_v2_dataset_create(const uint8_t epoch_key[32], meepow_v2_dataset** out_dataset) {
    if (!epoch_key || !out_dataset) return MEEPOW_V2_ERR_NULL_ARGUMENT;
    *out_dataset = nullptr;

    meepow::v2::Error e = meepow::v2::Error::Ok;
    auto ds = meepow::v2::Dataset::create(epoch_key, &e);
    if (!ds) return rc(e);

    auto* handle = new (std::nothrow) meepow_v2_dataset();
    if (!handle) return MEEPOW_V2_ERR_ALLOCATION_FAILED;
    handle->ds = std::move(ds);
    *out_dataset = handle;
    return MEEPOW_V2_OK;
}

void meepow_v2_dataset_free(meepow_v2_dataset* dataset) { delete dataset; }

size_t meepow_v2_dataset_size_bytes(const meepow_v2_dataset* dataset) {
    return (dataset && dataset->ds) ? dataset->ds->size_bytes() : 0;
}

// --- hasher ----------------------------------------------------------------------------------

int meepow_v2_hasher_create(const meepow_v2_dataset* dataset,
                            const uint8_t seed_block_hash[32],
                            uint64_t block_height,
                            const uint8_t* template_blob, size_t template_len,
                            meepow_v2_hasher** out_hasher) {
    if (!out_hasher) return MEEPOW_V2_ERR_NULL_ARGUMENT;
    *out_hasher = nullptr;
    if (!dataset || !dataset->ds) return MEEPOW_V2_ERR_INVALID_DATASET;

    meepow::v2::Error e = meepow::v2::Error::Ok;
    auto h = meepow::v2::Hasher::create(*dataset->ds, seed_block_hash, block_height,
                                        template_blob, template_len, &e);
    if (!h) return rc(e);

    auto* handle = new (std::nothrow) meepow_v2_hasher();
    if (!handle) return MEEPOW_V2_ERR_ALLOCATION_FAILED;
    handle->h = std::move(h);
    *out_hasher = handle;
    return MEEPOW_V2_OK;
}

void meepow_v2_hasher_free(meepow_v2_hasher* hasher) { delete hasher; }

int meepow_v2_hash(meepow_v2_hasher* hasher, uint32_t nonce, uint8_t out_hash[32]) {
    if (!hasher || !hasher->h) return MEEPOW_V2_ERR_NULL_ARGUMENT;
    return rc(hasher->h->hash(nonce, out_hash));
}

int meepow_v2_hash_batch(meepow_v2_hasher* hasher, uint32_t first_nonce, size_t count,
                         uint8_t* out_hashes, size_t out_len) {
    if (!hasher || !hasher->h) return MEEPOW_V2_ERR_NULL_ARGUMENT;
    return rc(hasher->h->hash_batch(first_nonce, count, out_hashes, out_len));
}

// --- epoch scheduling --------------------------------------------------------------------------

uint64_t meepow_v2_epoch_index(uint64_t height) { return meepow::v2::epoch_index(height); }

int meepow_v2_epoch_source_height(uint64_t height, uint64_t* out_height) {
    return meepow::v2::epoch_source_height(height, out_height) ? 1 : 0;
}

int meepow_v2_seed_block_height(uint64_t height, uint64_t* out_height) {
    return meepow::v2::seed_block_height(height, out_height) ? 1 : 0;
}

int meepow_v2_epoch_key_changes_on_reorg(uint64_t height, uint64_t fork_point) {
    return meepow::v2::epoch_key_changes_on_reorg(height, fork_point) ? 1 : 0;
}

int meepow_v2_seed_block_changes_on_reorg(uint64_t height, uint64_t fork_point) {
    return meepow::v2::seed_block_changes_on_reorg(height, fork_point) ? 1 : 0;
}

int meepow_v2_resolve_epoch_key(uint64_t height, meepow_v2_block_hash_fn get, void* ctx,
                                uint8_t out_key[32]) {
    return rc(meepow::v2::resolve_epoch_key(height, (meepow::v2::BlockHashFn)get, ctx, out_key));
}

int meepow_v2_resolve_seed_block_hash(uint64_t height, meepow_v2_block_hash_fn get, void* ctx,
                                      uint8_t out_hash[32]) {
    return rc(meepow::v2::resolve_seed_block_hash(height, (meepow::v2::BlockHashFn)get, ctx,
                                                   out_hash));
}

// --- difficulty / target -------------------------------------------------------------------------

int meepow_v2_difficulty_to_target(uint64_t difficulty, uint8_t out_target[32]) {
    return rc(meepow::v2::difficulty_to_target(difficulty, out_target));
}

int meepow_v2_hash_meets_target(const uint8_t hash[32], const uint8_t target[32]) {
    return meepow::v2::hash_meets_target(hash, target) ? 1 : 0;
}

}  // extern "C"
