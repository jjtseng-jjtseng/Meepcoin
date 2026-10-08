/*
 * MeepHash-W v2 — OPTIONAL C ABI.
 *
 * The MeepCoin daemon is C++ and links meepow/v2.hpp directly. This C ABI exists for independent
 * miners, pool software, test harnesses, and future language bindings (Rust/Go/Python/Node FFI).
 *
 * IT IS A WRAPPER OVER meepow/v2.hpp, WHICH IS ITSELF A WRAPPER OVER THE FROZEN IMPLEMENTATION.
 * There is exactly one consensus hash implementation in this repository. This header adds C
 * linkage and nothing else — no separate algorithm, no duplicated constants.
 *
 * Conventions:
 *   - All functions return int: 0 == success, non-zero == a meepow_v2_error value.
 *   - All 256-bit values (hashes, targets, keys) are 32-byte LITTLE-ENDIAN buffers.
 *   - Handles are opaque; free them with the matching *_free. Passing NULL to a *_free is a no-op.
 *   - No function throws; no C++ exception crosses this boundary.
 *
 * EXPERIMENTAL. Not production-ready, not proven memory-hard, not GPU/ASIC resistant, not for
 * mainnet or funds of value. Consensus cannot prove a hash came from a browser.
 */
#ifndef MEEPOW_V2_C_H
#define MEEPOW_V2_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Frozen consensus identity (mirrors meepow::v2:: constants; asserted equal at compile time). */
#define MEEPOW_V2_ALGO_VERSION     2
#define MEEPOW_V2_PARAM_SET_ID     60
#define MEEPOW_V2_HASH_SIZE        32
#define MEEPOW_V2_EPOCH_KEY_SIZE   32
#define MEEPOW_V2_SEED_HASH_SIZE   32
#define MEEPOW_V2_DATASET_BYTES    (32u * 1024u * 1024u)
#define MEEPOW_V2_SCRATCHPAD_BYTES (8u * 1024u * 1024u)
#define MEEPOW_V2_TOTAL_VM_STEPS   102400u
#define MEEPOW_V2_EPOCH_LENGTH     2048u
#define MEEPOW_V2_EPOCH_DELAY      64u
#define MEEPOW_V2_SEED_BLOCK_DELAY 64u

/* Error codes — numerically equal to meepow::v2::Error. */
typedef enum meepow_v2_error {
    MEEPOW_V2_OK = 0,
    MEEPOW_V2_ERR_NULL_ARGUMENT = 1,
    MEEPOW_V2_ERR_INVALID_TEMPLATE = 2,
    MEEPOW_V2_ERR_INVALID_DATASET = 3,
    MEEPOW_V2_ERR_ALLOCATION_FAILED = 4,
    MEEPOW_V2_ERR_BUFFER_TOO_SMALL = 5,
    MEEPOW_V2_ERR_INVALID_COUNT = 6,
    MEEPOW_V2_ERR_INVALID_DIFFICULTY = 7
} meepow_v2_error;

/* Stable ASCII description. Never NULL. */
const char* meepow_v2_error_string(int err);

/* ------------------------------------------------------------------------------------------- *
 * Dataset — 32 MiB epoch dataset, a pure function of the 32-byte epoch key.
 *
 * OWNERSHIP: meepow_v2_dataset_create allocates; the caller must call meepow_v2_dataset_free.
 * THREAD SAFETY: immutable once created. Share one dataset across any number of hashers/threads.
 *                It MUST outlive every hasher created from it.
 * COST: ~350 ms. Build once per epoch key; never per block or per nonce.
 * ------------------------------------------------------------------------------------------- */
typedef struct meepow_v2_dataset meepow_v2_dataset;

int  meepow_v2_dataset_create(const uint8_t epoch_key[32], meepow_v2_dataset** out_dataset);
void meepow_v2_dataset_free(meepow_v2_dataset* dataset);
size_t meepow_v2_dataset_size_bytes(const meepow_v2_dataset* dataset); /* 0 if NULL */

/* ------------------------------------------------------------------------------------------- *
 * Hasher — per-job context. Derives the VM program once and owns an 8 MiB scratchpad, so hashing
 * a nonce performs no heap allocation.
 *
 * OWNERSHIP: caller must call meepow_v2_hasher_free. Holds a NON-OWNING reference to the dataset.
 * THREAD SAFETY: NOT thread-safe — it mutates its scratchpad every hash. ONE HASHER PER THREAD.
 *
 * template_blob is the block hashing blob with the NONCE FIELD ZEROED; the nonce is passed
 * separately to the hash calls.
 * ------------------------------------------------------------------------------------------- */
typedef struct meepow_v2_hasher meepow_v2_hasher;

int  meepow_v2_hasher_create(const meepow_v2_dataset* dataset,
                             const uint8_t seed_block_hash[32],
                             uint64_t block_height,
                             const uint8_t* template_blob, size_t template_len,
                             meepow_v2_hasher** out_hasher);
void meepow_v2_hasher_free(meepow_v2_hasher* hasher);

/* One hash (~16.4 ms). out_hash receives 32 bytes. */
int meepow_v2_hash(meepow_v2_hasher* hasher, uint32_t nonce, uint8_t out_hash[32]);

/* Contiguous nonce range [first_nonce, first_nonce+count). Writes count*32 bytes; out_len must be
 * at least count*32. Byte-identical to calling meepow_v2_hash count times. Single-threaded. */
int meepow_v2_hash_batch(meepow_v2_hasher* hasher, uint32_t first_nonce, size_t count,
                         uint8_t* out_hashes, size_t out_len);

/* ------------------------------------------------------------------------------------------- *
 * Epoch scheduling (pure arithmetic; the library never reads a chain).
 * ------------------------------------------------------------------------------------------- */
uint64_t meepow_v2_epoch_index(uint64_t height);

/* Return 1 and set *out_height, or 0 when the genesis seed constant must be used instead. */
int meepow_v2_epoch_source_height(uint64_t height, uint64_t* out_height);
int meepow_v2_seed_block_height(uint64_t height, uint64_t* out_height);

/* 1 if a reorg with the given fork point changes this input, else 0. */
int meepow_v2_epoch_key_changes_on_reorg(uint64_t height, uint64_t fork_point);
int meepow_v2_seed_block_changes_on_reorg(uint64_t height, uint64_t fork_point);

/* Chain lookup callback: return the 32-byte block hash at height, or NULL if unknown. */
typedef const uint8_t* (*meepow_v2_block_hash_fn)(uint64_t height, void* ctx);

int meepow_v2_resolve_epoch_key(uint64_t height, meepow_v2_block_hash_fn get, void* ctx,
                                uint8_t out_key[32]);
int meepow_v2_resolve_seed_block_hash(uint64_t height, meepow_v2_block_hash_fn get, void* ctx,
                                      uint8_t out_hash[32]);

/* ------------------------------------------------------------------------------------------- *
 * Difficulty / target. 32-byte little-endian.
 *   target = floor((2^256 - 1) / difficulty); valid iff hash <= target.
 * ------------------------------------------------------------------------------------------- */
int meepow_v2_difficulty_to_target(uint64_t difficulty, uint8_t out_target[32]);

/* Returns 1 if hash <= target, else 0 (also 0 on NULL input). */
int meepow_v2_hash_meets_target(const uint8_t hash[32], const uint8_t target[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MEEPOW_V2_C_H */
