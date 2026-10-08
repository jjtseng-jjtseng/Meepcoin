/*
 * MeepHash-W v0 — public C API.
 *
 * EXPERIMENTAL research prototype. Not production-ready, not proven secure, not memory-hard,
 * not GPU/ASIC resistant. See docs/SECURITY_LIMITATIONS.md. Byte-for-byte behavior is defined
 * by docs/MEEPHASH_SPEC.md (algorithm version 0).
 *
 * The same sources compile to native (CMake) and WebAssembly (Emscripten). This C API is the
 * integration surface for the Monero-derived daemon (Phase 3) and the Wasm/TS wrapper.
 */
#ifndef MEEPOW_H
#define MEEPOW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEEPOW_ALGO_VERSION 0
#define MEEPOW_HASH_SIZE 32

/* Parameter-set identifiers (see spec §2). */
#define MEEPOW_PARAM_DEV 0  /* 32 MiB dataset / 8 MiB scratchpad / 256 prog / 8 rounds */
#define MEEPOW_PARAM_FAST 1 /* tiny; test/vector use only */

/* Dataset construction (see spec §4). */
#define MEEPOW_DATASET_A 0 /* independent chunks */
#define MEEPOW_DATASET_B 1 /* sequential dependent */

/* Opaque epoch dataset (cache-reusable across nonces and jobs with the same epoch key). */
typedef struct meepow_dataset meepow_dataset;

/*
 * Build an epoch dataset. Pure function of (param_set_id, construction, epoch_key[32]).
 * Returns NULL on allocation failure or invalid arguments. Free with meepow_dataset_free.
 */
meepow_dataset* meepow_dataset_create(uint8_t param_set_id, uint8_t construction,
                                      const uint8_t epoch_key[32]);
void meepow_dataset_free(meepow_dataset* ds);

/* Total dataset bytes for a parameter set (0 if the id is unknown). */
size_t meepow_dataset_bytes(uint8_t param_set_id);
/* Peak per-nonce scratchpad bytes for a parameter set (0 if unknown). */
size_t meepow_scratchpad_bytes(uint8_t param_set_id);

/*
 * Compute one MeepHash-W v0 result.
 *
 *   ds            : dataset built with the SAME param_set_id and the epoch_key implied below.
 *   seed_block_hash[32], block_height : program-derivation inputs (spec §5, §9).
 *   template_blob : mining template with the nonce field already ZEROED (spec §8).
 *   nonce         : per-attempt search value.
 *   out_hash[32]  : little-endian 256-bit result.
 *   out_checkpoint_round1[32], out_checkpoint_round_half[32] : optional (may be NULL);
 *                   intermediate digests for test vectors (spec §8.5).
 *
 * Returns 0 on success, non-zero on invalid arguments. Deterministic across native/Wasm.
 */
int meepow_hash(const meepow_dataset* ds, const uint8_t seed_block_hash[32],
                uint64_t block_height, const uint8_t* template_blob, size_t template_len,
                uint32_t nonce, uint8_t out_hash[32], uint8_t out_checkpoint_round1[32],
                uint8_t out_checkpoint_round_half[32]);

/*
 * Reusable per-job hashing context (allocation-free steady-state hashing).
 *
 * The VM program depends only on (epochKey, seedBlockHash, blockHeight) and the template blob is
 * constant across nonces, so a context derives the program ONCE and holds reusable scratchpad and
 * temporary buffers. meepow_ctx_hash then performs ZERO heap allocations per nonce. Output is
 * byte-for-byte identical to meepow_hash (which is implemented on top of this).
 *
 * Lifetime: the referenced dataset must outlive the context. Not thread-safe; use one context per
 * worker thread (each owns its scratchpad).
 */
typedef struct meepow_ctx meepow_ctx;

meepow_ctx* meepow_ctx_create(const meepow_dataset* ds, const uint8_t seed_block_hash[32],
                              uint64_t block_height, const uint8_t* template_blob,
                              size_t template_len);
void meepow_ctx_free(meepow_ctx* ctx);

/* Hash one nonce reusing the context's buffers. out_hash[32] required; checkpoints optional. */
int meepow_ctx_hash(meepow_ctx* ctx, uint32_t nonce, uint8_t out_hash[32],
                    uint8_t out_checkpoint_round1[32], uint8_t out_checkpoint_round_half[32]);

/*
 * Difficulty/target helpers (spec §10). Targets are 32-byte little-endian.
 * difficulty == 0 is invalid: meepow_difficulty_to_target returns non-zero and leaves
 * out_target untouched.
 */
int meepow_difficulty_to_target(uint64_t difficulty, uint8_t out_target[32]);
/* Returns 1 if hash <= target (both little-endian 256-bit), else 0. */
int meepow_hash_meets_target(const uint8_t hash[32], const uint8_t target[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MEEPOW_H */
