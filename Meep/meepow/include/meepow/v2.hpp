/*
 * MeepHash-W v2 — stable versioned C++ integration API.
 *
 * This is the interface the Monero-derived MeepCoin daemon links against directly. It is a THIN
 * WRAPPER over the frozen implementation in meepow/src/{dataset_v2,meepow_v2,meepow_v1,vm}.hpp.
 *
 *   *** IT DOES NOT REIMPLEMENT, COPY, OR MODIFY THE CONSENSUS HASH. ***
 *
 * Every hash produced here flows through the same meepow::v2_hash() that produced the committed
 * vectors in meepow/vectors/vectors_v2.txt. The optional C ABI (meepow/v2_c.h) calls THIS API, so
 * all three surfaces (internal C++, this API, the C ABI) are one implementation.
 *
 * Frozen identity — see docs/MEEPHASH_SPEC_V2.md and git tag `v2-frozen` (68ae0a66):
 *   algorithm version 2, parameter-set id 60, 32 MiB epoch dataset (4 data-dependent parents),
 *   8 MiB scratchpad (S3 init), 256-instruction program, 400 rounds = 102,400 fixed VM steps.
 *   Domain strings: MEEP/DATASET/v2, MEEP/PROGRAM/v1, MEEP/NONCE/v1, MEEP/SCRATCHSEED/v1,
 *   MEEP/FINAL/v1, MEEP/CHECKPOINT/v1.
 *
 * Any change to those values or strings is a CONSENSUS CHANGE and requires a new version (v3) with
 * new domain strings and new vectors. It must never be made in place.
 *
 * EXPERIMENTAL. Not production-ready, not proven memory-hard, not GPU/ASIC resistant, not approved
 * for mainnet or for funds of value. See docs/SECURITY_LIMITATIONS.md.
 *
 * It is impossible for consensus to prove that a hash was produced by a browser. Nothing in this
 * API provides, or can provide, such a proof.
 */
#ifndef MEEPOW_V2_API_HPP
#define MEEPOW_V2_API_HPP

#include <cstddef>
#include <cstdint>
#include <memory>

namespace meepow {
namespace v2 {

// ---------------------------------------------------------------------------------------------
// Frozen consensus identity. These are CONSENSUS CONSTANTS, not tunables.
// ---------------------------------------------------------------------------------------------

constexpr uint8_t  ALGO_VERSION    = 2;
constexpr uint8_t  PARAM_SET_ID    = 60;
constexpr size_t   HASH_SIZE       = 32;
constexpr size_t   EPOCH_KEY_SIZE  = 32;
constexpr size_t   SEED_HASH_SIZE  = 32;

constexpr size_t   DATASET_WORDS   = 4194304;              // 32 MiB / 8
constexpr size_t   DATASET_BYTES   = DATASET_WORDS * 8;
constexpr int      DATASET_PARENTS = 4;
constexpr size_t   SCRATCHPAD_BYTES = size_t(8) << 20;     // 8 MiB, per hashing context
constexpr uint32_t PROGRAM_LEN     = 256;
constexpr uint32_t ROUNDS          = 400;
constexpr uint32_t STEPS_PER_ROUND = 256;
constexpr uint64_t TOTAL_VM_STEPS  = uint64_t(ROUNDS) * STEPS_PER_ROUND;  // 102,400, FIXED

// Epoch scheduling (docs/MEEPHASH_SPEC.md §epochs). Deliberately identical to Monero's RandomX
// seed-hash schedule (SEEDHASH_EPOCH_BLOCKS / SEEDHASH_EPOCH_LAG) so the inherited seed-height
// plumbing carries over.
constexpr uint64_t EPOCH_LENGTH = 2048;
constexpr uint64_t EPOCH_DELAY  = 64;

// ---------------------------------------------------------------------------------------------
// Errors — explicit, no exceptions cross this boundary.
// ---------------------------------------------------------------------------------------------

enum class Error : int {
    Ok = 0,
    NullArgument,        // a required pointer was null
    InvalidTemplate,     // template blob length 0 or above MAX_TEMPLATE_BYTES
    InvalidDataset,      // dataset handle null or not built
    AllocationFailed,    // out of memory building a dataset or context
    BufferTooSmall,      // caller's output buffer cannot hold the requested hashes
    InvalidCount,        // batch count is 0, or first_nonce + count overflows uint32
    InvalidDifficulty,   // difficulty 0 has no representable target
};

// Human-readable, stable, ASCII. Never null.
const char* error_string(Error e) noexcept;

constexpr size_t MAX_TEMPLATE_BYTES = 1 << 20;  // 1 MiB; a block template is far smaller

// ---------------------------------------------------------------------------------------------
// Epoch helpers (pure functions of height; no I/O).
//
// epochIndex(h)   = max(0, h - EPOCH_DELAY) / EPOCH_LENGTH
// sourceHeight(h) = epochIndex(h) * EPOCH_LENGTH - 1      (undefined when epochIndex == 0)
// epochKey(h)     = epochIndex(h) == 0 ? GENESIS_SEED : blockHash(sourceHeight(h))
//
// The caller supplies the block hash; this library never reads a chain.
// ---------------------------------------------------------------------------------------------

// The program is additionally bound to a DELAYED seed block at height - SEED_BLOCK_DELAY, so the
// miner of the immediately preceding block cannot choose the next program.
constexpr uint64_t SEED_BLOCK_DELAY = 64;

uint64_t epoch_index(uint64_t height) noexcept;

// Returns false when epoch_index(height) == 0, i.e. the chain's genesis seed constant must be used
// instead of a block hash. Otherwise sets *out_height.
bool epoch_source_height(uint64_t height, uint64_t* out_height) noexcept;

// Returns false when height < SEED_BLOCK_DELAY (too shallow; genesis seed is used).
// Otherwise sets *out_height to height - SEED_BLOCK_DELAY.
bool seed_block_height(uint64_t height, uint64_t* out_height) noexcept;

// Reorg semantics. `fork_point` is the height of the highest common ancestor: blocks at heights
// 0..fork_point are shared, heights above it differ. Each input changes iff its source height is
// STRICTLY ABOVE the fork point.
bool epoch_key_changes_on_reorg(uint64_t height, uint64_t fork_point) noexcept;
bool seed_block_changes_on_reorg(uint64_t height, uint64_t fork_point) noexcept;

// Chain lookup callback: return a pointer to the 32-byte block hash at `height`, or nullptr if it
// is unknown. The library never reads a chain itself.
using BlockHashFn = const uint8_t* (*)(uint64_t height, void* ctx);

// Resolve the two chain-derived inputs for `height`. Both fall back to the genesis seed constant
// where the schedule requires it. Return Error::Ok, or Error::NullArgument if the callback could
// not supply a required block hash.
Error resolve_epoch_key(uint64_t height, BlockHashFn get, void* ctx,
                        uint8_t out_key[EPOCH_KEY_SIZE]) noexcept;
Error resolve_seed_block_hash(uint64_t height, BlockHashFn get, void* ctx,
                              uint8_t out_hash[SEED_HASH_SIZE]) noexcept;

// ---------------------------------------------------------------------------------------------
// Dataset — the 32 MiB epoch dataset. Pure function of the epoch key.
//
// MEMORY OWNERSHIP: the Dataset owns its 32 MiB. It is freed when the unique_ptr is destroyed.
// THREAD SAFETY: construction is single-threaded; once built the Dataset is IMMUTABLE and may be
// shared by any number of Hashers on any number of threads concurrently. It must outlive every
// Hasher created from it.
//
// COST: ~350 ms to build. Build once per epoch key and reuse; do NOT rebuild per block or nonce.
// ---------------------------------------------------------------------------------------------

class Dataset {
public:
    ~Dataset();
    Dataset(const Dataset&) = delete;
    Dataset& operator=(const Dataset&) = delete;

    // Build from a 32-byte epoch key. Returns nullptr and sets *err on failure (err may be null).
    static std::unique_ptr<Dataset> create(const uint8_t epoch_key[EPOCH_KEY_SIZE],
                                           Error* err = nullptr) noexcept;

    size_t size_words() const noexcept;
    size_t size_bytes() const noexcept;
    // The epoch key this dataset was built from (32 bytes, owned by the Dataset).
    const uint8_t* epoch_key() const noexcept;

private:
    Dataset();
    struct Impl;
    std::unique_ptr<Impl> p_;
    friend class Hasher;
};

// ---------------------------------------------------------------------------------------------
// Hasher — a per-job hashing context.
//
// The VM program depends on (epochKey, seedBlockHash, blockHeight) and the template blob is
// constant across nonces, so the program is derived ONCE here and the 8 MiB scratchpad is
// allocated ONCE. hash() then performs zero heap allocations per nonce.
//
// MEMORY OWNERSHIP: the Hasher owns its 8 MiB scratchpad and its derived program. It holds a
// non-owning reference to the Dataset, which MUST outlive it.
//
// THREAD SAFETY: a Hasher is NOT thread-safe — it mutates its scratchpad on every hash. Use ONE
// HASHER PER THREAD. Multiple Hashers may share one Dataset concurrently without synchronisation.
// ---------------------------------------------------------------------------------------------

class Hasher {
public:
    ~Hasher();
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;

    // Derive a job context. `template_blob` is the block hashing blob with the nonce field ZEROED;
    // the nonce is supplied separately to hash(). Returns nullptr and sets *err on failure.
    static std::unique_ptr<Hasher> create(const Dataset& dataset,
                                          const uint8_t seed_block_hash[SEED_HASH_SIZE],
                                          uint64_t block_height,
                                          const uint8_t* template_blob, size_t template_len,
                                          Error* err = nullptr) noexcept;

    // One hash. out_hash receives 32 bytes, little-endian 256-bit result. ~16.4 ms.
    Error hash(uint32_t nonce, uint8_t out_hash[HASH_SIZE]) noexcept;

    // Contiguous nonce range [first_nonce, first_nonce + count). Writes count * 32 bytes into
    // out_hashes, which must be at least out_len >= count * 32 bytes.
    //
    // This is a CONVENIENCE loop over hash(), not a parallel or vectorised path: it exists so
    // miners and pools can amortise call overhead, and it produces byte-identical results to
    // calling hash() count times. It is single-threaded; parallelism is the caller's choice, one
    // Hasher per thread.
    Error hash_batch(uint32_t first_nonce, size_t count,
                     uint8_t* out_hashes, size_t out_len) noexcept;

    // Consensus identity of this context, for assertions and logging.
    uint64_t block_height() const noexcept;

private:
    Hasher();
    struct Impl;
    std::unique_ptr<Impl> p_;
};

// ---------------------------------------------------------------------------------------------
// Difficulty / target (docs/MEEPHASH_SPEC.md §10).
// Hashes and targets are 32-byte LITTLE-ENDIAN unsigned 256-bit integers.
//   target = floor((2^256 - 1) / difficulty);  valid iff hash <= target.
// ---------------------------------------------------------------------------------------------

// difficulty 0 is invalid -> returns Error::InvalidDifficulty and leaves out_target untouched.
Error difficulty_to_target(uint64_t difficulty, uint8_t out_target[HASH_SIZE]) noexcept;

// True iff hash <= target (both 32-byte little-endian). Both pointers must be non-null.
bool hash_meets_target(const uint8_t hash[HASH_SIZE], const uint8_t target[HASH_SIZE]) noexcept;

}  // namespace v2
}  // namespace meepow

#endif  // MEEPOW_V2_API_HPP
