// Epoch and delayed-seed-block rules (spec §9). Pure arithmetic + chain lookups via callback,
// so the standalone library stays chain-agnostic; Phase 3 supplies the real block-hash source.
#ifndef MEEPOW_EPOCH_HPP
#define MEEPOW_EPOCH_HPP

#include <cstdint>
#include <cstring>

#include "params.hpp"

namespace meepow {

// Prototype genesis seed: 32 zero bytes. Phase 3 replaces with the real genesis block hash.
constexpr uint8_t GENESIS_SEED[32] = {0};

inline uint64_t epoch_index(uint64_t h) {
    return (h <= EPOCH_DELAY) ? 0 : (h - EPOCH_DELAY) / EPOCH_LENGTH;
}

// Height whose block hash seeds the epoch key. Valid only when epoch_index(h) > 0.
inline uint64_t epoch_source_height(uint64_t h) {
    return epoch_index(h) * EPOCH_LENGTH - 1;
}

// True when height h draws its epoch key from GENESIS_SEED (epoch 0).
inline bool epoch_uses_genesis(uint64_t h) { return epoch_index(h) == 0; }

// True when height h draws its seed-block hash from GENESIS_SEED (too shallow for a delayed block).
inline bool seed_uses_genesis(uint64_t h) { return h < SEED_BLOCK_DELAY; }
inline uint64_t seed_block_height(uint64_t h) { return h - SEED_BLOCK_DELAY; }

// Reorg semantics via fork_point = height of the highest common ancestor (the last block both
// chains share). Blocks at heights 0..fork_point are identical; heights > fork_point differ.
// The source block therefore changes iff its height is strictly above the fork point (spec §9).
inline bool reorg_changes_epoch_key(uint64_t h, uint64_t fork_point) {
    if (epoch_uses_genesis(h)) return false;  // genesis seed is immutable
    return epoch_source_height(h) > fork_point;
}
inline bool reorg_changes_seed_block(uint64_t h, uint64_t fork_point) {
    if (seed_uses_genesis(h)) return false;
    return seed_block_height(h) > fork_point;
}

// Chain lookup: return a pointer to the 32-byte block hash at `height`, or nullptr if unknown.
using BlockHashFn = const uint8_t* (*)(uint64_t height, void* ctx);

// Resolve the 32-byte epoch key for height h into out[32]. Returns false if a required block
// hash is unavailable.
inline bool resolve_epoch_key(uint64_t h, BlockHashFn get, void* ctx, uint8_t out[32]) {
    if (epoch_uses_genesis(h)) {
        std::memcpy(out, GENESIS_SEED, 32);
        return true;
    }
    const uint8_t* bh = get(epoch_source_height(h), ctx);
    if (!bh) return false;
    std::memcpy(out, bh, 32);
    return true;
}

inline bool resolve_seed_block_hash(uint64_t h, BlockHashFn get, void* ctx, uint8_t out[32]) {
    if (seed_uses_genesis(h)) {
        std::memcpy(out, GENESIS_SEED, 32);
        return true;
    }
    const uint8_t* bh = get(seed_block_height(h), ctx);
    if (!bh) return false;
    std::memcpy(out, bh, 32);
    return true;
}

}  // namespace meepow

#endif  // MEEPOW_EPOCH_HPP
