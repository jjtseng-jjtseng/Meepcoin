/*
 * MeepCoin proof-of-work entry point — MeepHash-W v2 (frozen).
 *
 * Replaces RandomX (rx_slow_hash) as the consensus hash. This header is the ONLY PoW interface the
 * daemon uses; mining and verification both route through it, so there is exactly one
 * implementation and no second copy to keep in sync.
 *
 * The algorithm itself lives in the meepcoin repository under meepow/ and is consumed as a
 * library (meepow_v2), NOT vendored or reimplemented here.
 *
 * EXPERIMENTAL DEVNET. Coins have no value. Not for mainnet.
 */
#ifndef MEEP_HASH_H
#define MEEP_HASH_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Compute one MeepHash-W v2 block PoW.
 *
 *   seedhash : 32-byte epoch seed (Monero's existing 2048/64-lagged seed hash). MeepCoin feeds
 *              this as BOTH the epoch key and the delayed-seed-block input -- see
 *              docs/DEVNET_PARAMETERS.md for why that choice is made and what it costs.
 *   height   : block height (enters the frozen program derivation).
 *   data/len : the block hashing blob. The 4-byte nonce field is located by parsing the header
 *              varints, zeroed to form the template, and passed to the algorithm separately --
 *              exactly the (template-with-nonce-zeroed, nonce) split the spec defines.
 *   result_hash : 32-byte little-endian output.
 */
void meep_slow_hash(const char *seedhash, uint64_t height,
                    const void *data, size_t length, char *result_hash);

/* Release this thread's cached hashing context (8 MiB scratchpad). Safe to call repeatedly. */
void meep_slow_hash_free_state(void);

#if defined(__cplusplus)
}
#endif

#endif /* MEEP_HASH_H */
