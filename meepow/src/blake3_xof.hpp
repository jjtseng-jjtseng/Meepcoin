// meep_xof: the single domain-separated BLAKE3 entry point (spec §1).
// Every hash use frames its input as ALGO_VERSION || PARAM_SET_ID || (LE64(len)||bytes) per field.
#ifndef MEEPOW_BLAKE3_XOF_HPP
#define MEEPOW_BLAKE3_XOF_HPP

#include <cstddef>
#include <cstdint>

extern "C" {
#include "blake3.h"
}
#include "endian.hpp"
#include "meepow/meepow.h"

namespace meepow {

struct Field {
    const uint8_t* p;
    size_t n;
};

// Absorb version + param-set + framed fields, then squeeze out_len bytes (spec §1.1).
inline void meep_xof(const char* context, uint8_t param_set_id, const Field* fields,
                     size_t nfields, uint8_t* out, size_t out_len) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, context);
    const uint8_t hdr[2] = {(uint8_t)MEEPOW_ALGO_VERSION, param_set_id};
    blake3_hasher_update(&h, hdr, 2);
    for (size_t i = 0; i < nfields; ++i) {
        uint8_t len_le[8];
        store_u64_le(len_le, (uint64_t)fields[i].n);
        blake3_hasher_update(&h, len_le, 8);
        if (fields[i].n) blake3_hasher_update(&h, fields[i].p, fields[i].n);
    }
    blake3_hasher_finalize(&h, out, out_len);  // BLAKE3 XOF: arbitrary out_len from offset 0
}

}  // namespace meepow

#endif  // MEEPOW_BLAKE3_XOF_HPP
