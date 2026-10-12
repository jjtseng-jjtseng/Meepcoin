// Little-endian fixed-width helpers, rotates, and portable mulhi64 (spec §0, §7).
// Header-only, no platform intrinsics, no undefined behavior. Included by native and Wasm.
#ifndef MEEPOW_ENDIAN_HPP
#define MEEPOW_ENDIAN_HPP

#include <cstdint>
#include <cstring>

namespace meepow {

// Read/write u64/u32 as little-endian regardless of host byte order. memcpy avoids aliasing UB;
// the byte assembly makes the result independent of host endianness.
inline uint64_t load_u64_le(const uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}
inline uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
inline void store_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);  p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);  p[7] = (uint8_t)(v >> 56);
}
inline void store_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

// Rotates with masked counts; r==0 returns x (the (64-r)&63 guard avoids the UB of >>64).
inline uint64_t rotl64(uint64_t x, unsigned n) {
    unsigned r = n & 63u;
    return (x << r) | (x >> ((64u - r) & 63u));
}
inline uint64_t rotr64(uint64_t x, unsigned n) {
    unsigned r = n & 63u;
    return (x >> r) | (x << ((64u - r) & 63u));
}

// High 64 bits of the 128-bit product a*b — portable reference via four 32x32->64 products
// (spec §7). Consensus-critical; differentially tested against unsigned __int128.
inline uint64_t mulhi64(uint64_t a, uint64_t b) {
    uint64_t aL = a & 0xffffffffULL, aH = a >> 32;
    uint64_t bL = b & 0xffffffffULL, bH = b >> 32;
    uint64_t ll = aL * bL;
    uint64_t lh = aL * bH;
    uint64_t hl = aH * bL;
    uint64_t hh = aH * bH;
    uint64_t cross = (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    return hh + (lh >> 32) + (hl >> 32) + (cross >> 32);
}

// 8-byte little-endian byte shuffle: output byte i = input byte ((sel >> (3*i)) & 7) (spec §6.1).
inline uint64_t byte_shuffle(uint64_t x, uint64_t sel) {
    uint8_t in[8], out[8];
    store_u64_le(in, x);
    for (int i = 0; i < 8; ++i) out[i] = in[(sel >> (3 * i)) & 7u];
    return load_u64_le(out);
}

}  // namespace meepow

#endif  // MEEPOW_ENDIAN_HPP
