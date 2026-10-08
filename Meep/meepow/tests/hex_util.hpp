// Hex encoding/decoding for test vectors (spec §11).
//
// Encoding conventions (single source of truth for generator and parser):
//   * Byte-array fields (epochKey, seedBlockHash, templateBlob, checkpoints, finalHash,
//     target) are hex of the raw bytes in array order. hash/target byte arrays are the
//     little-endian 256-bit representations, so their hex is LE.
//   * Scalar integer fields (blockHeight u64, nonce u32, difficulty u64) are big-endian,
//     fixed width (16 / 8 / 16 hex chars) — the natural human reading of the number.
// The parser rejects odd-length hex, non-hex characters, and wrong fixed widths.
#ifndef MEEPOW_HEX_UTIL_HPP
#define MEEPOW_HEX_UTIL_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace meepow_test {

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;  // tolerated on input; output is lowercase
    return -1;
}

inline std::string bytes_to_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s[2 * i] = d[p[i] >> 4];
        s[2 * i + 1] = d[p[i] & 15];
    }
    return s;
}

// Decode hex to bytes. If expected_len != 0, the byte length must match exactly (spec §11).
inline std::vector<uint8_t> hex_to_bytes(const std::string& s, size_t expected_len = 0) {
    if (s.size() % 2 != 0) throw std::runtime_error("hex: odd length");
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("hex: invalid character");
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (expected_len && out.size() != expected_len)
        throw std::runtime_error("hex: wrong width");
    return out;
}

// Big-endian fixed-width scalar encoders (spec §11).
inline std::string u64_to_hex_be(uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (56 - 8 * i));
    return bytes_to_hex(b, 8);
}
inline std::string u32_to_hex_be(uint32_t v) {
    uint8_t b[4];
    for (int i = 0; i < 4; ++i) b[i] = (uint8_t)(v >> (24 - 8 * i));
    return bytes_to_hex(b, 4);
}
inline uint64_t hex_be_to_u64(const std::string& s) {
    auto b = hex_to_bytes(s, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}
inline uint32_t hex_be_to_u32(const std::string& s) {
    auto b = hex_to_bytes(s, 4);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | b[i];
    return v;
}

}  // namespace meepow_test

#endif  // MEEPOW_HEX_UTIL_HPP
