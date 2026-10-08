/*
 * meepow-v2-hash — compute one MeepHash-W v2 result from explicit inputs.
 *
 * Exists so block-level consensus vectors can be produced and checked through the PUBLIC v2 API
 * (meepow/v2.hpp) rather than through the daemon. If this tool and the daemon ever disagree on a
 * block, one of them is wrong and the vector catches it.
 *
 * Usage:
 *   meepow-v2-hash <epoch_key_hex64> <seed_block_hash_hex64> <height> <template_hex> <nonce>
 *
 * The template must already have its nonce field zeroed; the nonce is supplied separately. That
 * split is exactly what the frozen spec defines and what the daemon's bridge performs.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "meepow/v2.hpp"

namespace v2 = meepow::v2;

static bool unhex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

static std::string tohex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) { s[i * 2] = d[p[i] >> 4]; s[i * 2 + 1] = d[p[i] & 15]; }
    return s;
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::fprintf(stderr,
            "usage: %s <epoch_key_hex64> <seed_hash_hex64> <height> <template_hex> <nonce>\n",
            argv[0]);
        return 2;
    }
    std::vector<uint8_t> ek, sh, tmpl;
    if (!unhex(argv[1], ek) || ek.size() != 32) { std::fprintf(stderr, "bad epoch key\n"); return 2; }
    if (!unhex(argv[2], sh) || sh.size() != 32) { std::fprintf(stderr, "bad seed hash\n"); return 2; }
    const uint64_t height = strtoull(argv[3], nullptr, 10);
    if (!unhex(argv[4], tmpl) || tmpl.empty()) { std::fprintf(stderr, "bad template\n"); return 2; }
    const uint32_t nonce = (uint32_t)strtoul(argv[5], nullptr, 10);

    v2::Error err = v2::Error::Ok;
    auto ds = v2::Dataset::create(ek.data(), &err);
    if (!ds) { std::fprintf(stderr, "dataset: %s\n", v2::error_string(err)); return 1; }

    auto h = v2::Hasher::create(*ds, sh.data(), height, tmpl.data(), tmpl.size(), &err);
    if (!h) { std::fprintf(stderr, "hasher: %s\n", v2::error_string(err)); return 1; }

    // Optional 6th argument: a difficulty. When present, scan upward from <nonce> until a result
    // meets target = floor((2^256-1)/difficulty), printing "<nonce> <hash>". Used to construct
    // alternate-chain vectors: two distinct valid nonces for the SAME template give two valid
    // sibling blocks at the same height.
    if (argc >= 7) {
        const uint64_t difficulty = strtoull(argv[6], nullptr, 10);
        uint8_t target[32];
        if (v2::difficulty_to_target(difficulty, target) != v2::Error::Ok) {
            std::fprintf(stderr, "bad difficulty\n");
            return 2;
        }
        const uint64_t limit = argc >= 8 ? strtoull(argv[7], nullptr, 10) : 5000000ULL;
        uint8_t out[32];
        for (uint64_t i = 0; i < limit; ++i) {
            const uint32_t n = (uint32_t)(nonce + i);
            if (h->hash(n, out) != v2::Error::Ok) return 1;
            if (v2::hash_meets_target(out, target)) {
                std::printf("%u %s\n", n, tohex(out, 32).c_str());
                return 0;
            }
        }
        std::fprintf(stderr, "no nonce found within %llu tries\n", (unsigned long long)limit);
        return 3;
    }

    uint8_t out[32];
    err = h->hash(nonce, out);
    if (err != v2::Error::Ok) { std::fprintf(stderr, "hash: %s\n", v2::error_string(err)); return 1; }

    std::printf("%s\n", tohex(out, 32).c_str());
    return 0;
}
