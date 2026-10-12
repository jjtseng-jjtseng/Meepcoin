// MeepHash-W v1 determinism dump: prints known-answer hashes for the finalist (S3, 400 rounds)
// and the v1-fast profile. Native output is committed as vectors_v1.txt and reproduced by Wasm
// (native/Wasm equivalence) and across compilers (ASan/UBSan, gcc/clang).
//
// Usage: meepow-v1-validate [finalist_count] [fast_count]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"

using namespace meepow;

static void dump(const ParamSetV1& ps, const char* label, unsigned count) {
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> ds(ps.dataset_words);
    dataset_fill_B(ds.data(), ps.dataset_words, epochKey, 0);
    V1Ctx* c = v1_ctx_create(ps, ds.data(), ps.dataset_words, epochKey, seedHash, 4096, tmpl, 8);
    for (unsigned n = 0; n < count; ++n) {
        uint8_t h[32];
        v1_hash(c, n, h, nullptr, nullptr);
        printf("%s %u ", label, n);
        for (int i = 0; i < 32; ++i) printf("%02x", h[i]);
        printf("\n");
    }
    v1_ctx_free(c);
}

int main(int argc, char** argv) {
    unsigned fin = argc > 1 ? (unsigned)atoi(argv[1]) : 20;
    unsigned fast = argc > 2 ? (unsigned)atoi(argv[2]) : 100;
    dump(v1_config(50, "v1-finalist", SCRATCH_S3, V1_ROUNDS_50X), "finalist", fin);
    dump(v1_fast(SCRATCH_S3), "fast", fast);
    return 0;
}
