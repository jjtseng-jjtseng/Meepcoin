// v2 reference determinism dump: prints known-answer hashes for the v2 candidate (nparents), for
// native/Wasm equivalence and cross-compiler determinism checks.
// Usage: meepow-v2-validate [nparents] [count]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"

using namespace meepow;

int main(int argc, char** argv) {
    unsigned nparents = argc > 1 ? (unsigned)atoi(argv[1]) : 4;
    unsigned count = argc > 2 ? (unsigned)atoi(argv[2]) : 20;
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> ds(V2_SEED_WORDS * 512);
    v2_dataset_fill(ds.data(), ds.size(), epochKey, (int)nparents);
    V1Ctx* c = v2_ctx_create(ds, epochKey, seedHash, 4096, tmpl, 8);
    for (unsigned n = 0; n < count; ++n) {
        uint8_t h[32];
        v2_hash(c, n, h, nullptr, nullptr);
        printf("v2 %u %u ", nparents, n);
        for (int i = 0; i < 32; ++i) printf("%02x", h[i]);
        printf("\n");
    }
    v1_ctx_free(c);
    return 0;
}
