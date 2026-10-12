// Host-side verification of the EXACT CUDA core (v2_cuda_core.cuh compiled as plain C++).
// Proves the standalone GPU implementation reproduces the committed vectors_v2.txt byte-for-byte
// BEFORE any GPU run. This is also an independent reimplementation cross-check of frozen v2:
// it shares no code with meepow/src — only the specification.
//
// Build: g++ -O2 -std=c++17 -DMEEP_HOST_ONLY v2_cuda_hosttest.cpp -o v2_cuda_hosttest
// Run:   ./v2_cuda_hosttest ../vectors/vectors_v2.txt
#define MEEP_HOST_ONLY
#include "v2_cuda_core.cuh"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    const char* vpath = argc > 1 ? argv[1] : "../vectors/vectors_v2.txt";
    FILE* f = fopen(vpath, "rb");
    if (!f) { printf("cannot open %s\n", vpath); return 2; }

    MeepKeys K;
    meep_init_keys(&K);

    // Frozen v2 test inputs (identical to meepow/benchmarks/v2_validate.cpp).
    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint64_t HEIGHT = 4096;

    printf("building 32 MiB v2 dataset (standalone implementation)...\n");
    std::vector<uint64_t> D(DATASET_WORDS);
    meep_v2_build_dataset(&K, ek, D.data());

    std::vector<MInstr> prog(PROG_LEN);
    {
        std::vector<uint8_t> pb(PROG_LEN * 8);
        uint8_t fb[256];
        meep_derive_program(&K, ek, sh, HEIGHT, prog.data(), pb.data(), fb);
    }

    std::vector<uint64_t> SP(SCRATCH_WORDS);
    std::vector<uint8_t> framebuf(1024);

    int total = 0, ok = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char tag[8]; unsigned np, nonce; char hex[80];
        if (sscanf(line, "%7s %u %u %72s", tag, &np, &nonce, hex) != 4) continue;
        if (strcmp(tag, "v2") != 0) continue;
        ++total;
        uint8_t out[32];
        meep_v2_hash_one(&K, D.data(), prog.data(), tmpl, 8, nonce, SP.data(), 1, framebuf.data(), out);
        char got[65];
        for (int i = 0; i < 32; ++i) sprintf(got + i * 2, "%02x", out[i]);
        got[64] = 0;
        if (strcmp(got, hex) == 0) ++ok;
        else if (total - ok <= 3)
            printf("MISMATCH nonce %u:\n  got %s\n  exp %s\n", nonce, got, hex);
    }
    fclose(f);
    printf("\nEXACT-CUDA host verification: %d/%d vectors reproduced byte-for-byte\n", ok, total);
    if (ok == total && total > 0) { printf("RESULT: PASS — GPU core is exact\n"); return 0; }
    printf("RESULT: FAIL — do NOT run performance measurements\n");
    return 1;
}
