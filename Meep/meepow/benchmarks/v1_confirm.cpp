// Focused confirmation bench for the FROZEN v1 candidate (S3 x 400). Prints per-hash times so an
// external driver can pool across sessions and compute confidence intervals (CONFIRMATION_PLAN_V1).
//
// Usage: meepow-v1-confirm --warmup W --timed N [--dump FILE]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;

int main(int argc, char** argv) {
    int warmup = 200, timed = 1000;
    std::string dump;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--warmup" && i + 1 < argc) warmup = atoi(argv[++i]);
        else if (a == "--timed" && i + 1 < argc) timed = atoi(argv[++i]);
        else if (a == "--dump" && i + 1 < argc) dump = argv[++i];
    }
#if defined(MEEPOW_BLAKE3_PORTABLE_BUILD)
    const char* variant = "portable";
#else
    const char* variant = "optimized";
#endif

    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    std::vector<uint64_t> ds(V1_DATASET_WORDS);
    dataset_fill_B(ds.data(), V1_DATASET_WORDS, epochKey, 0);
    ParamSetV1 ps = v1_config(50, "v1-finalist", SCRATCH_S3, V1_ROUNDS_50X);
    V1Ctx* c = v1_ctx_create(ps, ds.data(), V1_DATASET_WORDS, epochKey, seedHash, 4096, tmpl, sizeof(tmpl));

    uint8_t h[32];
    for (int i = 0; i < warmup; ++i) v1_hash(c, (uint32_t)i, h, nullptr, nullptr);
    std::vector<double> per(timed);
    for (int n = 0; n < timed; ++n) {
        auto a = clk::now();
        v1_hash(c, (uint32_t)(warmup + n), h, nullptr, nullptr);
        per[n] = std::chrono::duration<double, std::milli>(clk::now() - a).count();
    }
    v1_ctx_free(c);

    if (!dump.empty()) {
        FILE* f = fopen(dump.c_str(), "w");
        for (double x : per) fprintf(f, "%.5f\n", x);
        fclose(f);
    }
    std::vector<double> s = per;
    std::sort(s.begin(), s.end());
    double sum = 0; for (double x : s) sum += x;
    printf("variant=%s warmup=%d timed=%d mean=%.4f p50=%.4f p95=%.4f p99=%.4f min=%.4f\n",
           variant, warmup, timed, sum / s.size(), s[s.size()/2], s[(size_t)(s.size()*0.95)],
           s[(size_t)(s.size()*0.99)], s.front());
    return 0;
}
