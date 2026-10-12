// MeepHash-W v0 native benchmark (allocation-free steady-state via the reusable context).
// Separates one-time dataset init and context creation from repeated per-nonce hashing, and
// reports allocations/hash, peak RSS, and p50/p95/p99 (BENCHMARK_PLAN.md).
//
// Usage: meepow-bench [--param dev|fast] [--hashes N] [--construction A|B] [--csv]
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

#include "meepow/meepow.h"
#include "blake3_xof.hpp"
#include "params.hpp"

// --- global allocation counter (counts every operator new in this program) ------------------
static std::atomic<uint64_t> g_alloc_count{0};
void* operator new(std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

using clk = std::chrono::steady_clock;
static double ms_since(clk::time_point t0) {
    return std::chrono::duration<double, std::milli>(clk::now() - t0).count();
}
static double peak_rss_mib() {
#if defined(__unix__)
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss / 1024.0;  // ru_maxrss is KiB on Linux
#else
    return -1.0;
#endif
}

int main(int argc, char** argv) {
    uint8_t param = MEEPOW_PARAM_DEV;
    uint8_t constr = MEEPOW_DATASET_B;
    int hashes = 300;
    bool csv = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--param" && i + 1 < argc)
            param = (std::string(argv[++i]) == "fast") ? MEEPOW_PARAM_FAST : MEEPOW_PARAM_DEV;
        else if (a == "--construction" && i + 1 < argc)
            constr = (std::string(argv[++i]) == "A") ? MEEPOW_DATASET_A : MEEPOW_DATASET_B;
        else if (a == "--hashes" && i + 1 < argc)
            hashes = atoi(argv[++i]);
        else if (a == "--csv")
            csv = true;
    }
#if defined(MEEPOW_BLAKE3_PORTABLE_BUILD)
    const char* variant = "portable-blake3";
#else
    const char* variant = "optimized-blake3";
#endif

    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    const uint8_t tmpl[32] = {0};

    // --- one-time: dataset init ---
    auto t0 = clk::now();
    meepow_dataset* ds = meepow_dataset_create(param, constr, epochKey);
    double dataset_ms = ms_since(t0);
    if (!ds) { fprintf(stderr, "dataset create failed\n"); return 1; }

    // --- one-time: context creation (program derivation + buffer allocation) ---
    t0 = clk::now();
    meepow_ctx* ctx = meepow_ctx_create(ds, seedHash, 4096, tmpl, sizeof(tmpl));
    double ctx_ms = ms_since(t0);
    if (!ctx) { fprintf(stderr, "ctx create failed\n"); return 1; }

    uint8_t h[32];
    meepow_ctx_hash(ctx, 0, h, nullptr, nullptr);  // warm

    // --- allocations per hash on the reusing path (should be 0) ---
    uint64_t a_before = g_alloc_count.load();
    for (int n = 0; n < 64; ++n) meepow_ctx_hash(ctx, (uint32_t)(n + 1), h, nullptr, nullptr);
    double allocs_per_hash_ctx = (double)(g_alloc_count.load() - a_before) / 64.0;

    // --- allocations per hash on the OLD one-shot path (create+hash+free each call) ---
    a_before = g_alloc_count.load();
    for (int n = 0; n < 64; ++n)
        meepow_hash(ds, seedHash, 4096, tmpl, sizeof(tmpl), (uint32_t)(n + 1), h, nullptr, nullptr);
    double allocs_per_hash_oneshot = (double)(g_alloc_count.load() - a_before) / 64.0;

    // --- steady-state per-hash timing on the reusing path ---
    std::vector<double> per;
    per.reserve(hashes);
    auto tall = clk::now();
    for (int n = 0; n < hashes; ++n) {
        auto th = clk::now();
        meepow_ctx_hash(ctx, (uint32_t)(n + 1), h, nullptr, nullptr);
        per.push_back(ms_since(th));
    }
    double total_ms = ms_since(tall);

    std::sort(per.begin(), per.end());
    double sum = 0;
    for (double x : per) sum += x;
    double mean = sum / per.size();
    double var = 0;
    for (double x : per) var += (x - mean) * (x - mean);
    var /= per.size();
    double sd = std::sqrt(var);
    double p50 = per[per.size() / 2];
    double p95 = per[(size_t)(per.size() * 0.95)];
    double p99 = per[(size_t)(per.size() * 0.99)];
    double hps = 1000.0 * hashes / total_ms;

    // --- verification cost: cold (ctx_create + one hash) vs warm (one ctx_hash) ---
    double warm_verify_ms = p50;
    t0 = clk::now();
    meepow_ctx* vctx = meepow_ctx_create(ds, seedHash, 4096, tmpl, sizeof(tmpl));
    meepow_ctx_hash(vctx, 12345, h, nullptr, nullptr);
    double cold_verify_ms = ms_since(t0);
    meepow_ctx_free(vctx);

    // --- cost breakdown: how much of a hash is the BLAKE3 scratchpad fill? ---
    // The scratchpad fill is one meep_xof producing scratch_words*8 bytes per hash (spec §8 step 3).
    // Timing it in isolation shows how BLAKE3-throughput-bound the hash is.
    const meepow::ParamSet* psb = meepow::param_set(param);
    std::vector<uint8_t> fillbuf(psb->scratch_words * 8);
    uint8_t nseed[96] = {0};
    meepow::Field ff[2] = {{nseed, 4}, {nseed, 96}};
    meep_xof(meepow::CTX_SCRATCHPAD, param, ff, 2, fillbuf.data(), fillbuf.size());  // warm
    int fillreps = 200;
    auto tf = clk::now();
    for (int i = 0; i < fillreps; ++i)
        meep_xof(meepow::CTX_SCRATCHPAD, param, ff, 2, fillbuf.data(), fillbuf.size());
    double fill_ms = ms_since(tf) / fillreps;
    double fill_frac = 100.0 * fill_ms / p50;

    double rss = peak_rss_mib();
    meepow_ctx_free(ctx);
    meepow_dataset_free(ds);

    if (csv) {
        printf("variant,param,constr,dataset_init_ms,ctx_create_ms,hashes,hps,mean_ms,sd_ms,"
               "p50_ms,p95_ms,p99_ms,p99_over_p50,warm_verify_ms,cold_verify_ms,"
               "allocs_per_hash_ctx,allocs_per_hash_oneshot,peak_rss_mib\n");
        printf("%s,%s,%c,%.2f,%.4f,%d,%.2f,%.4f,%.4f,%.4f,%.4f,%.4f,%.3f,%.4f,%.4f,%.2f,%.2f,%.1f\n",
               variant, param == MEEPOW_PARAM_FAST ? "fast" : "dev", constr == MEEPOW_DATASET_A ? 'A' : 'B',
               dataset_ms, ctx_ms, hashes, hps, mean, sd, p50, p95, p99, p99 / p50, warm_verify_ms,
               cold_verify_ms, allocs_per_hash_ctx, allocs_per_hash_oneshot, rss);
    } else {
        printf("MeepHash-W v0 bench [%s, param=%s, construction=%c]\n", variant,
               param == MEEPOW_PARAM_FAST ? "fast" : "dev", constr == MEEPOW_DATASET_A ? 'A' : 'B');
        printf("  one-time  dataset init : %.2f ms\n", dataset_ms);
        printf("  one-time  ctx create   : %.4f ms (program derivation + buffers)\n", ctx_ms);
        printf("  steady    hashrate     : %.1f H/s  (%d hashes)\n", hps, hashes);
        printf("  per-hash  mean/sd      : %.4f / %.4f ms (cv=%.2f%%)\n", mean, sd, 100 * sd / mean);
        printf("  per-hash  p50/p95/p99  : %.4f / %.4f / %.4f ms (p99/p50=%.3f)\n", p50, p95, p99,
               p99 / p50);
        printf("  verify    warm/cold    : %.4f / %.4f ms\n", warm_verify_ms, cold_verify_ms);
        printf("  allocs/hash ctx/oneshot: %.2f / %.2f\n", allocs_per_hash_ctx, allocs_per_hash_oneshot);
        printf("  peak RSS               : %.1f MiB\n", rss);
        printf("  scratchpad BLAKE3 fill : %.4f ms/hash = %.1f%% of per-hash time\n", fill_ms, fill_frac);
    }
    return 0;
}
