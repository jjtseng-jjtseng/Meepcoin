// MeepHash-W v2 (N=4) FINAL TMTO CONFIRMATION under strict total-memory accounting.
//
//  * Hard total-memory budgets: every attacker byte counted (values, tags, meta, index array,
//    traversal stack). A row is labeled "50%" only if TOTAL peak bytes <= 50% of the full backend.
//  * Cross-nonce (persistent) caching: LRU / LFU / static / hybrid, cache NOT cleared between hashes.
//  * Slowdown DISTRIBUTIONS over a large pre-registered nonce sample (min/p1/p5/p25/p50/p95/max),
//    plus a cheap-nonce grinding repeatability test (are the cheapest nonces repeatably cheap?).
//  * Iterative reconstruction, preallocated buffers, zero per-read allocation.
//
// Usage: meepow-v2-tmto-strict [nonces] [order: seq|rand]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
#include "tmto_strict.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }
static double pct(std::vector<double>& s, double p) { return s[(size_t)((s.size() - 1) * p)]; }

static const int NPARENTS = 4;

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);  // unbuffered: show progress as it happens
    int NONCES = argc > 1 ? atoi(argv[1]) : 60;
    std::string order = argc > 2 ? argv[2] : "seq";

    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    size_t DW = V2_SEED_WORDS * 512;  // 32 MiB
    std::vector<uint64_t> ds(DW);
    auto t0 = clk::now();
    v2_dataset_fill(ds.data(), DW, epochKey, NPARENTS);
    double fill_ms = ms(t0, clk::now());
    V1Ctx* c = v2_ctx_create(ds, epochKey, seedHash, 4096, tmpl, sizeof(tmpl));

    const size_t FULL_BYTES = DW * 8;  // full backend's comparable total memory
    printf("== v2 N=%d FINAL TMTO CONFIRMATION (strict total-memory accounting) ==\n", NPARENTS);
    printf("dataset %.1f MiB, construction %.0f ms, nonces=%d, order=%s\n",
           FULL_BYTES / 1048576.0, fill_ms, NONCES, order.c_str());

    // nonce sample (pre-registered): sequential range, or a fixed pseudo-random permutation
    std::vector<uint32_t> nonces(NONCES);
    for (int i = 0; i < NONCES; ++i) nonces[i] = 100000u + (uint32_t)i;
    if (order == "rand") { std::mt19937 rng(4242); std::shuffle(nonces.begin(), nonces.end(), rng); }

    // reference: full dataset, direct reads
    std::vector<std::vector<uint8_t>> ref(NONCES, std::vector<uint8_t>(32));
    std::vector<double> refper;
    for (int i = 0; i < NONCES; ++i) { uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); memcpy(ref[i].data(), h, 32); }
    for (int i = 0; i < NONCES; ++i) { auto a = clk::now(); uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); refper.push_back(ms(a, clk::now())); }
    std::vector<double> rs = refper; std::sort(rs.begin(), rs.end());
    double ref_p50 = pct(rs, 0.50);
    printf("reference (full, %.2f MiB) per-hash p50 = %.3f ms\n\n", FULL_BYTES / 1048576.0, ref_p50);

    printf("%-22s %8s %8s %7s %6s %6s %7s %7s | slowdown distribution (x ref p50)\n",
           "attack", "persist", "temp", "total%", "words%", "corr", "hitrate", "ops/rd");
    printf("%-22s %8s %8s %7s %6s %6s %7s %7s | %6s %6s %6s %6s %6s %6s %6s\n",
           "", "MiB", "MiB", "offull", "cached", "", "", "", "min", "p1", "p5", "p25", "p50", "p95", "max");

    struct Row { std::string name; double slow_p50, slow_min, slow_p5; double totalpct; int corr; };
    std::vector<Row> rows;

    auto run = [&](const char* name, double budget_frac, StrictPolicy pol,
                   const std::vector<uint32_t>* pin) {
        StrictAttacker a;
        size_t budget = (size_t)(budget_frac * FULL_BYTES);
        strict_init(a, ds, NPARENTS, budget, pol, 4096);
        if (pin) strict_pin(a, *pin, 4);  // half the ways pinned to the trained hot set
        // warm the cache over a disjoint warmup range (cross-nonce learning is allowed)
        { uint8_t h[32]; for (int i = 0; i < 6; ++i) v2_hash_raw(c, 900000u + i, h, strict_read, &a); }
        // correctness + timing over the nonce sample; cache PERSISTS across nonces
        int corr = 0;
        std::vector<double> per;
        uint64_t reads0 = a.reads, hits0 = a.hits, ops0 = a.ops;
        for (int i = 0; i < NONCES; ++i) {
            uint8_t h[32];
            auto s = clk::now();
            v2_hash_raw(c, nonces[i], h, strict_read, &a);
            per.push_back(ms(s, clk::now()));
            if (memcmp(h, ref[i].data(), 32) == 0) corr++;
        }
        uint64_t reads = a.reads - reads0, hits = a.hits - hits0, ops = a.ops - ops0;
        std::vector<double> sl;
        for (double x : per) sl.push_back(x / ref_p50);
        std::sort(sl.begin(), sl.end());
        double totalpct = 100.0 * a.total_bytes() / FULL_BYTES;
        printf("%-22s %8.2f %8.3f %6.1f%% %5.1f%% %5d%% %6.1f%% %7.2f | %6.2f %6.2f %6.2f %6.2f %6.2f %6.2f %6.2f\n",
               name, a.persistent_bytes() / 1048576.0, a.temp_bytes() / 1048576.0, totalpct,
               100.0 * a.retained_fraction(), 100 * corr / NONCES,
               reads ? 100.0 * hits / reads : 0.0, reads ? (double)ops / reads : 0.0,
               sl.front(), pct(sl, 0.01), pct(sl, 0.05), pct(sl, 0.25), pct(sl, 0.50), pct(sl, 0.95), sl.back());
        rows.push_back({name, pct(sl, 0.50), sl.front(), pct(sl, 0.05), totalpct, 100 * corr / NONCES});
    };

    // ---- adversarial placement training (large disjoint training set) ----
    std::vector<uint32_t> counts32;
    {
        std::vector<uint32_t> cnt(DW, 0);
        V2DsBackend prof; v2_backend_init(prof, ds, NPARENTS); prof.is_full = true; prof.counts = &cnt;
        uint8_t h[32];
        for (int i = 0; i < 24; ++i) v2_hash(c, 700000u + i, h, &prof, nullptr);  // disjoint training
        std::vector<std::pair<uint32_t, uint32_t>> hot;
        uint64_t nz = 0, multi = 0;
        for (size_t w = V2_SEED_WORDS; w < DW; ++w) { if (cnt[w]) { hot.push_back({cnt[w], (uint32_t)w}); nz++; if (cnt[w] > 1) multi++; } }
        std::sort(hot.begin(), hot.end(), [](auto& x, auto& y) { return x.first > y.first; });
        for (auto& p : hot) counts32.push_back(p.second);
        printf("[placement training: 24 disjoint nonces touched %llu distinct words; %llu touched >1x "
               "(global hot-set share %.2f%%)]\n\n", (unsigned long long)nz, (unsigned long long)multi,
               100.0 * multi / (double)(DW - V2_SEED_WORDS));
    }

    run("75% LRU",              0.75, SP_LRU, nullptr);
    run("50% LRU",              0.50, SP_LRU, nullptr);
    run("50% LFU",              0.50, SP_LFU, nullptr);
    run("50% static+LRU(hot)",  0.50, SP_STATIC_LRU, &counts32);
    run("25% LRU",              0.25, SP_LRU, nullptr);
    run("25% LFU",              0.25, SP_LFU, nullptr);
    run("25% static+LRU(hot)",  0.25, SP_STATIC_LRU, &counts32);

    // ---- cheap-nonce grinding: are the cheapest nonces repeatably cheap? ----
    printf("\n-- cheap-nonce grinding (50%% LRU): repeatability of the low-cost tail --\n");
    {
        StrictAttacker a; strict_init(a, ds, NPARENTS, (size_t)(0.50 * FULL_BYTES), SP_LRU, 4096);
        uint8_t h[32];
        for (int i = 0; i < 6; ++i) v2_hash_raw(c, 900000u + i, h, strict_read, &a);
        auto pass = [&](std::vector<double>& out) {
            out.clear();
            for (int i = 0; i < NONCES; ++i) { auto s = clk::now(); v2_hash_raw(c, nonces[i], h, strict_read, &a); out.push_back(ms(s, clk::now())); }
        };
        std::vector<double> A, B; pass(A); pass(B);
        // correlation + where pass-A's cheapest 10% land in pass B
        double ma = 0, mb = 0; for (size_t i = 0; i < A.size(); ++i) { ma += A[i]; mb += B[i]; }
        ma /= A.size(); mb /= B.size();
        double num = 0, da = 0, db = 0;
        for (size_t i = 0; i < A.size(); ++i) { num += (A[i]-ma)*(B[i]-mb); da += (A[i]-ma)*(A[i]-ma); db += (B[i]-mb)*(B[i]-mb); }
        double r = num / std::sqrt(da * db);
        std::vector<size_t> idx(A.size()); for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y) { return A[x] < A[y]; });
        std::vector<double> Bs = B; std::sort(Bs.begin(), Bs.end());
        size_t topk = A.size() / 10 ? A.size() / 10 : 1;
        double avgrank = 0;
        for (size_t i = 0; i < topk; ++i) {
            double t = B[idx[i]];
            avgrank += 100.0 * (std::lower_bound(Bs.begin(), Bs.end(), t) - Bs.begin()) / B.size();
        }
        avgrank /= topk;
        std::vector<double> As = A; std::sort(As.begin(), As.end());
        printf("cross-pass r = %.3f (r~0 => cheap nonces are NOISE, not selectable)\n", r);
        printf("pass-A cheapest 10%% land at avg %.1f-th percentile in pass B (50 => noise)\n", avgrank);
        printf("cheapest/median slowdown ratio = %.3f (how much a lucky nonce saves)\n", As.front() / As[As.size()/2]);
    }

    printf("\n[gates: 75%% >=1.3x, 50%% >=2.0x, 25%% >=4.0x, correct hashes, and total%% <= label]\n");
    v1_ctx_free(c);
    return 0;
}
