// Bounded companion to the strict TMTO confirmation: measures the 25% budget rows and the
// cheap-nonce grinding repeatability with a small nonce count, so the (very slow) deep-recompute
// attacks finish in bounded time. Same strict attacker, same hard total-memory accounting.
//
// Usage: meepow-v2-tmto-quick [nonces]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
#include "tmto_strict.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }
static double pctl(std::vector<double>& s, double p) { return s[(size_t)((s.size() - 1) * p)]; }

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int N = argc > 1 ? atoi(argv[1]) : 4;
    const int NP = 4;
    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    size_t DW = V2_SEED_WORDS * 512;
    std::vector<uint64_t> ds(DW);
    v2_dataset_fill(ds.data(), DW, ek, NP);
    V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
    const size_t FULL = DW * 8;

    std::vector<uint32_t> nonces(N);
    for (int i = 0; i < N; ++i) nonces[i] = 200000u + (uint32_t)i;
    std::vector<std::vector<uint8_t>> ref(N, std::vector<uint8_t>(32));
    std::vector<double> rp;
    for (int i = 0; i < N; ++i) { uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); memcpy(ref[i].data(), h, 32); }
    for (int i = 0; i < N; ++i) { auto a = clk::now(); uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); rp.push_back(ms(a, clk::now())); }
    std::sort(rp.begin(), rp.end());
    double ref50 = pctl(rp, 0.5);
    printf("== v2 N=4 strict TMTO (bounded companion), nonces=%d, ref p50=%.2f ms ==\n", N, ref50);
    printf("%-18s %7s %6s %6s %7s %8s | %8s %8s %8s\n","attack","total%","words%","corr","hitrate","ops/rd","min x","p50 x","max x");

    auto run = [&](const char* name, double frac, StrictPolicy pol) {
        StrictAttacker a;
        strict_init(a, ds, NP, (size_t)(frac * FULL), pol, 4096);
        { uint8_t h[32]; for (int i = 0; i < 3; ++i) v2_hash_raw(c, 900000u + i, h, strict_read, &a); }
        int corr = 0; std::vector<double> per;
        uint64_t r0 = a.reads, h0 = a.hits, o0 = a.ops;
        for (int i = 0; i < N; ++i) {
            uint8_t h[32]; auto s = clk::now();
            v2_hash_raw(c, nonces[i], h, strict_read, &a);
            per.push_back(ms(s, clk::now()));
            if (memcmp(h, ref[i].data(), 32) == 0) corr++;
        }
        uint64_t rd = a.reads - r0, hi = a.hits - h0, op = a.ops - o0;
        std::vector<double> sl; for (double x : per) sl.push_back(x / ref50);
        std::sort(sl.begin(), sl.end());
        printf("%-18s %6.1f%% %5.1f%% %5d%% %6.1f%% %8.1f | %8.1f %8.1f %8.1f\n", name,
               100.0 * a.total_bytes() / FULL, 100.0 * a.retained_fraction(), 100 * corr / N,
               rd ? 100.0 * hi / rd : 0.0, rd ? (double)op / rd : 0.0, sl.front(), pctl(sl, 0.5), sl.back());
    };
    run("25% LRU", 0.25, SP_LRU);
    run("25% LFU", 0.25, SP_LFU);

    // cheap-nonce grinding at the 75% budget (fast enough for a repeatability test)
    printf("\n-- cheap-nonce grinding (75%% budget, LRU, cross-nonce cache) --\n");
    {
        StrictAttacker a; strict_init(a, ds, NP, (size_t)(0.75 * FULL), SP_LRU, 4096);
        uint8_t h[32];
        int G = N * 4;
        std::vector<uint32_t> gn(G); for (int i = 0; i < G; ++i) gn[i] = 300000u + (uint32_t)i;
        for (int i = 0; i < 3; ++i) v2_hash_raw(c, 900000u + i, h, strict_read, &a);
        auto pass = [&](std::vector<double>& out) {
            out.clear();
            for (int i = 0; i < G; ++i) { auto s = clk::now(); v2_hash_raw(c, gn[i], h, strict_read, &a); out.push_back(ms(s, clk::now())); }
        };
        std::vector<double> A, B; pass(A); pass(B);
        double ma = 0, mb = 0; for (int i = 0; i < G; ++i) { ma += A[i]; mb += B[i]; }
        ma /= G; mb /= G;
        double num = 0, da = 0, db = 0;
        for (int i = 0; i < G; ++i) { num += (A[i]-ma)*(B[i]-mb); da += (A[i]-ma)*(A[i]-ma); db += (B[i]-mb)*(B[i]-mb); }
        double r = (da > 0 && db > 0) ? num / std::sqrt(da * db) : 0.0;
        std::vector<size_t> idx(G); for (int i = 0; i < G; ++i) idx[i] = i;
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y){ return A[x] < A[y]; });
        std::vector<double> Bs = B; std::sort(Bs.begin(), Bs.end());
        size_t topk = G / 4 ? G / 4 : 1; double rank = 0;
        for (size_t i = 0; i < topk; ++i) rank += 100.0 * (std::lower_bound(Bs.begin(), Bs.end(), B[idx[i]]) - Bs.begin()) / G;
        rank /= topk;
        std::vector<double> As = A; std::sort(As.begin(), As.end());
        printf("nonces=%d  cross-pass r=%.3f  A-cheapest-25%% land at avg %.1f-th pct in B (50=noise)\n", G, r, rank);
        printf("cheapest/median = %.3f, p5/median = %.3f (how much a lucky nonce could save)\n",
               As.front()/As[G/2], As[G/20]/As[G/2]);
    }
    v1_ctx_free(c);
    return 0;
}
