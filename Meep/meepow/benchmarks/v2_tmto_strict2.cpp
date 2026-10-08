// MeepHash-W v2 (N=4) — CORRECTED strict TMTO: budget-SATURATING attackers across multiple cache
// representations. Reports byte-level accounting, budget utilization, word coverage, metadata
// bytes/word, correctness, hit rate, ops/read, p50/p95/p99, slowdown — per representation.
// The official gate uses the FASTEST valid attacker at each budget.
//
// Usage: meepow-v2-tmto-strict2 [max_nonces] [time_budget_s_per_row]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
#include "tmto_strict2.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }
static double pctl(std::vector<double>& s, double p) { return s.empty() ? 0 : s[(size_t)((s.size() - 1) * p)]; }

struct Best { double slow; std::string rep; double util; };

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int MAXN = argc > 1 ? atoi(argv[1]) : 24;
    double TBUDGET = argc > 2 ? atof(argv[2]) : 45.0;  // seconds per row (adaptive sample size)
    int ONLY = argc > 3 ? atoi(argv[3]) : 0;           // 0=all, 1=75%, 2=50%, 3=25%
    int SKIP_NONCE = argc > 4 ? atoi(argv[4]) : 0;     // 1 = skip the nonce-selection section
    int ONLYREP = argc > 5 ? atoi(argv[5]) : -1;       // -1 = all reps, else CacheRep value
    const int NP = 4;

    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    size_t D = V2_SEED_WORDS * 512;                 // 4,194,304 words = 32 MiB
    std::vector<uint64_t> ds(D);
    auto t0 = clk::now();
    v2_dataset_fill(ds.data(), D, ek, NP);
    double fill_ms = ms(t0, clk::now());
    V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
    const size_t FULL = D * 8;

    // ---- reference (full memory) ----
    std::vector<uint32_t> nonces(MAXN);
    for (int i = 0; i < MAXN; ++i) nonces[i] = 500000u + (uint32_t)i;   // pre-registered sample
    std::vector<std::vector<uint8_t>> ref(MAXN, std::vector<uint8_t>(32));
    std::vector<double> rp;
    for (int i = 0; i < MAXN; ++i) { uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); memcpy(ref[i].data(), h, 32); }
    for (int i = 0; i < MAXN; ++i) { auto a = clk::now(); uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); rp.push_back(ms(a, clk::now())); }
    std::sort(rp.begin(), rp.end());
    double ref50 = pctl(rp, 0.5);

    printf("== v2 N=4 CORRECTED strict TMTO (budget-saturating attackers) ==\n");
    printf("dataset D=%zu words = %.0f MiB; construction %.0f ms; reference p50 = %.2f ms (n=%d)\n",
           D, FULL / 1048576.0, fill_ms, ref50, MAXN);
    printf("scratchpad (common to reference and attacker, not charged to the dataset budget) = 8 MiB\n\n");

    Best best[3] = {{1e18, "", 0}, {1e18, "", 0}, {1e18, "", 0}};
    double budgets[3] = {0.75, 0.50, 0.25};
    const char* blabel[3] = {"75%", "50%", "25%"};
    CacheRep reps[8] = {REP_PREFIX, REP_PREFIX_MEMO, REP_STATIC, REP_HYBRID,
                        REP_DIRECT, REP_SA2, REP_LFU8, REP_SA8};

    printf("%-4s %-24s %10s %10s %6s %10s %6s %7s %6s %7s %9s %8s %8s %8s %9s %4s\n",
           "budg", "representation", "allowed B", "actual B", "util%", "words", "words%", "meta/w",
           "corr", "hitrate", "ops/read", "p50 ms", "p95 ms", "p99 ms", "slowdown", "n");

    if (ONLY == 4) {  // nonce-analysis-only mode: prefix @ 50% (the measured fastest attacker)
        best[1].rep = rep_name(REP_PREFIX); best[1].slow = 0; best[1].util = 100.0;
    }
    for (int bi = 0; bi < 3; ++bi) {
        if (ONLY && bi != ONLY - 1) continue;
        size_t budget = (size_t)(budgets[bi] * FULL);
        for (CacheRep rep : reps) {
            if (ONLYREP >= 0 && (int)rep != ONLYREP) continue;
            Attacker2 a;
            a2_init(a, ds, NP, budget, rep);
            // warm on disjoint nonces (cross-nonce learning allowed; cache persists)
            { uint8_t h[32]; for (int i = 0; i < 3; ++i) v2_hash_raw(c, 800000u + i, h, a2_read, &a); }
            // adaptive sample size: stop at MAXN or when the time budget is exhausted
            std::vector<double> per; int corr = 0, n = 0;
            uint64_t r0 = a.reads, h0 = a.hits, o0 = a.ops;
            auto tstart = clk::now();
            for (int i = 0; i < MAXN; ++i) {
                uint8_t h[32];
                auto s = clk::now();
                v2_hash_raw(c, nonces[i], h, a2_read, &a);
                per.push_back(ms(s, clk::now()));
                if (memcmp(h, ref[i].data(), 32) == 0) corr++;
                ++n;
                if (ms(tstart, clk::now()) / 1000.0 > TBUDGET) break;
            }
            uint64_t rd = a.reads - r0, hi = a.hits - h0, op = a.ops - o0;
            std::vector<double> s = per; std::sort(s.begin(), s.end());
            double p50 = pctl(s, 0.5), p95 = pctl(s, 0.95), p99 = pctl(s, 0.99);
            double slow = p50 / ref50;
            printf("%-4s %-24s %10zu %10zu %5.1f%% %10zu %5.1f%% %6.2f %5d%% %6.1f%% %9.1f %8.2f %8.2f %8.2f %8.1fx %4d\n",
                   blabel[bi], rep_name(rep), budget, a.total_bytes(),
                   100.0 * a.total_bytes() / budget, a.words_held(),
                   100.0 * a.words_held() / D, a.meta_bytes_per_word(),
                   n ? 100 * corr / n : 0, rd ? 100.0 * hi / rd : 0.0, rd ? (double)op / rd : 0.0,
                   p50, p95, p99, slow, n);
            if (corr == n && n > 0 && slow < best[bi].slow) {
                best[bi].slow = slow; best[bi].rep = rep_name(rep);
                best[bi].util = 100.0 * a.total_bytes() / budget;
            }
        }
        printf("\n");
    }

    printf("FASTEST VALID ATTACKER per budget (official gate basis):\n");
    const double gate[3] = {1.3, 2.0, 4.0};
    for (int bi = 0; bi < 3 && ONLY != 4; ++bi) {
        if (ONLY && bi != ONLY - 1) continue;
        printf("  %-4s %-24s util %.1f%%  slowdown %.1fx   gate >=%.1fx  -> %s\n", blabel[bi],
               best[bi].rep.c_str(), best[bi].util, best[bi].slow, gate[bi],
               best[bi].slow >= gate[bi] ? "PASS" : "FAIL");
    }
    if (SKIP_NONCE) { v1_ctx_free(c); return 0; }

    // ---- nonce-selection analysis with the FASTEST 50%-budget attacker ----
    printf("\n-- nonce selection / cheap-nonce grinding, FASTEST 50%% attacker (%s) --\n",
           best[1].rep.c_str());
    {
        CacheRep fastest = REP_STATIC;
        for (CacheRep r : reps) if (best[1].rep == rep_name(r)) fastest = r;
        Attacker2 a; a2_init(a, ds, NP, (size_t)(0.50 * FULL), fastest);
        uint8_t h[32];
        for (int i = 0; i < 3; ++i) v2_hash_raw(c, 800000u + i, h, a2_read, &a);
        int G = MAXN;
        std::vector<uint32_t> gn(G); for (int i = 0; i < G; ++i) gn[i] = 600000u + (uint32_t)i;
        auto pass = [&](std::vector<double>& out) {
            out.clear();
            for (int i = 0; i < G; ++i) { auto s = clk::now(); v2_hash_raw(c, gn[i], h, a2_read, &a); out.push_back(ms(s, clk::now())); }
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
        size_t topk = (size_t)(G / 4) ? (size_t)(G / 4) : 1; double rank = 0;
        for (size_t i = 0; i < topk; ++i) rank += 100.0 * (std::lower_bound(Bs.begin(), Bs.end(), B[idx[i]]) - Bs.begin()) / G;
        rank /= topk;
        std::vector<double> As = A; std::sort(As.begin(), As.end());
        printf("n=%d  slowdown min %.1fx p1 %.1fx p5 %.1fx p25 %.1fx p50 %.1fx p95 %.1fx max %.1fx\n",
               G, As.front()/ref50, pctl(As,0.01)/ref50, pctl(As,0.05)/ref50, pctl(As,0.25)/ref50,
               pctl(As,0.50)/ref50, pctl(As,0.95)/ref50, As.back()/ref50);
        printf("cross-pass r = %.3f (0 => cheap nonces are noise)   A-cheapest-25%% land at %.1f-th pct in B\n", r, rank);
        printf("cheapest/median = %.3f   p5/median = %.3f\n", As.front()/As[G/2], pctl(As,0.05)/As[G/2]);
    }
    v1_ctx_free(c);
    return 0;
}
