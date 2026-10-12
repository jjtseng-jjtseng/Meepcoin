// MeepHash-W v2 (frozen) — CPU adversarial THROUGHPUT confirmation at a 50% DATASET-memory budget.
//
// A real miner maximizes total H/s across many nonces, not per-hash latency. This harness runs the
// fastest known 50%-dataset-budget attacker (prefix retention) at full device concurrency under ONE
// GLOBAL memory budget — the retained region is a single shared read-only array, so N in-flight
// nonces canNOT each get a private cache. Per-thread costs (traversal stack) are charged to the
// same global budget, so the retained set shrinks as thread count grows.
//
// Compared against the full-memory miner at the SAME thread count on the same hardware.
// Early abort accounts for ALL work spent on abandoned nonces when computing useful H/s.
//
// Usage: meepow-v2-throughput [threads] [hashes_per_config] [abort_ops_threshold] [run_single=1]
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <tuple>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
#include "tmto_strict2.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double secs(clk::time_point a, clk::time_point b) { return std::chrono::duration<double>(b - a).count(); }

static const int NP = 4;
static const size_t STACK_FRAMES_MT = 2048;   // per-thread traversal stack (charged globally)

struct Shared {
    std::vector<uint64_t> prefix;   // ONE global retained region (read-only, shared by all threads)
    std::vector<uint64_t> seed;     // seed region (shared)
    size_t R = 0;
    uint64_t seedconst = 0;
    size_t D = 0;
};

// Build the global shared retained region for a dataset budget, charging T per-thread stacks.
static Shared build_shared(const std::vector<uint64_t>& ds, size_t budget, int T, size_t& global_bytes) {
    Shared s;
    s.D = ds.size();
    s.seedconst = ds[0];
    s.seed.assign(ds.begin(), ds.begin() + V2_SEED_WORDS);
    size_t seed_b = s.seed.size() * 8;
    size_t stacks_b = (size_t)T * STACK_FRAMES_MT * sizeof(Attacker2::Frame);
    size_t avail = budget > seed_b + stacks_b ? budget - seed_b - stacks_b : 0;
    s.R = avail / 8;
    if (s.R > s.D) s.R = s.D;
    s.prefix.assign(s.R, 0);
    for (size_t i = 0; i < s.R; ++i) s.prefix[i] = ds[i];
    global_bytes = seed_b + stacks_b + s.R * 8;
    return s;
}

// Per-thread attacker view onto the shared region (owns only its traversal stack).
static void bind_thread_attacker(Attacker2& a, const Shared& s, const std::vector<uint64_t>& ds) {
    a.rep = REP_PREFIX;
    a.nparents = NP;
    a.D = s.D;
    a.truth = ds.data();           // only used for verification paths; reads go through shared arrays
    a.seedconst = s.seedconst;
    a.prefix = s.R;
    a.keep = 0;
    a.svals_shared = s.prefix.data();
    a.seed_shared = s.seed.data();
    a.stack.assign(STACK_FRAMES_MT, Attacker2::Frame{});
    a.sets = a.ways = a.cap_dyn = 0;
    a.reads = a.hits = a.misses = a.ops = a.max_depth = 0;
}

struct RunResult {
    double wall = 0, hps = 0, useful_hps = 0;
    int completed = 0, aborted = 0, correct = 0;
    uint64_t reads = 0, hits = 0, ops = 0;
    size_t global_bytes = 0;
};

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int T = argc > 1 ? atoi(argv[1]) : (int)std::thread::hardware_concurrency();
    int NH = argc > 2 ? atoi(argv[2]) : 48;
    uint64_t ABORT_OPS = argc > 3 ? (uint64_t)atoll(argv[3]) : 0;  // 0 = no early abort
    // argv[4]: run the T=1 baselines (default 1). They are NOT the gated comparison and the T=1
    // attacker costs NH/9.7 s, which dominates a sustained run; set 0 to skip them.
    int RUN_SINGLE = argc > 4 ? atoi(argv[4]) : 1;

    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    size_t D = V2_SEED_WORDS * 512;                 // 32 MiB
    std::vector<uint64_t> ds(D);
    v2_dataset_fill(ds.data(), D, ek, NP);
    const size_t FULL = D * 8;
    const size_t SCRATCH = 8u << 20;

    printf("== v2 FROZEN — CPU adversarial THROUGHPUT confirmation ==\n");
    printf("dataset %.0f MiB (budget denominator); scratchpad %.0f MiB per in-flight hash (common)\n",
           FULL / 1048576.0, SCRATCH / 1048576.0);
    printf("threads=%d, hashes/config=%d, per-thread stack=%zu KiB (charged to the GLOBAL budget)\n\n",
           T, NH, STACK_FRAMES_MT * sizeof(Attacker2::Frame) / 1024);

    // reference hashes for correctness
    std::vector<uint32_t> nonces(NH);
    for (int i = 0; i < NH; ++i) nonces[i] = 700000u + (uint32_t)i;
    // Reference hashes, computed in parallel. This is a correctness precomputation OUTSIDE every
    // timed region, so threading it changes no measured quantity — it only stops the reference pass
    // (NH x ~16.4 ms single-threaded) from dwarfing the sustained runs it exists to check.
    std::vector<std::array<uint8_t, 32>> ref(NH);
    {
        std::atomic<int> next{0};
        std::vector<std::thread> th;
        for (int t = 0; t < T; ++t) th.emplace_back([&]{
            V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
            int i;
            while ((i = next.fetch_add(1)) < NH) {
                uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr); memcpy(ref[i].data(), h, 32);
            }
            v1_ctx_free(c);
        });
        for (auto& x : th) x.join();
    }

    // ---------- full-memory miner at T threads (the comparison baseline) ----------
    auto run_full = [&](int threads) {
        std::atomic<int> next{0}; std::atomic<int> correct{0};
        std::vector<std::thread> th;
        auto t0 = clk::now();
        for (int t = 0; t < threads; ++t) th.emplace_back([&]{
            V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
            int i;
            while ((i = next.fetch_add(1)) < NH) {
                uint8_t h[32]; v2_hash(c, nonces[i], h, nullptr, nullptr);
                if (memcmp(h, ref[i].data(), 32) == 0) correct.fetch_add(1);
            }
            v1_ctx_free(c);
        });
        for (auto& x : th) x.join();
        RunResult r; r.wall = secs(t0, clk::now()); r.completed = NH; r.correct = correct.load();
        r.hps = NH / r.wall; r.useful_hps = r.hps;
        r.global_bytes = FULL + (size_t)threads * SCRATCH;
        return r;
    };

    // ---------- attacker at T threads, ONE global shared retained region ----------
    auto run_attack = [&](int threads, uint64_t abort_ops) {
        size_t gb = 0;
        Shared s = build_shared(ds, (size_t)(0.50 * FULL), threads, gb);
        std::atomic<int> next{0}, correct{0}, aborted{0}, completed{0};
        std::atomic<uint64_t> areads{0}, ahits{0}, aops{0};
        std::vector<std::thread> th;
        auto t0 = clk::now();
        for (int t = 0; t < threads; ++t) th.emplace_back([&]{
            V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
            Attacker2 a; bind_thread_attacker(a, s, ds);
            // early-abort wrapper: once ops exceed the threshold, reads return fast (garbage) so the
            // nonce is abandoned; ALL time spent on it still counts in the wall clock (useful H/s).
            struct Ctx { Attacker2* a; uint64_t limit; uint64_t base; bool dead; } cx{&a, abort_ops, 0, false};
            auto rd = [](void* p, uint64_t idx) -> uint64_t {
                Ctx* q = (Ctx*)p;
                if (q->dead) return 0;
                // PER-HASH op budget (delta since this hash started), not a cumulative counter.
                if (q->limit && (q->a->ops - q->base) > q->limit) { q->dead = true; return 0; }
                return a2_read(q->a, idx);
            };
            int i;
            while ((i = next.fetch_add(1)) < NH) {
                cx.dead = false;
                cx.base = a.ops;
                uint8_t h[32];
                v2_hash_raw(c, nonces[i], h, rd, &cx);
                if (cx.dead) { aborted.fetch_add(1); }
                else {
                    completed.fetch_add(1);
                    if (memcmp(h, ref[i].data(), 32) == 0) correct.fetch_add(1);
                }
            }
            areads.fetch_add(a.reads); ahits.fetch_add(a.hits); aops.fetch_add(a.ops);
            v1_ctx_free(c);
        });
        for (auto& x : th) x.join();
        RunResult r; r.wall = secs(t0, clk::now());
        r.completed = completed.load(); r.aborted = aborted.load(); r.correct = correct.load();
        r.reads = areads.load(); r.hits = ahits.load(); r.ops = aops.load();
        r.hps = NH / r.wall;                       // attempts/s
        r.useful_hps = r.completed / r.wall;       // completed hashes/s, ALL wasted work included
        r.global_bytes = gb + (size_t)threads * SCRATCH;
        r.global_bytes -= (size_t)threads * SCRATCH;  // dataset-side only; scratch reported separately
        return std::make_pair(r, s.R);
    };

    printf("%-34s %5s %9s %10s %10s %8s %7s %8s %9s\n",
           "config", "thr", "wall s", "H/s", "useful H/s", "correct", "abort%", "hitrate", "ops/read");

    // 1) single-thread baselines (context only — the gate is the T-thread comparison below)
    RunResult a1{}; a1.useful_hps = 0.0;
    if (RUN_SINGLE) {
        RunResult f1 = run_full(1);
        printf("%-34s %5d %9.2f %10.2f %10.2f %7d%% %6.1f%% %8s %9s\n",
               "FULL-memory miner (baseline)", 1, f1.wall, f1.hps, f1.useful_hps, 100 * f1.correct / NH, 0.0, "-", "-");
        size_t R1;
        std::tie(a1, R1) = run_attack(1, 0);
        printf("%-34s %5d %9.2f %10.2f %10.2f %7d%% %6.1f%% %7.1f%% %9.1f\n",
               "attacker 50% ds-budget", 1, a1.wall, a1.hps, a1.useful_hps,
               a1.completed ? 100 * a1.correct / a1.completed : 0, 100.0 * a1.aborted / NH,
               a1.reads ? 100.0 * a1.hits / a1.reads : 0.0, a1.reads ? (double)a1.ops / a1.reads : 0.0);
        printf("     retained %zu words (%.1f%% of D), global dataset-side %.2f MiB\n\n",
               R1, 100.0 * R1 / D, a1.global_bytes / 1048576.0);
    } else {
        printf("(T=1 baselines skipped by request — they are not the gated comparison)\n\n");
    }

    // 2) full device concurrency
    RunResult fT = run_full(T);
    printf("%-34s %5d %9.2f %10.2f %10.2f %7d%% %6.1f%% %8s %9s\n",
           "FULL-memory miner", T, fT.wall, fT.hps, fT.useful_hps, 100 * fT.correct / NH, 0.0, "-", "-");
    auto [aT, RT] = run_attack(T, 0);
    printf("%-34s %5d %9.2f %10.2f %10.2f %7d%% %6.1f%% %7.1f%% %9.1f\n",
           "attacker 50% ds-budget (shared)", T, aT.wall, aT.hps, aT.useful_hps,
           aT.completed ? 100 * aT.correct / aT.completed : 0, 100.0 * aT.aborted / NH,
           aT.reads ? 100.0 * aT.hits / aT.reads : 0.0, aT.reads ? (double)aT.ops / aT.reads : 0.0);
    printf("     retained %zu words (%.1f%% of D), global dataset-side %.2f MiB (%.1f%% of 32 MiB)\n",
           RT, 100.0 * RT / D, aT.global_bytes / 1048576.0, 100.0 * aT.global_bytes / FULL);
    printf("     whole working set: attacker %.0f MiB vs full-memory %.0f MiB (%.1f%%)\n\n",
           (aT.global_bytes + (size_t)T * SCRATCH) / 1048576.0, (FULL + (size_t)T * SCRATCH) / 1048576.0,
           100.0 * (aT.global_bytes + (size_t)T * SCRATCH) / (FULL + (size_t)T * SCRATCH));

    // 3) early-abort nonce selection at full concurrency
    if (ABORT_OPS) {
        auto [ab, Rab] = run_attack(T, ABORT_OPS);
        printf("%-34s %5d %9.2f %10.2f %10.2f %7d%% %6.1f%% %7.1f%% %9.1f\n",
               "attacker + early abort", T, ab.wall, ab.hps, ab.useful_hps,
               ab.completed ? 100 * ab.correct / ab.completed : 0, 100.0 * ab.aborted / NH,
               ab.reads ? 100.0 * ab.hits / ab.reads : 0.0, ab.reads ? (double)ab.ops / ab.reads : 0.0);
        printf("     (useful H/s counts ALL time spent on abandoned nonces)\n");
        printf("\nSLOWDOWN vs full-memory @T=%d : plain %.2fx   early-abort %.2fx   [gate >= 2.0x]\n",
               T, fT.useful_hps / aT.useful_hps, ab.useful_hps > 0 ? fT.useful_hps / ab.useful_hps : 0.0);
    } else {
        printf("SLOWDOWN vs full-memory @T=%d : %.2fx   [gate >= 2.0x]\n", T, fT.useful_hps / aT.useful_hps);
    }
    if (a1.useful_hps > 0.0)
        printf("attacker throughput speedup vs single-hash attacker: %.2fx (1 thread -> %d threads)\n",
               aT.useful_hps / a1.useful_hps, T);
    return 0;
}
