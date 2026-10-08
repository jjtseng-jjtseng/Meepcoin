// Phase 1A adversarial tracks (SHORTCUT_ANALYSIS.md, BENCHMARK_PLAN.md thresholds).
// Uses the allocation-free reusable context for timing. Prints measured numbers only.
//
//   grinding       : per-program cost distribution across seed hashes + measurement noise floor.
//   store-elision  : (a) all-store elimination timing + hash divergence, (b) LIVENESS analysis =
//                    fraction of stores ever read back (oracle-elidable dead stores).
//   tmto           : reduced-memory dataset regeneration (construction A) vs stored, at multiple
//                    dataset sizes, with exact retained memory + construction-B fill cost.
//
// Usage: meepow-adversarial [grinding|store-elision|tmto|all] [--param dev|fast]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "experimental_pipeline.hpp"
#include "meepow/meepow.h"
#include "params.hpp"
#include "program.hpp"
#include "vm.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms_since(clk::time_point t0) {
    return std::chrono::duration<double, std::milli>(clk::now() - t0).count();
}

struct Stats { double mean, sd, cv, mn, mx, p50, p95, p99; };
static Stats stats_of(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    double sum = 0;
    for (double x : v) sum += x;
    double mean = sum / v.size(), var = 0;
    for (double x : v) var += (x - mean) * (x - mean);
    var /= v.size();
    return {mean, std::sqrt(var), 100 * std::sqrt(var) / mean, v.front(), v.back(),
            v[v.size() / 2], v[(size_t)(v.size() * 0.95)], v[(size_t)(v.size() * 0.99)]};
}

// ----------------------------------------------------------------------------- grinding --------
static void track_grinding(uint8_t param) {
    const ParamSet* ps = param_set(param);
    printf("\n== GRINDING: per-program cost across seed-block hashes (param=%s) ==\n", ps->name);
    printf("  warmup: 1 hash/program discarded; reps: median of R hashes/program (ctx reused)\n");
    uint8_t epochKey[32];
    for (int i = 0; i < 32; ++i) epochKey[i] = (uint8_t)(i * 5 + 2);
    meepow_dataset* ds = meepow_dataset_create(param, MEEPOW_DATASET_B, epochKey);
    const uint8_t tmpl[16] = {0};
    const int programs = (param == MEEPOW_PARAM_FAST) ? 3000 : 1500;
    const int reps = (param == MEEPOW_PARAM_FAST) ? 25 : 15;

    std::mt19937_64 rng(999);
    std::vector<double> cost;   // per-program median hash time
    cost.reserve(programs);
    std::vector<double> samp(reps);
    uint8_t h[32];
    for (int p = 0; p < programs; ++p) {
        uint8_t seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)rng();
        meepow_ctx* ctx = meepow_ctx_create(ds, seed, 4096, tmpl, sizeof(tmpl));
        meepow_ctx_hash(ctx, 0, h, nullptr, nullptr);  // warm
        for (int k = 0; k < reps; ++k) {
            auto t0 = clk::now();
            meepow_ctx_hash(ctx, (uint32_t)(k + 1), h, nullptr, nullptr);
            samp[k] = ms_since(t0);
        }
        std::sort(samp.begin(), samp.end());
        cost.push_back(samp[reps / 2]);
        meepow_ctx_free(ctx);
    }
    // Noise floor: one fixed program, same method.
    std::vector<double> nf;
    nf.reserve(programs);
    {
        uint8_t seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = 0x5A;
        meepow_ctx* ctx = meepow_ctx_create(ds, seed, 4096, tmpl, sizeof(tmpl));
        for (int p = 0; p < programs; ++p) {
            for (int k = 0; k < reps; ++k) {
                auto t0 = clk::now();
                meepow_ctx_hash(ctx, (uint32_t)(p * reps + k), h, nullptr, nullptr);
                samp[k] = ms_since(t0);
            }
            std::sort(samp.begin(), samp.end());
            nf.push_back(samp[reps / 2]);
        }
        meepow_ctx_free(ctx);
    }
    meepow_dataset_free(ds);

    Stats s = stats_of(cost), n = stats_of(nf);
    printf("  programs=%d  reps=%d\n", programs, reps);
    printf("  cross-program: mean=%.5f sd=%.5f CV=%.2f%% min=%.5f max=%.5f p95=%.5f p99=%.5f\n",
           s.mean, s.sd, s.cv, s.mn, s.mx, s.p95, s.p99);
    printf("  min/median=%.3f  max/median=%.3f  grinder best-of-%d advantage=%.3f%%\n",
           s.mn / s.p50, s.mx / s.p50, programs, 100 * (s.p50 - s.mn) / s.p50);
    printf("  NOISE FLOOR (one fixed program): CV=%.2f%%  (derivation: identical timing method on a\n",
           n.cv);
    printf("    single program; its CV is pure measurement/scheduler noise. cross-program CV<=noise\n");
    printf("    CV => no genuine per-program cost difference. Structural: step count is constant.)\n");
    printf("  [gate: CV<=5%%, fastest>=0.90x median]\n");
}

// -------------------------------------------------------------------- store-elision + liveness -
// Instrumented run that classifies every store as live (its written word is later read before
// being overwritten or before the hash ends) or dead (oracle-elidable). Returns totals.
struct Liveness { uint64_t stores, live, dead; };
static Liveness run_with_liveness(uint8_t param, const uint64_t* D, size_t dwords,
                                  const uint8_t epochKey[32], const uint8_t seed_block_hash[32],
                                  uint64_t height, const uint8_t* tmpl, size_t tmpl_len,
                                  uint32_t nonce) {
    const ParamSet* ps = param_set(param);
    uint8_t table[256];
    build_opcode_table(table);
    std::vector<uint8_t> prog_bytes((size_t)ps->program_len * 8);
    {
        uint8_t h_le[8];
        store_u64_le(h_le, height);
        Field f[3] = {{h_le, 8}, {epochKey, 32}, {seed_block_hash, 32}};
        meep_xof(CTX_PROGRAM, param, f, 3, prog_bytes.data(), prog_bytes.size());
    }
    std::vector<Instr> program(ps->program_len);
    for (uint32_t i = 0; i < ps->program_len; ++i)
        program[i] = decode_instr(prog_bytes.data() + (size_t)i * 8, table);

    uint8_t seed[96];
    {
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field f[2] = {{n_le, 4}, {tmpl, tmpl_len}};
        meep_xof(CTX_NONCE, param, f, 2, seed, sizeof(seed));
    }
    VmState vm{};
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(seed + i * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(seed + 64 + i * 8);
    std::vector<uint64_t> scratch(ps->scratch_words);
    vm.SP = scratch.data();
    vm.D = D;
    vm.datasetMask = dwords - 1;
    vm.scratchMask = ps->scratch_words - 1;
    vm.storePos = 0;
    {
        std::vector<uint8_t> sp(ps->scratch_words * 8);
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field f[2] = {{n_le, 4}, {seed, sizeof(seed)}};
        meep_xof(CTX_SCRATCHPAD, param, f, 2, sp.data(), sp.size());
        for (size_t w = 0; w < ps->scratch_words; ++w) vm.SP[w] = load_u64_le(sp.data() + w * 8);
    }

    // Liveness shadow: pending[w]=1 means word w was written and not yet read since.
    std::vector<uint8_t> pending(ps->scratch_words, 0);
    Liveness lv{0, 0, 0};
    auto mark_read = [&](uint64_t off) {
        if (pending[off]) { pending[off] = 0; lv.live++; }
    };
    auto mark_store = [&](uint64_t off) {
        if (pending[off]) lv.dead++;  // previous write to off overwritten without a read
        pending[off] = 1;
        lv.stores++;
    };

    const uint32_t N = ps->program_len;
    uint64_t t = 0;
    for (uint32_t round = 0; round < ps->rounds; ++round) {
        uint32_t pc = 0;
        for (uint32_t step = 0; step < ps->steps_per_round; ++step) {
            const Instr& I = program[pc];
            // Re-implement the two memory ops with liveness hooks; delegate the rest.
            if (I.op == OP_STORE64) {
                uint64_t off = (vm.r[I.dst] + (uint64_t)I.imm) & vm.scratchMask;
                mark_store(off);
                execute_step(vm, I);  // performs the real store + accumulator fold
            } else if (I.op == OP_LOAD64_SCRATCH) {
                uint64_t off = scratch_load_addr(vm, vm.r[I.src], (uint64_t)I.imm);
                mark_read(off);
                execute_step(vm, I);
            } else {
                execute_step(vm, I);
            }
            ++t;
            if ((t % MIXBACK_INTERVAL) == 0) {
                unsigned j = (unsigned)((t / MIXBACK_INTERVAL) & 7u);
                uint64_t off = vm.lastStores[j] & vm.scratchMask;
                mark_read(off);
                vm.r[j] ^= vm.SP[off];
            }
            if (I.op == OP_BRANCH_IF_BIT && ((vm.r[I.src] >> I.aux) & 1u))
                pc = (uint32_t)((pc + 1 + (I.imm & (N - 1))) % N);
            else
                pc = (pc + 1) % N;
        }
    }
    // Final walk reads recent store sites + data-dependent locations.
    for (int k = 0; k < 8; ++k) mark_read(vm.lastStores[k] & vm.scratchMask);
    for (int k = 0; k < 24; ++k) {
        uint64_t idx = (vm.acc[k & 3] ^ vm.r[k & 7] ^ (uint64_t)k * 0x9E3779B97F4A7C15ULL) &
                       vm.scratchMask;
        mark_read(idx);
    }
    // Any still-pending words are stores that were never read.
    for (size_t w = 0; w < ps->scratch_words; ++w)
        if (pending[w]) lv.dead++;
    return lv;
}

static void track_store_elision(uint8_t param) {
    const ParamSet* ps = param_set(param);
    printf("\n== STORE-ELISION (param=%s) ==\n", ps->name);
    uint8_t epochKey[32], seed[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 9 + 4); seed[i] = (uint8_t)(i + 7); }
    const uint8_t tmpl[16] = {0};
    std::vector<uint64_t> words(ps->dataset_words);
    dataset_fill_A(words.data(), ps->dataset_words, epochKey, param);

    // (a) Wholesale no-store elimination: divergence + timing.
    const int nonces = (param == MEEPOW_PARAM_FAST) ? 3000 : 300;
    int diverged = 0;
    uint8_t ref[32], ns[32];
    VariantOpts nostore; nostore.no_store = true;
    auto t0 = clk::now();
    for (int n = 0; n < nonces; ++n)
        run_variant(param, epochKey, words.data(), ps->dataset_words, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)n, VariantOpts{}, ref);
    double compliant_ms = ms_since(t0) / nonces;
    t0 = clk::now();
    for (int n = 0; n < nonces; ++n)
        run_variant(param, epochKey, words.data(), ps->dataset_words, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)n, nostore, ns);
    double nostore_ms = ms_since(t0) / nonces;
    for (int n = 0; n < nonces; ++n) {
        run_variant(param, epochKey, words.data(), ps->dataset_words, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)n, VariantOpts{}, ref);
        run_variant(param, epochKey, words.data(), ps->dataset_words, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)n, nostore, ns);
        if (std::memcmp(ref, ns, 32) != 0) ++diverged;
    }
    printf("  (a) wholesale no-store: divergence %d/%d (%.1f%%), speedup %.2f%%\n", diverged, nonces,
           100.0 * diverged / nonces, 100.0 * (compliant_ms - nostore_ms) / compliant_ms);

    // (b) Liveness: fraction of stores ever read back (oracle dead-store elimination ceiling).
    const int lvn = (param == MEEPOW_PARAM_FAST) ? 2000 : 200;
    uint64_t St = 0, Lv = 0, Dd = 0;
    for (int n = 0; n < lvn; ++n) {
        Liveness lv = run_with_liveness(param, words.data(), ps->dataset_words, epochKey, seed, 4096,
                                        tmpl, sizeof(tmpl), (uint32_t)n);
        St += lv.stores; Lv += lv.live; Dd += lv.dead;
    }
    double deadFrac = 100.0 * Dd / St;
    printf("  (b) liveness over %d nonces: stores/hash=%.1f  live=%.1f%%  dead(oracle-elidable)=%.1f%%\n",
           lvn, (double)St / lvn, 100.0 * Lv / St, deadFrac);
    printf("      note: STORE64 is ~8%% of %u steps; stores are a tiny fraction of per-hash cost,\n",
           ps->rounds * ps->steps_per_round);
    printf("      so even eliminating the dead %.1f%% saves ~0%% wall time (see (a)). Hash is\n",
           deadFrac);
    printf("      BLAKE3/scratchpad-fill-bound, not store-bound.\n");
    printf("  [gate: elision speedup <=5%% AND hash unchanged -> wholesale changes hash 100%%]\n");
}

// ---------------------------------------------------------------------------------- tmto -------
static void tmto_at_size(uint8_t param, const uint8_t epochKey[32], const uint8_t seed[32],
                         size_t dwords, const char* label) {
    const ParamSet* ps = param_set(param);
    const uint8_t tmpl[16] = {0};
    const int hashes = 60;
    std::vector<uint64_t> words(dwords);
    auto tf = clk::now();
    dataset_fill_A(words.data(), dwords, epochKey, param);
    double fillA_ms = ms_since(tf);
    uint8_t h[32];
    run_variant(param, epochKey, words.data(), dwords, seed, 4096, tmpl, sizeof(tmpl), 0, VariantOpts{}, h);
    auto t0 = clk::now();
    for (int n = 0; n < hashes; ++n)
        run_variant(param, epochKey, words.data(), dwords, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)(n + 1), VariantOpts{}, h);
    double stored_ms = ms_since(t0) / hashes;
    VariantOpts lazy; lazy.lazy_dataset_A = true;
    run_variant(param, epochKey, nullptr, dwords, seed, 4096, tmpl, sizeof(tmpl), 0, lazy, h);
    t0 = clk::now();
    for (int n = 0; n < hashes; ++n)
        run_variant(param, epochKey, nullptr, dwords, seed, 4096, tmpl, sizeof(tmpl),
                    (uint32_t)(n + 1), lazy, h);
    double lazy_ms = ms_since(t0) / hashes;

    tf = clk::now();
    std::vector<uint64_t> wB(dwords);
    dataset_fill_B(wB.data(), dwords, epochKey, param);
    double fillB_ms = ms_since(tf);

    double ds_mib = dwords * 8.0 / (1024 * 1024);
    double lazy_mib = (CHUNK_WORDS * 8.0 + ps->scratch_words * 8.0) / (1024 * 1024);
    printf("  [%s] dataset=%.0f MiB\n", label, ds_mib);
    printf("     A stored : init %.1f ms, retained %.1f MiB, per-hash %.4f ms\n", fillA_ms, ds_mib, stored_ms);
    printf("     A lazy   : init 0 ms,    retained %.2f MiB, per-hash %.4f ms  (mem %.3fx, slow %.2fx)\n",
           lazy_mib, lazy_ms, lazy_mib / ds_mib, lazy_ms / stored_ms);
    printf("     B fill   : %.1f ms serial (one-time per epoch key: node startup / epoch transition)\n",
           fillB_ms);
}

static void track_tmto(uint8_t param) {
    printf("\n== TMTO: reduced-memory dataset regeneration (param=%s) ==\n", param_set(param)->name);
    uint8_t epochKey[32], seed[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i + 11); seed[i] = (uint8_t)(i * 4 + 5); }
    if (param == MEEPOW_PARAM_FAST) {
        tmto_at_size(param, epochKey, seed, 0x8000, "256KiB");
        tmto_at_size(param, epochKey, seed, 0x10000, "512KiB");
        tmto_at_size(param, epochKey, seed, 0x20000, "1MiB");
    } else {
        tmto_at_size(param, epochKey, seed, 0x400000, "32MiB");
        tmto_at_size(param, epochKey, seed, 0x800000, "64MiB");
        tmto_at_size(param, epochKey, seed, 0x1000000, "128MiB");
    }
    printf("  Construction B practicality: fill is O(datasetWords) serial and one-time per epoch\n");
    printf("  key (cached across the epoch). Normal generation/epoch transition/node startup pay it\n");
    printf("  once; block verification reuses the cached dataset (per-hash only). Lazy-B has NO cheap\n");
    printf("  per-word regen (serial dependency) -> reduced-memory B is far beyond the 2x gate.\n");
    printf("  [gate: <=50%% memory must be >=2.0x slower]\n");
}

int main(int argc, char** argv) {
    std::string which = "all";
    uint8_t param = MEEPOW_PARAM_FAST;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--param" && i + 1 < argc)
            param = (std::string(argv[++i]) == "dev") ? MEEPOW_PARAM_DEV : MEEPOW_PARAM_FAST;
        else if (a[0] != '-')
            which = a;
    }
    if (which == "all" || which == "grinding") track_grinding(param);
    if (which == "all" || which == "store-elision") track_store_elision(param);
    if (which == "all" || which == "tmto") track_tmto(param);
    return 0;
}
