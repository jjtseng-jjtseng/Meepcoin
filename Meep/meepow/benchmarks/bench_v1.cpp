// MeepHash-W v1 component-timed benchmark (BENCHMARK_PLAN_V1.md).
// Sweeps 3 scratch-init candidates x 3 VM-work levels, reporting absolute ms and % time in
// seed hashing / scratchpad init / dataset access / VM execution / finalization, plus the
// BLAKE3 vs VM fractions, per-hash p50/p95/p99, and peak RSS. Build-variant aware.
//
// Usage: meepow-bench-v1 [--csv]
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#if defined(__unix__)
#include <sys/resource.h>
#endif

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
static double peak_rss_mib() {
#if defined(__unix__)
    struct rusage ru; getrusage(RUSAGE_SELF, &ru); return ru.ru_maxrss / 1024.0;
#else
    return -1.0;
#endif
}

struct Row {
    const char* mode; uint32_t rounds;
    double seed, scr, scr_b3, ds, vm, fin, total;
    double p50, p95, p99, hps; double rss;
};

static double avg_time(int reps, const std::function<void()>& fn) {
    fn();  // warm
    auto a = clk::now();
    for (int i = 0; i < reps; ++i) fn();
    return ms(a, clk::now()) / reps;
}

int main(int argc, char** argv) {
    bool csv = false;
    for (int i = 1; i < argc; ++i) if (std::string(argv[i]) == "--csv") csv = true;
#if defined(MEEPOW_BLAKE3_PORTABLE_BUILD)
    const char* variant = "portable-blake3";
#else
    const char* variant = "optimized-blake3";
#endif

    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    const uint8_t tmpl[32] = {0};

    // Shared epoch dataset (construction B, 32 MiB) — version-independent, built once.
    std::vector<uint64_t> dataset(V1_DATASET_WORDS);
    dataset_fill_B(dataset.data(), V1_DATASET_WORDS, epochKey, 0);

    struct Cfg { ScratchMode mode; const char* name; uint32_t rounds; };
    ScratchMode modes[3] = {SCRATCH_S1, SCRATCH_S2, SCRATCH_S3};
    const char* mnames[3] = {"S1", "S2", "S3"};
    uint32_t levels[3] = {V1_ROUNDS_10X, V1_ROUNDS_20X, V1_ROUNDS_50X};

    std::vector<Row> rows;
    for (int mi = 0; mi < 3; ++mi) {
        for (int li = 0; li < 3; ++li) {
            ParamSetV1 ps = v1_config((uint8_t)(10 + mi * 3 + li), "v1", modes[mi], levels[li]);
            V1Ctx* c = v1_ctx_create(ps, dataset.data(), V1_DATASET_WORDS, epochKey, seedHash, 4096,
                                     tmpl, sizeof(tmpl));
            // component timing
            int reps = (levels[li] >= V1_ROUNDS_50X) ? 30 : 60;
            uint8_t seed[96], h[32];
            double t_seed = avg_time(reps, [&]{ v1_nonce_seed(c, 12345, seed); });
            v1_nonce_seed(c, 12345, seed);
            double t_scr = avg_time(reps, [&]{ v1_scratch_init(c, 12345, seed); });
            // scratch BLAKE3 portion: time just the seed XOF at the mode's size
            size_t b3bytes = (ps.scratch_mode == SCRATCH_S1) ? ps.s1_seed_words * 8
                             : (ps.scratch_mode == SCRATCH_S2) ? 32
                             : (ps.scratch_words / ps.s3_stride) * 8;
            std::vector<uint8_t> b3buf(b3bytes);
            uint8_t n_le[4] = {1,2,3,4};
            Field bf[2] = {{n_le,4},{seed,96}};
            double t_scr_b3 = avg_time(reps * 3, [&]{ meep_xof(CTX_V1_SCRATCHSEED, ps.id, bf, 2, b3buf.data(), b3bytes); });
            v1_scratch_init(c, 12345, seed);
            VmState vm{}, vm2{};
            double t_vm_total = avg_time(reps, [&]{ v1_run_vm(c, seed, vm, false, nullptr, nullptr); });
            double t_vm_stub  = avg_time(reps, [&]{ v1_run_vm(c, seed, vm2, true, nullptr, nullptr); });
            double t_ds = t_vm_total - t_vm_stub; if (t_ds < 0) t_ds = 0;
            v1_run_vm(c, seed, vm, false, nullptr, nullptr);
            double t_fin = avg_time(reps * 2, [&]{ VmState vf = vm; v1_finalize(c, vf, h); });

            // per-hash distribution (full hash)
            int dn = (levels[li] >= V1_ROUNDS_50X) ? 120 : 300;
            std::vector<double> per; per.reserve(dn);
            v1_hash(c, 0, h, nullptr, nullptr);
            for (int n = 0; n < dn; ++n) { auto a = clk::now(); v1_hash(c, (uint32_t)(n+1), h, nullptr, nullptr); per.push_back(ms(a, clk::now())); }
            std::sort(per.begin(), per.end());
            double sum = 0; for (double x : per) sum += x;
            double meanp = sum / per.size();

            Row r;
            r.mode = mnames[mi]; r.rounds = levels[li];
            r.seed = t_seed; r.scr = t_scr; r.scr_b3 = t_scr_b3; r.ds = t_ds;
            r.vm = t_vm_stub; r.fin = t_fin;
            r.total = per[per.size()/2];  // use measured p50 full hash as total reference
            r.p50 = per[per.size()/2]; r.p95 = per[(size_t)(per.size()*0.95)]; r.p99 = per[(size_t)(per.size()*0.99)];
            r.hps = 1000.0 / meanp; r.rss = peak_rss_mib();
            rows.push_back(r);
            v1_ctx_free(c);
        }
    }

    // Honest classification (strict per BENCHMARK_PLAN_V1.md):
    //   BLAKE3    = seed + BLAKE3 part of scratch init + finalization
    //   SCRATCHexp= non-BLAKE3 scratchpad expansion (NOT counted as VM)
    //   VM+DS     = VM program execution + dataset access (the gated "VM fraction")
    if (csv) {
        printf("variant,mode,rounds,seed_ms,scratch_ms,scratch_b3_ms,dataset_ms,vm_ms,final_ms,"
               "p50_ms,p95_ms,p99_ms,hps,blake3_pct,scratch_exp_pct,vm_ds_pct,rss_mib\n");
        for (auto& r : rows) {
            double tot = r.seed + r.scr + r.ds + r.vm + r.fin;
            double b3 = r.seed + r.scr_b3 + r.fin;
            double sx = r.scr - r.scr_b3;
            double vmds = r.vm + r.ds;
            printf("%s,%s,%u,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.1f,%.1f,%.1f,%.1f\n",
                   variant, r.mode, r.rounds, r.seed, r.scr, r.scr_b3, r.ds, r.vm, r.fin,
                   r.p50, r.p95, r.p99, r.hps, 100*b3/tot, 100*sx/tot, 100*vmds/tot, r.rss);
        }
    } else {
        printf("MeepHash-W v1 component timings [%s], dataset=32MiB construction B\n", variant);
        printf("%-3s %6s | %8s %8s %8s %8s | %7s %7s %7s | %7s %6s %7s %6s\n",
               "mod","rounds","scratch","dataset","vm","final","p50","p95","p99","H/s","BLAKE%","SCRexp%","VM+DS%");
        for (auto& r : rows) {
            double tot = r.seed + r.scr + r.ds + r.vm + r.fin;
            double b3 = r.seed + r.scr_b3 + r.fin;
            double sx = r.scr - r.scr_b3;
            double vmds = r.vm + r.ds;
            printf("%-3s %6u | %8.4f %8.4f %8.4f %8.4f | %7.3f %7.3f %7.3f | %7.1f %6.1f %7.1f %6.1f\n",
                   r.mode, r.rounds, r.scr, r.ds, r.vm, r.fin, r.p50, r.p95, r.p99, r.hps,
                   100*b3/tot, 100*sx/tot, 100*vmds/tot);
        }
    }
    return 0;
}
