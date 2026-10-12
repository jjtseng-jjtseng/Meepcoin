// MeepHash-W v2 dataset experiment (BENCHMARK_PLAN_V2). Builds a v2 dataset candidate and runs the
// TMTO suite (every storage backend) and the corrected store-elision suite (every scratchpad
// policy) THROUGH THE SHARED CONSENSUS HASH — reference and adversaries call the same v2_hash, so
// correctness is meaningful and there is no transcribed loop.
//
// Usage: meepow-v2-experiment [nparents] [tmto_hashes] [--param dev|fast]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "dataset_backend.hpp"
#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
#include "params_v1.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }
static double medianv(std::vector<double> v){ std::sort(v.begin(),v.end()); return v[v.size()/2]; }

static const uint64_t READ_CAP = 60000;  // per-read reconstruction op cap (bounds worst-case time)

int main(int argc, char** argv) {
    int nparents = argc > 1 ? atoi(argv[1]) : 3;
    int tmto_hashes = argc > 2 ? atoi(argv[2]) : 4;
    size_t DW = V2_SEED_WORDS * 512;  // default; overridden below by param
    for (int i = 1; i < argc; ++i) if (std::string(argv[i]) == "--param" && i+1<argc && std::string(argv[i+1])=="fast") DW = 0x8000;
    if (DW != 0x8000) DW = 0x400000;  // DEV 32 MiB

    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};

    printf("== v2 DATASET EXPERIMENT: nparents=%d, dataset=%.1f MiB ==\n", nparents, DW*8.0/1048576.0);
    std::vector<uint64_t> ds(DW);
    auto t0 = clk::now();
    v2_dataset_fill(ds.data(), DW, epochKey, nparents);
    double fill_ms = ms(t0, clk::now());
    printf("dataset construction: %.1f ms (gate <= 3000 ms)\n", fill_ms);

    V1Ctx* c = v2_ctx_create(ds, epochKey, seedHash, 4096, tmpl, sizeof(tmpl));

    // Reference: full backend (fn-ptr, apples-to-apples with reduced backends).
    V2DsBackend full; v2_backend_init(full, ds, nparents); full.is_full = true;
    // determinism: dsb=null (direct) vs full backend must match, and be deterministic.
    { uint8_t a[32], b[32]; v2_hash(c,0,a,nullptr,nullptr); v2_hash(c,0,b,&full,nullptr);
      printf("reference determinism (direct==full-backend): %s\n", memcmp(a,b,32)==0?"OK":"MISMATCH"); }

    int refN = 40; std::vector<double> refper; std::vector<std::vector<uint8_t>> refhash(tmto_hashes, std::vector<uint8_t>(32));
    for (int n=0;n<tmto_hashes;++n){ uint8_t h[32]; v2_hash(c,(uint32_t)n,h,&full,nullptr); memcpy(refhash[n].data(),h,32); }
    for (int n=0;n<refN;++n){ auto a=clk::now(); uint8_t h[32]; v2_hash(c,(uint32_t)n,h,&full,nullptr); refper.push_back(ms(a,clk::now())); }
    double ref_ms = medianv(refper);
    printf("reference per-hash (full backend) p50 = %.4f ms\n\n", ref_ms);

    // profile access counts for adversarial placement — on DISJOINT nonces (1000..1007) from the
    // TMTO test set (0..tmto_hashes-1), since dataset accesses are nonce-dependent: a real attacker
    // cannot profile the exact future nonces. Retaining a hot-set from other nonces should NOT help.
    std::vector<uint32_t> counts(DW,0);
    { V2DsBackend prof; v2_backend_init(prof, ds, nparents); prof.is_full=true; prof.counts=&counts;
      uint8_t h[32]; for(int n=1000;n<1008;++n) v2_hash(c,(uint32_t)n,h,&prof,nullptr); }

    // Reduced backends: present bitmap = the retained subset; per-hash memo models a smart attacker
    // who recomputes each missing word once/hash with O(1) structures. Exact hashes (no op cap).
    auto build_stride=[&](V2DsBackend& b, size_t k){ v2_backend_init(b,ds,nparents); v2_backend_enable_memo(b);
        for(size_t w=V2_SEED_WORDS;w<DW;w+=k) b.present[w]=1; v2_backend_count_retained(b); };
    auto build_random=[&](V2DsBackend& b, double frac){ v2_backend_init(b,ds,nparents); v2_backend_enable_memo(b);
        std::mt19937_64 rng(99); for(size_t w=V2_SEED_WORDS;w<DW;++w) if((rng()>>11)*(1.0/9007199254740992.0)<frac) b.present[w]=1;
        v2_backend_count_retained(b); };
    auto build_adv=[&](V2DsBackend& b, double frac){ v2_backend_init(b,ds,nparents); v2_backend_enable_memo(b);
        std::vector<std::pair<uint32_t,size_t>> cs; for(size_t w=V2_SEED_WORDS;w<DW;++w) if(counts[w]) cs.push_back({counts[w],w});
        std::sort(cs.begin(),cs.end(),[](auto&x,auto&y){return x.first>y.first;});
        size_t keep=(size_t)(frac*(DW-V2_SEED_WORDS)); for(size_t i=0;i<keep && i<cs.size();++i) b.present[cs[i].second]=1;
        v2_backend_count_retained(b); };
    auto build_recompute=[&](V2DsBackend& b){ v2_backend_init(b,ds,nparents); v2_backend_enable_memo(b); v2_backend_count_retained(b); };

    printf("%-16s %10s %11s %7s %9s %9s %9s\n","backend","persist","peak-mem","corr","per-hash","slowdown","ops/rd");
    auto run_tmto=[&](const char* name, V2DsBackend& b){
        int correct=0; for(int n=0;n<tmto_hashes;++n){ uint8_t h[32]; v2_hash(c,(uint32_t)n,h,&b,nullptr); if(memcmp(h,refhash[n].data(),32)==0) correct++; }
        std::vector<double> per; uint64_t reads=0,opsum=0;
        for(int n=0;n<tmto_hashes;++n){ auto a=clk::now(); uint8_t h[32]; v2_hash(c,(uint32_t)n,h,&b,nullptr); per.push_back(ms(a,clk::now())); reads+=b.reads; opsum+=b.ops; }
        double phash=medianv(per);
        double persist=b.retained_words*8.0/1048576.0;
        double peak=(b.retained_words+b.peak_cache)*8.0/1048576.0;  // persistent + transient memo
        printf("%-16s %7.2f MiB %8.2f MiB %6d%% %7.1f ms %8.1fx %9.2f\n", name,
               persist, peak, 100*correct/tmto_hashes, phash, phash/ref_ms, reads? (double)opsum/reads:0.0);
    };
    printf("(smart attacker: per-hash memo; 'retained' = PERSISTENT store; ops/read = amortized recompute)\n");
    { V2DsBackend b; build_random(b,0.75); run_tmto("random-75%", b); }
    { V2DsBackend b; build_stride(b,2); run_tmto("stride-2 (~50%)", b); }
    { V2DsBackend b; build_random(b,0.50); run_tmto("random-50%", b); }
    { V2DsBackend b; build_stride(b,4); run_tmto("stride-4 (~25%)", b); }
    { V2DsBackend b; build_random(b,0.25); run_tmto("random-25%", b); }
    { V2DsBackend b; build_adv(b,0.50); run_tmto("adv-place-50%", b); }
    { V2DsBackend b; build_adv(b,0.25); run_tmto("adv-place-25%", b); }
    { V2DsBackend b; build_recompute(b); run_tmto("recompute-seed", b); }

    // ---- store-elision on the shared VM (scratchpad backends) ----
    printf("\n-- store-elision (shared VM, scratchpad backends) --\n");
    printf("%-16s %10s %10s\n","sp policy","agreement","speedup");
    std::vector<uint8_t> ro(32); // reference (no sp backend) per nonce
    int seN=200; std::vector<std::vector<uint8_t>> seref(seN, std::vector<uint8_t>(32));
    for(int n=0;n<seN;++n){ uint8_t h[32]; v2_hash(c,(uint32_t)n,h,nullptr,nullptr); memcpy(seref[n].data(),h,32);}
    auto refroot=[&](){ auto a=clk::now(); uint8_t h[32]; for(int n=0;n<seN;++n) v2_hash(c,(uint32_t)n,h,nullptr,nullptr); return ms(a,clk::now())/seN; };
    double se_ref_ms=refroot();
    // dead-store oracle read-set (per nonce) — computed by a profiling read-set is complex; we use
    // SP_FULL as the agreement anchor and measure timing for each policy.
    auto run_se=[&](const char* name, SpPolicy pol){
        V2SpBackend sp; sp.policy=pol; sp.keepNum=1; sp.keepDen=2;
        int agree=0; auto a=clk::now();
        for(int n=0;n<seN;++n){ uint8_t h[32]; v2_hash(c,(uint32_t)n,h,nullptr,&sp); if(memcmp(h,seref[n].data(),32)==0) agree++; }
        double t=ms(a,clk::now())/seN;
        printf("%-16s %8d%% %9.2f%%\n", name, 100*agree/seN, 100*(se_ref_ms-t)/se_ref_ms);
    };
    run_se("full", SP_FULL);
    run_se("no_store", SP_NO_STORE);
    run_se("write_buffer", SP_WRITE_BUFFER);
    run_se("partial_50", SP_PARTIAL);
    run_se("recompute", SP_RECOMPUTE);
    printf("[full must be 100%% agreement (shared VM sanity); lossy policies change the hash]\n");

    v1_ctx_free(c);
    return 0;
}
