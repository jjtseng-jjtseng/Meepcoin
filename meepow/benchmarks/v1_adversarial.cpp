// MeepHash-W v1 adversarial tracks for the finalist (S3 x 400). Grinding cost variance + noise
// floor, store-elision liveness, and multi-size construction-B (dataset init + per-hash).
//
// Usage: meepow-v1-adversarial
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"
#include "vm.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static ParamSetV1 finalist() { return v1_config(50, "v1-finalist", SCRATCH_S3, V1_ROUNDS_50X); }

// ---- grinding: per-program (seed hash) cost variance vs measurement noise floor ---------------
static void grinding(const std::vector<uint64_t>& ds) {
    printf("\n== v1 GRINDING (finalist S3x400) ==\n");
    ParamSetV1 ps = finalist();
    uint8_t epochKey[32];
    for (int i = 0; i < 32; ++i) epochKey[i] = (uint8_t)(i * 5 + 2);
    const uint8_t tmpl[16] = {0};
    const int programs = 400, reps = 9;
    std::mt19937_64 rng(999);
    std::vector<double> cost, nf;
    std::vector<double> samp(reps);
    uint8_t h[32];
    for (int p = 0; p < programs; ++p) {
        uint8_t seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)rng();
        V1Ctx* c = v1_ctx_create(ps, ds.data(), ps.dataset_words, epochKey, seed, 4096, tmpl, sizeof(tmpl));
        v1_hash(c, 0, h, nullptr, nullptr);
        for (int k = 0; k < reps; ++k) { auto a = clk::now(); v1_hash(c, k + 1, h, nullptr, nullptr); samp[k] = ms(a, clk::now()); }
        std::sort(samp.begin(), samp.end());
        cost.push_back(samp[reps / 2]);
        v1_ctx_free(c);
    }
    { // noise floor: one fixed program
        uint8_t seed[32]; for (int i = 0; i < 32; ++i) seed[i] = 0x5A;
        V1Ctx* c = v1_ctx_create(ps, ds.data(), ps.dataset_words, epochKey, seed, 4096, tmpl, sizeof(tmpl));
        for (int p = 0; p < programs; ++p) {
            for (int k = 0; k < reps; ++k) { auto a = clk::now(); v1_hash(c, p * reps + k, h, nullptr, nullptr); samp[k] = ms(a, clk::now()); }
            std::sort(samp.begin(), samp.end());
            nf.push_back(samp[reps / 2]);
        }
        v1_ctx_free(c);
    }
    auto st = [](std::vector<double>& v){ std::sort(v.begin(), v.end()); double s=0; for(double x:v)s+=x; double m=s/v.size(),var=0; for(double x:v)var+=(x-m)*(x-m); var/=v.size(); return std::make_pair(m, 100*std::sqrt(var)/m); };
    auto [m1, cv1] = st(cost); auto [m2, cv2] = st(nf);
    printf("  cross-program: mean=%.4f ms CV=%.2f%%  fastest/median=%.3f\n", m1, cv1, cost.front()/cost[cost.size()/2]);
    printf("  noise floor:   CV=%.2f%%   [gate: CV<=5%% (<=noise), fastest>=0.90x]\n", cv2);
}

// ---- store-elision liveness for the v1 pipeline ----------------------------------------------
static void store_liveness(const std::vector<uint64_t>& ds) {
    printf("\n== v1 STORE-ELISION LIVENESS (finalist S3x400) ==\n");
    ParamSetV1 ps = finalist();
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 9 + 4); seedHash[i] = (uint8_t)(i + 7); }
    const uint8_t tmpl[8] = {1,2,3,4,5,6,7,8};
    const int nonces = 60;
    uint64_t St = 0, Lv = 0, Dd = 0;
    std::vector<uint8_t> pending(ps.scratch_words, 0);
    std::vector<uint64_t> scratch(ps.scratch_words);
    uint8_t table[256]; build_opcode_table(table);
    // derive program once
    std::vector<uint8_t> prog_bytes((size_t)ps.program_len * 8);
    { uint8_t hl[8]; store_u64_le(hl, 4096); Field pf[3]={{hl,8},{epochKey,32},{seedHash,32}}; meep_xof(CTX_V1_PROGRAM, ps.id, pf, 3, prog_bytes.data(), prog_bytes.size()); }
    std::vector<Instr> program(ps.program_len);
    for (uint32_t i=0;i<ps.program_len;++i) program[i]=decode_instr(prog_bytes.data()+(size_t)i*8, table);

    for (int nn = 0; nn < nonces; ++nn) {
        std::fill(pending.begin(), pending.end(), 0);
        uint8_t seed[96]; { uint8_t nl[4]; store_u32_le(nl,(uint32_t)nn); Field f[2]={{nl,4},{tmpl,8}}; meep_xof(CTX_V1_NONCE, ps.id, f, 2, seed, 96); }
        // scratch init (S3) — reuse the library
        V1Ctx tmpc; tmpc.ps=ps; tmpc.scratch=std::move(scratch); // borrow
        // simpler: call v1_scratch_init needs a ctx; build a light one
        tmpc.scratch.resize(ps.scratch_words);
        tmpc.seedbytes.resize((ps.scratch_words/ps.s3_stride)*8);
        v1_scratch_init(&tmpc, (uint32_t)nn, seed);
        VmState vm{};
        for (int i=0;i<8;++i) vm.r[i]=load_u64_le(seed+i*8);
        for (int i=0;i<4;++i) vm.acc[i]=load_u64_le(seed+64+i*8);
        vm.SP=tmpc.scratch.data(); vm.scratchMask=ps.scratch_words-1; vm.D=ds.data(); vm.datasetMask=ps.dataset_words-1;
        for(int i=0;i<8;++i) vm.lastStores[i]=0; vm.storePos=0;
        auto mark_read=[&](uint64_t o){ if(pending[o]){pending[o]=0;Lv++;} };
        auto mark_store=[&](uint64_t o){ if(pending[o])Dd++; pending[o]=1; St++; };
        const uint32_t N=ps.program_len; uint64_t t=0;
        for (uint32_t round=0; round<ps.rounds; ++round){ uint32_t pc=0;
            for (uint32_t step=0; step<ps.steps_per_round; ++step){ const Instr& I=program[pc];
                if(I.op==OP_STORE64){ uint64_t off=(vm.r[I.dst]+(uint64_t)I.imm)&vm.scratchMask; mark_store(off); execute_step(vm,I);}
                else if(I.op==OP_LOAD64_SCRATCH){ uint64_t off=scratch_load_addr(vm,vm.r[I.src],(uint64_t)I.imm); mark_read(off); execute_step(vm,I);}
                else execute_step(vm,I);
                uint64_t da=(vm.acc[2]^vm.r[step&7])&vm.datasetMask; uint64_t dv=vm.D[da]; vm.acc[3]^=dv; vm.acc[2]=rotl64(vm.acc[2]+dv,23);
                ++t; if((t%MIXBACK_INTERVAL)==0){ unsigned j=(unsigned)((t/MIXBACK_INTERVAL)&7u); uint64_t off=vm.lastStores[j]&vm.scratchMask; mark_read(off); vm.r[j]^=vm.SP[off]; }
                if(I.op==OP_BRANCH_IF_BIT && ((vm.r[I.src]>>I.aux)&1u)) pc=(uint32_t)((pc+1+(I.imm&(N-1)))%N); else pc=(pc+1)%N;
            }
        }
        for(int k=0;k<8;++k) mark_read(vm.lastStores[k]&vm.scratchMask);
        for(int k=0;k<24;++k){ uint64_t idx=(vm.acc[k&3]^vm.r[k&7]^(uint64_t)k*0x9E3779B97F4A7C15ULL)&vm.scratchMask; mark_read(idx); }
        for(size_t w=0;w<ps.scratch_words;++w) if(pending[w]) Dd++;
        scratch=std::move(tmpc.scratch);
    }
    printf("  stores/hash=%.1f  live=%.1f%%  dead(oracle-elidable)=%.1f%%  [gate: live>=90%%]\n",
           (double)St/nonces, 100.0*Lv/St, 100.0*Dd/St);
}

// ---- multi-size construction B under v1 ------------------------------------------------------
static void multisize() {
    printf("\n== v1 CONSTRUCTION B multi-size (finalist S3x400) ==\n");
    uint8_t epochKey[32], seedHash[32];
    for (int i=0;i<32;++i){ epochKey[i]=(uint8_t)(i+11); seedHash[i]=(uint8_t)(i*4+5); }
    const uint8_t tmpl[8]={1,2,3,4,5,6,7,8};
    size_t sizes[3]={0x400000,0x800000,0x1000000}; const char* names[3]={"32MiB","64MiB","128MiB"};
    for (int s=0;s<3;++s){
        std::vector<uint64_t> ds(sizes[s]);
        auto a=clk::now(); dataset_fill_B(ds.data(), sizes[s], epochKey, 0); double fill=ms(a,clk::now());
        ParamSetV1 ps=finalist(); ps.dataset_words=sizes[s];
        V1Ctx* c=v1_ctx_create(ps, ds.data(), sizes[s], epochKey, seedHash, 4096, tmpl, 8);
        uint8_t h[32]; v1_hash(c,0,h,nullptr,nullptr);
        std::vector<double> per; for(int n=0;n<80;++n){ auto b=clk::now(); v1_hash(c,(uint32_t)(n+1),h,nullptr,nullptr); per.push_back(ms(b,clk::now())); }
        std::sort(per.begin(),per.end());
        printf("  [%s] dataset init %.1f ms (one-time/epoch), per-hash p50 %.3f ms, mem ~%.0f MiB\n",
               names[s], fill, per[per.size()/2], sizes[s]*8.0/1048576.0 + ps.scratch_words*8.0/1048576.0);
        v1_ctx_free(c);
    }
    printf("  (dataset init is one-time per epoch key: node startup / epoch transition; verification\n");
    printf("   reuses the cached dataset. v1 reads the dataset EVERY VM step -> reduced-memory attacks\n");
    printf("   are penalized far more than v0.)\n");
}

int main() {
    uint8_t epochKey[32]; for (int i=0;i<32;++i) epochKey[i]=(uint8_t)(i*5+2);
    std::vector<uint64_t> ds(V1_DATASET_WORDS);
    dataset_fill_B(ds.data(), V1_DATASET_WORDS, epochKey, 0);
    grinding(ds);
    store_liveness(ds);
    multisize();
    return 0;
}
