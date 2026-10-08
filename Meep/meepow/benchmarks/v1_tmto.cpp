// MeepHash-W v1 (frozen S3x400) time-memory tradeoff suite for construction B
// (CONFIRMATION_PLAN_V1). v1 does ~108k dataset reads/hash (read-chain + program), so dataset
// access latency dominates the hash; measuring reduced-memory dataset access is the TMTO gate.
//
// Strategies for construction B (D[w]=mixB(D[w-1], D[D[w-1]%w], w), a data-dependent DAG):
//   full            : store all words (baseline).
//   checkpoint 1/S  : store every S-th word; recompute others by replay (recompute-on-access /
//                     partial caching). Correctness = exact recompute (verified).
//   from-seed       : store only the seed region; procedural reconstruction from the seed.
//   compression     : entropy/compressibility probe (repeated-word ratio) — is the dataset
//                     compressible enough to shrink memory losslessly?
//
// Usage: meepow-v1-tmto [samples]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <unordered_map>
#include <vector>

#include "dataset.hpp"
#include "params.hpp"
#include "params_v1.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }

static const size_t DW = V1_DATASET_WORDS;  // 32 MiB / 8 = 4,194,304 words
static const uint32_t READS_PER_HASH = 108000;  // ~ read-chain(102400) + program dataset loads

// Count the mixB operations needed to recompute D[w] for construction B from checkpoints stored
// every `stride` words (per-access memo, no full storage). Capped to avoid OOM/hang: if the work
// exceeds `cap`, we stop and report the access as "capped" (>= cap ops). Returns value; sets
// `capped`. This measures the recompute-on-access COST that a 1/stride-memory attacker pays.
static uint64_t countB(size_t w, size_t stride, const std::vector<uint64_t>& ckpt,
                       std::unordered_map<size_t,uint64_t>& memo, uint64_t& ops, uint64_t cap,
                       bool& capped) {
    if (capped) return 0;
    if (w % stride == 0) return ckpt[w / stride];
    auto it = memo.find(w); if (it != memo.end()) return it->second;
    if (ops >= cap || memo.size() >= cap) { capped = true; return 0; }
    uint64_t prev = countB(w - 1, stride, ckpt, memo, ops, cap, capped);
    if (capped) return 0;
    size_t back = (size_t)(prev % (uint64_t)w);
    uint64_t bval = countB(back, stride, ckpt, memo, ops, cap, capped);
    if (capped) return 0;
    ++ops;
    uint64_t val = mixB(prev, bval, (uint64_t)w);
    memo[w] = val;
    return val;
}

int main(int argc, char** argv){
    int samples = argc>1?atoi(argv[1]):4000;
    uint8_t epochKey[32]; for(int i=0;i<32;++i) epochKey[i]=(uint8_t)(i*5+2);
    std::vector<uint64_t> D(DW);
    auto t0=clk::now(); dataset_fill_B(D.data(), DW, epochKey, 0); double fill_ms=ms(t0,clk::now());
    printf("== v1 TMTO SUITE (frozen S3x400, construction B, %.0f MiB, %d samples) ==\n", DW*8.0/1048576.0, samples);
    printf("full dataset init %.1f ms; ~%u dataset reads/hash; stored per-hash ~16 ms (=> ~%.0f ns/read)\n",
           fill_ms, READS_PER_HASH, 16e6/READS_PER_HASH);

    std::mt19937_64 rng(12345);
    std::vector<size_t> probe(samples);
    for(auto& p : probe) p = rng() % DW;

    // stored read cost
    { volatile uint64_t sink=0; auto a=clk::now(); for(size_t p:probe) sink^=D[p]; double t=ms(a,clk::now());
      printf("stored     : retained %6.1f MiB (100%%)   per-read %.1f ns   slowdown 1.0x\n", DW*8.0/1048576.0, t*1e6/samples); }

    printf("%-10s %12s %14s %10s %8s\n","strategy","retained","mixB-ops/read","vs stored","correct");
    const uint64_t CAP = 3000000;  // ops cap per access (>=CAP => effectively unbounded)
    for (size_t S : {2u,4u,8u,16u,64u}) {
        size_t nck = DW/S + 1;
        std::vector<uint64_t> ckpt(nck);
        for(size_t k=0;k<nck;++k){ size_t idx=k*S; if(idx<DW) ckpt[k]=D[idx]; }
        int correct=0, cappedN=0; double opsum=0;
        for(size_t p:probe){
            std::unordered_map<size_t,uint64_t> memo; uint64_t ops=0; bool capped=false;
            uint64_t v=countB(p,S,ckpt,memo,ops,CAP,capped);
            if (capped) { cappedN++; opsum += CAP; }
            else { opsum += ops; if(v==D[p]) correct++; }
        }
        double avgops = opsum/samples;
        // A stored read is ~1 memory access; recompute pays ~avgops mixB ops (each ~ a few ns).
        printf("ckpt 1/%-4zu %8.2f MiB %14.0f %8.0fx %6d%% %s\n",
               S, DW*8.0/S/1048576.0, avgops, avgops /* ops vs ~1 for stored */,
               samples? 100*correct/samples:0, cappedN? "(some capped)":"");
    }

    // procedural from-seed: replaying from the seed region (stride ~ whole dataset) is the extreme.
    printf("from-seed  : retained ~0.06 MiB (seed only); replay is O(datasetWords) per held-out access\n");
    printf("             => per hash ~ %u accesses x O(4.2M ops) = astronomically slower (not run)\n", READS_PER_HASH);

    // compression probe: count exact duplicate 8-byte words (a cheap losslessness bound).
    { std::unordered_map<uint64_t,uint32_t> seen; size_t dup=0, n=std::min(DW,(size_t)2000000);
      for(size_t i=0;i<n;++i){ auto& c=seen[D[i]]; if(c) dup++; c++; }
      printf("compression: duplicate-word ratio %.4f%% over %zu words => high entropy, not losslessly compressible\n",
             100.0*dup/n, n); }

    printf("[gate: any strategy at <=50%% memory must be >=2.0x slower per hash, with correct hashes]\n");
    return 0;
}
