// MeepHash-W v1 (frozen S3x400) grinding confirmation (CONFIRMATION_PLAN_V1).
// Samples many programs (distinct seed-block hashes), measures per-program median hash time in
// TWO independent passes, and tests whether "fast" programs are REPEATABLY fast (a real grindable
// gain) or just measurement noise: reports cross-pass correlation and where pass-1's fastest
// programs rank in pass-2. Also CV vs noise floor and the fastest-advantage distribution.
//
// Usage: meepow-v1-grind [programs] [reps]   (run under `taskset -c N` for a stable core)
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;
static double ms(clk::time_point a, clk::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }

static double median(std::vector<double> v){ std::sort(v.begin(),v.end()); return v[v.size()/2]; }
static double mean(const std::vector<double>& v){ double s=0; for(double x:v)s+=x; return s/v.size(); }
static double cv(const std::vector<double>& v){ double m=mean(v),s=0; for(double x:v)s+=(x-m)*(x-m); return 100*std::sqrt(s/v.size())/m; }
static double pearson(const std::vector<double>& a, const std::vector<double>& b){
    double ma=mean(a),mb=mean(b),num=0,da=0,db=0;
    for(size_t i=0;i<a.size();++i){ num+=(a[i]-ma)*(b[i]-mb); da+=(a[i]-ma)*(a[i]-ma); db+=(b[i]-mb)*(b[i]-mb);} return num/std::sqrt(da*db);
}

// Measure per-program median hash times for a fixed set of seed hashes.
static std::vector<double> measure_pass(const std::vector<std::array<uint8_t,32>>& seeds,
                                        const std::vector<uint64_t>& ds, int reps){
    ParamSetV1 ps=v1_config(50,"v1",SCRATCH_S3,V1_ROUNDS_50X);
    uint8_t epochKey[32]; for(int i=0;i<32;++i) epochKey[i]=(uint8_t)(i*5+2);
    uint8_t tmpl[16]={0}; uint8_t h[32];
    std::vector<double> out; out.reserve(seeds.size());
    std::vector<double> samp(reps);
    for(auto& sd : seeds){
        V1Ctx* c=v1_ctx_create(ps, ds.data(), ps.dataset_words, epochKey, sd.data(), 4096, tmpl, sizeof(tmpl));
        v1_hash(c,0,h,nullptr,nullptr); // warm
        for(int k=0;k<reps;++k){ auto a=clk::now(); v1_hash(c,(uint32_t)(k+1),h,nullptr,nullptr); samp[k]=ms(a,clk::now()); }
        out.push_back(median(samp));
        v1_ctx_free(c);
    }
    return out;
}

int main(int argc, char** argv){
    int programs = argc>1?atoi(argv[1]):2000;
    int reps = argc>2?atoi(argv[2]):15;
    std::mt19937_64 rng(0xC0FFEE);
    std::vector<std::array<uint8_t,32>> seeds(programs);
    for(auto& s : seeds) for(int i=0;i<32;++i) s[i]=(uint8_t)rng();
    uint8_t epochKey[32]; for(int i=0;i<32;++i) epochKey[i]=(uint8_t)(i*5+2);
    std::vector<uint64_t> ds(V1_DATASET_WORDS); dataset_fill_B(ds.data(),V1_DATASET_WORDS,epochKey,0);

    printf("== v1 GRINDING (frozen S3x400) programs=%d reps=%d ==\n", programs, reps);
    // noise floor: one fixed program measured `programs` times
    { std::vector<std::array<uint8_t,32>> one(programs, seeds[0]);
      auto nf = measure_pass(one, ds, reps);
      printf("noise floor (one fixed program): CV=%.2f%%\n", cv(nf)); }

    auto passA = measure_pass(seeds, ds, reps);
    auto passB = measure_pass(seeds, ds, reps);

    double medA=median(passA);
    std::vector<double> sortedA=passA; std::sort(sortedA.begin(),sortedA.end());
    double fastest=sortedA.front(), p01=sortedA[programs/100], p05=sortedA[programs/20];
    printf("cross-program pass A: CV=%.2f%%  fastest/median=%.3f  p01/median=%.3f  p05/median=%.3f\n",
           cv(passA), fastest/medA, p01/medA, p05/medA);
    printf("best-of-%d advantage (median/fastest) = %.2f%%\n", programs, 100*(medA-fastest)/medA);

    // Repeatability: correlation between passes, and rank of pass-A-fastest in pass B.
    double r = pearson(passA, passB);
    printf("cross-pass correlation (repeatability) r = %.3f  (r~0 => 'fast' programs are NOISE)\n", r);
    // For the fastest 5% in A, where do they land in B (percentile rank)?
    std::vector<size_t> idx(programs); for(size_t i=0;i<idx.size();++i) idx[i]=i;
    std::sort(idx.begin(),idx.end(),[&](size_t a,size_t b){return passA[a]<passA[b];});
    std::vector<double> sortedB=passB; std::sort(sortedB.begin(),sortedB.end());
    auto pct_rank=[&](double t){ return 100.0*(std::lower_bound(sortedB.begin(),sortedB.end(),t)-sortedB.begin())/programs; };
    double avgrank=0; int topk=programs/20;
    for(int i=0;i<topk;++i) avgrank += pct_rank(passB[idx[i]]);
    avgrank/=topk;
    printf("pass-A fastest 5%% land at avg %.1f-th percentile in pass B (50 => pure noise; <20 => real)\n", avgrank);
    printf("[gate: CV<=5%% AND <=noise AND repeatable best-of-N advantage <=2%%]\n");
    return 0;
}
