// Startup and clock-skew sensitivity; no network activation. Honest Poisson single-miner model.
#include "asert-candidate.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <vector>
using meepcoin_candidate::asert;
using meepcoin_candidate::uint128_t;
static void study(double hashrate,unsigned lag,int miner_skew,int validator_skew){
 constexpr unsigned seeds=1000,blocks=1800;double steady=0,largest=0,total_deferrals=0,max_deferred_seconds=0;
 unsigned hour_runs=0,horizon_failures=0;std::vector<unsigned> warmup;
 for(unsigned seed=0;seed<seeds;++seed){
  std::mt19937_64 rng(0x5354415254555000ULL+seed);double clock=lag,sum=0,maxgap=0;uint128_t d=20;std::vector<uint64_t> times={0};unsigned consecutive=0,ready=0;
  for(unsigned i=1;i<=blocks;++i){
   const double u=(double(rng()>>11)+.5)/9007199254740992.0;const double before=clock;clock+=-std::log(u)*d.convert_to<double>()/hashrate;
   if(clock>365*86400){++horizon_failures;break;}
   auto history=times;std::sort(history.begin(),history.end());const size_t n=history.size();const uint64_t median=n%2?history[n/2]:history[n/2-1]+(history[n/2]-history[n/2-1])/2;
   const uint64_t timestamp=uint64_t(std::max<double>(median,std::max(0.0,std::floor(clock+miner_skew))));
   const double necessary=double(timestamp)-120-validator_skew;
   if(clock<necessary){total_deferrals++;max_deferred_seconds=std::max(max_deferred_seconds,necessary-clock);clock=necessary;}
   maxgap=std::max(maxgap,clock-before);if(i>600)sum+=clock-before;
   times.push_back(timestamp);if(times.size()>11)times.erase(times.begin());
   d=std::max<uint128_t>(20,asert(20,i,int64_t(timestamp),900));
   if(d.convert_to<double>()/hashrate<=90)++consecutive;else consecutive=0;
   if(!ready&&consecutive>=30)ready=i;
  }
  if(ready)warmup.push_back(ready);if(maxgap>3600)++hour_runs;largest=std::max(largest,maxgap);steady+=sum/1200;
 }
 std::sort(warmup.begin(),warmup.end());
 std::cout<<"{\"hashesPerSecond\":"<<hashrate<<",\"genesisLagSeconds\":"<<lag<<",\"minerClockSkew\":"<<miner_skew<<",\"validatorClockSkew\":"<<validator_skew<<",\"seeds\":"<<seeds<<",\"steadyMeanSeconds\":"<<steady/seeds<<",\"hourGapRuns\":"<<hour_runs<<",\"worstGapSeconds\":"<<largest<<",\"recoveredRuns\":"<<warmup.size()<<",\"recoveryMaxBlocks\":"<<(warmup.empty()?0:warmup.back())<<",\"deferredBlocks\":"<<total_deferrals<<",\"maxDeferralSeconds\":"<<max_deferred_seconds<<",\"horizonFailures\":"<<horizon_failures<<"}\n";
}
int main(){for(double h:{.05,.5,5.,50.,500.})for(unsigned lag:{0u,3600u,86400u})study(h,lag,0,0);
 for(auto clocks:std::vector<std::pair<int,int>>{{-30,30},{30,-30},{-60,60},{60,-60},{-120,120},{120,-120},{120,0}})study(50,3600,clocks.first,clocks.second);}
