// Mature-chain model; the v17 daemon candidate separately qualifies startup.
#include "asert-candidate.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <string>
#include <vector>
using meepcoin_candidate::asert;
using meepcoin_candidate::uint128_t;
static void study(uint32_t half,const std::string& name,double rate,unsigned seeds=1000,unsigned seed_offset=0) {
  constexpr unsigned blocks=1800;
  std::vector<unsigned> recoveries;std::vector<double> gaps,means,seconds;
  unsigned hour_runs=0,post_first_hour_runs=0,failed_recovery=0;
  unsigned observed_failed_recovery=0,observed_within180=0,observed_max=0;
  for(unsigned seed=0;seed<seeds;++seed) {
    std::mt19937_64 rng(0x4d45455000000000ULL+seed+seed_offset);
    double clock=0,sum=0,maxgap=0,post_max=0;unsigned consecutive=0,recovered=0;double recovery_seconds=0;
    uint128_t d=1000;std::vector<double> waits;unsigned observed_recovered=0;
    for(unsigned i=0;i<blocks;++i) {
      double u=(double(rng()>>11)+.5)/9007199254740992.0;
      double wait=-std::log(u)*d.convert_to<double>()/(1000.0/60.0*rate);
      clock+=wait;maxgap=std::max(maxgap,wait);if(i)post_max=std::max(post_max,wait);
      waits.push_back(wait);if(waits.size()>30)waits.erase(waits.begin());
      double average=0;for(auto x:waits)average+=x;average/=waits.size();
      if(!observed_recovered&&i>=29&&average<=120)observed_recovered=i+1;
      if(i>=600)sum+=wait;
      d=asert(1000,i+1,int64_t(clock),half);
      if(d.convert_to<double>()/(1000.0/60.0*rate)<=90)++consecutive;else consecutive=0;
      if(!recovered&&consecutive>=30){recovered=i+1;recovery_seconds=clock;}
    }
    if(maxgap>3600)++hour_runs;if(post_max>3600)++post_first_hour_runs;
    if(!recovered)++failed_recovery;else{recoveries.push_back(recovered);seconds.push_back(recovery_seconds);}
    if(!observed_recovered)++observed_failed_recovery;
    else{observed_max=std::max(observed_max,observed_recovered);if(observed_recovered<=180)++observed_within180;}
    gaps.push_back(maxgap);means.push_back(sum/1200);
  }
  std::sort(recoveries.begin(),recoveries.end());std::sort(seconds.begin(),seconds.end());std::sort(gaps.begin(),gaps.end());
  double mean=0;for(auto x:means)mean+=x;mean/=seeds;
  double variance=0;for(auto x:means)variance+=(x-mean)*(x-mean);variance/=(seeds-1);
  std::cout<<"{\"halfLifeSeconds\":"<<half<<",\"scenario\":\""<<name<<"\",\"seeds\":"<<seeds
    <<",\"steadyMeanSeconds\":"<<mean<<",\"steadyMean95HalfWidth\":"<<1.96*std::sqrt(variance/seeds)
    <<",\"runsWithHourGap\":"<<hour_runs<<",\"runsWithPostFirstHourGap\":"<<post_first_hour_runs
    <<",\"failedRecovery\":"<<failed_recovery<<",\"recoveryP95Blocks\":"<<(recoveries.empty()?0:recoveries[std::min(recoveries.size()-1,size_t(seeds*.95))])
    <<",\"observedFailedRecovery\":"<<observed_failed_recovery<<",\"observedRecoveredWithin180\":"<<observed_within180<<",\"observedRecoveryMaxBlocks\":"<<observed_max
    <<",\"recoveryP95Seconds\":"<<(seconds.empty()?0:seconds[std::min(seconds.size()-1,size_t(seeds*.95))])
    <<",\"recoveryMaxBlocks\":"<<(recoveries.empty()?0:recoveries.back())<<",\"maxGapP95Seconds\":"<<gaps[std::min(gaps.size()-1,size_t(seeds*.95))]<<",\"worstGapSeconds\":"<<gaps.back()<<"}\n";
}
int main(int argc,char**argv) {
  try {
    if(argc==2&&(std::string(argv[1])=="holdout"||std::string(argv[1])=="holdout-original-metric")) {
      study(900,"stable-mature",1,10000,100000);study(900,"ninety-percent-departure",.1,10000,100000);study(900,"tenfold-arrival",10,10000,100000);return 0;
    }
    if(argc==2&&std::string(argv[1])=="study") {
      for(uint32_t half:{900u,1800u,3600u,7200u}) {
        study(half,"stable-mature",1);study(half,"ninety-percent-departure",.1);study(half,"tenfold-arrival",10);
      }return 0;
    }
    std::string anchor;uint64_t height;int64_t elapsed;uint32_t half;
    while(std::cin>>anchor>>height>>elapsed>>half)std::cout<<asert(uint128_t(anchor),height,elapsed,half)<<'\n';
  }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
