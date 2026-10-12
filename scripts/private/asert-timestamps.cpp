// UNACTIVATED: anchored DAA sensitivity to finite minority timestamp strategies.
#include "asert-candidate.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <string>
#include <vector>
using meepcoin_candidate::asert;
using meepcoin_candidate::uint128_t;
static void study(unsigned half,unsigned window,unsigned future,double fraction,bool push_future) {
 constexpr unsigned seeds=1000,blocks=1800;
 unsigned hour_runs=0,horizon_runs=0;double grand_mean=0,worst=0;unsigned long long malicious=0;
 for(unsigned seed=0;seed<seeds;++seed) {
  std::mt19937_64 rng(0x54494d4553540000ULL+seed);double clock=0,maxgap=0,sum=0;uint128_t d=1000;
  std::vector<uint64_t> history{0};bool horizon=false;
  for(unsigned i=0;i<blocks;++i) {
   const double u=(double(rng()>>11)+.5)/9007199254740992.0;
   const double wait=-std::log(u)*d.convert_to<double>()/(1000.0/60);
   if(wait>31557600||clock+wait>double(INT64_MAX)){horizon=true;break;}
   clock+=wait;maxgap=std::max(maxgap,wait);if(i>=600)sum+=wait;
   auto sorted=history;std::sort(sorted.begin(),sorted.end());
   uint64_t median=sorted[sorted.size()/2];
   if(sorted.size()%2==0)median=(sorted[sorted.size()/2-1]+median)/2;
   const double share=(double(rng()>>11)+.5)/9007199254740992.0;
   const bool bad=share<fraction;if(bad)++malicious;
   const uint64_t timestamp=bad?(push_future?uint64_t(clock)+future:median):std::max(uint64_t(clock),median);
   if(timestamp<median||timestamp>uint64_t(clock)+future)throw std::runtime_error("modeled invalid timestamp");
   history.push_back(timestamp);if(history.size()>window)history.erase(history.begin());
   d=asert(1000,i+1,int64_t(timestamp),half);
  }
  if(horizon)++horizon_runs;if(maxgap>3600||horizon)++hour_runs;
  grand_mean+=sum/1200;worst=std::max(worst,maxgap);
 }
 const double p=double(hour_runs)/seeds,z=1.644853626951;
 const double upper=(p+z*z/(2*seeds)+z*std::sqrt(p*(1-p)/seeds+z*z/(4.0*seeds*seeds)))/(1+z*z/seeds);
 std::cout<<"{\"halfLifeSeconds\":"<<half<<",\"medianWindow\":"<<window<<",\"futureLimitSeconds\":"<<future
  <<",\"maliciousFraction\":"<<fraction<<",\"strategy\":\""<<(push_future?"future-limit":"earliest-median")
  <<"\",\"seeds\":"<<seeds<<",\"blocksPerSeed\":"<<blocks<<",\"runsWithHourGap\":"<<hour_runs
  <<",\"hourGapOneSidedWilson95Upper\":"<<upper<<",\"horizonFailures\":"<<horizon_runs<<",\"steadyMeanSeconds\":"<<grand_mean/seeds
  <<",\"worstGapSeconds\":"<<worst<<",\"maliciousAcceptedBlocks\":"<<malicious<<"}\n";
}
int main() {
 for(unsigned half:{900u,1800u})for(unsigned window:{11u,60u})for(unsigned future:{120u,7200u})
  for(double fraction:{.1,.25,.4})for(bool push_future:{false,true})study(half,window,future,fraction,push_future);
}
