// Conditional stochastic timing model; calls the exact production integer DAA.
// Measured steady rates are inputs, not a guarantee about future mining.
#include "cryptonote_basic/meepcoin_asert.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <vector>
int main(int argc,char**argv){
 if(argc!=3)return 2;
 const double rate=std::stod(argv[1]);const unsigned blocks=std::stoul(argv[2]);
 if(!std::isfinite(rate)||rate<=0||blocks<26||blocks>100)return 2;
 constexpr unsigned seeds=4096;std::vector<double> times;
 for(unsigned seed=0;seed<seeds;++seed){
  std::mt19937_64 rng(0x4d45455000000000ULL+seed);
  // Start 300 seconds after genesis; quiet periods are additional reservations.
  double clock=300;uint64_t height=0,parent=0;
  for(unsigned n=0;n<blocks;++n){
   const auto difficulty=cryptonote::meepcoin_asert_difficulty(height,parent,0);
   const double u=(double(rng()>>11)+.5)/9007199254740992.0;
   // Allow two seconds of job/validation overhead per block conservatively.
   clock+=-std::log(u)*difficulty.convert_to<double>()/rate+2;
   parent=uint64_t(clock);++height;
  }
  times.push_back(clock-300);
 }
 std::sort(times.begin(),times.end());
 const double p95=times[size_t(std::ceil(.95*seeds))-1];
 std::cout<<"{\"schema\":\"meepcoin-conditional-timing-model/1\",\"seeds\":"<<seeds
  <<",\"hashesPerSecond\":"<<rate<<",\"blocks\":"<<blocks
  <<",\"startOffsetSeconds\":300,\"perBlockOverheadSeconds\":2,\"medianMiningSeconds\":"<<times[seeds/2]
  <<",\"p95MiningSeconds\":"<<p95<<",\"worstSampleSeconds\":"<<times.back()
  <<",\"miningBudgetSeconds\":2400,\"fitsConditionalBudget\":"<<(p95<=2400?"true":"false")
  <<",\"limitations\":\"Fixed measured rates and honest wall timestamps; no network outages, thermal change, competition or adversary modeled. Empirical run still required.\"}\n";
 return p95<=2400?0:1;
}
