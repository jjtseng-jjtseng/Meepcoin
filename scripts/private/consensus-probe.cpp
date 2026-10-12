// Offline study linked to real production libraries. Not daemon acceptance evidence.
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "easylogging++.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
using cryptonote::difficulty_type;
static uint64_t difficulty(const std::vector<uint64_t>& ts,const std::vector<difficulty_type>& cw) {
  auto d=cryptonote::next_difficulty(ts,cw,60);
  if(d==0 || d>UINT64_MAX)throw std::runtime_error("unusable difficulty");
  return d.convert_to<uint64_t>();
}
static void monetary() {
  const uint64_t supply=MONEY_SUPPLY,tail=FINAL_SUBSIDY_PER_MINUTE;
  std::cout << "{\"kind\":\"monetary\",\"rewards\":[";
  bool comma=false;
  for(uint64_t generated:{uint64_t(0),supply-1,supply,supply+1,UINT64_MAX}) {
    for(uint64_t weight:{uint64_t(300000),uint64_t(450000),uint64_t(600000),uint64_t(600001)}) {
      uint64_t reward=UINT64_MAX;
      bool ok=cryptonote::get_block_reward(300000,weight,generated,reward,16);
      if(comma)std::cout << ',';
      comma=true;
      std::cout << "{\"generated\":\""<<generated<<"\",\"weight\":"<<weight<<",\"accepted\":"<<(ok?"true":"false");
      if(ok)std::cout << ",\"reward\":\""<<reward<<'"';
      std::cout << '}';
    }
  }
  std::cout << "],\"amounts\":[";comma=false;
  for(const std::string input:{"0","0.00000000001","1","1.00000000000","1.000000000001","-1","nan","184467440.73709551615","184467440.73709551616"}) {
    uint64_t amount=0;bool ok=cryptonote::parse_amount(amount,input);
    if(comma)std::cout << ',';
    comma=true;
    std::cout << "{\"input\":\""<<input<<"\",\"accepted\":"<<(ok?"true":"false");
    if(ok)std::cout<<",\"atomic\":\""<<amount<<'"';
    std::cout<<'}';
  }
  uint64_t generated=0,first_tail=0,supply_height=0;difficulty_type total=0;
  std::cout << "],\"emission\":[";
  for(uint64_t height=1;height<=52560000; ++height) {
    const uint64_t reward=std::max(generated>=supply?uint64_t(0):(supply-generated)>>21,tail);
    if(reward==tail && !first_tail)first_tail=height;
    total+=reward;generated=reward<supply-generated?generated+reward:supply;
    if(generated==supply && !supply_height)supply_height=height;
    if(height==525600 || height==5256000 || height==13140000 || height==52560000) {
      if(height!=525600)std::cout<<',';
      std::cout<<"{\"height\":"<<height<<",\"totalAtomic\":\""<<total<<"\",\"accountedEmission\":\""<<generated<<"\"}";
    }
  }
  std::cout<<"],\"firstTailHeight\":"<<first_tail<<",\"supplyParameterReachedHeight\":"<<supply_height<<"}\n";
}
static void scenario(const std::string& name,double factor,bool fresh,bool compressed) {
  constexpr unsigned seeds=32,blocks=1800;
  double means=0;unsigned hour_gap_runs=0,recovered_runs=0;double worst_gap=0;
  std::cout<<"{\"kind\":\"policy\",\"scenario\":\""<<name<<"\",\"seeds\":"<<seeds<<",\"blocksPerSeed\":"<<blocks<<",\"runs\":[";
  for(unsigned seed=0;seed<seeds;++seed) {
    std::mt19937_64 rng(0x4d45455000000000ULL+seed);
    std::vector<uint64_t> ts;std::vector<difficulty_type> cw;
    uint64_t t=0;difficulty_type cumulative=0;
    if(!fresh) for(unsigned i=1;i<=735;++i){t=60*i;ts.push_back(t);cumulative+=1000;cw.push_back(cumulative);}
    double clock=t,interval_sum=0,max_gap=0;unsigned recovered=0,samples=0,processed=0;uint64_t max_d=0;bool stalled=false;
    std::vector<double> waits;
    for(unsigned i=0;i<blocks;++i) {
      const uint64_t d=difficulty(ts,cw);max_d=std::max(max_d,d);
      const double u=(double(rng()>>11)+0.5)/9007199254740992.0;
      const double wait=-std::log(u)*double(d)/(1000.0/60.0*factor);
      if(wait>31536000 || d>1000000000000ULL){stalled=true;max_gap=std::max(max_gap,wait);break;}
      clock+=wait;max_gap=std::max(max_gap,wait);
      ++processed;if(i>=600){interval_sum+=wait;++samples;}
      uint64_t stamp=uint64_t(clock);
      if(compressed && !ts.empty()) {
        auto recent=std::vector<uint64_t>(ts.end()-std::min<size_t>(60,ts.size()),ts.end());
        std::sort(recent.begin(),recent.end());size_t n=recent.size();
        stamp=n%2?recent[n/2]:(recent[n/2-1]+recent[n/2])/2;
      }
      cumulative+=d;ts.push_back(stamp);cw.push_back(cumulative);
      if(ts.size()>735){ts.erase(ts.begin());cw.erase(cw.begin());}
      waits.push_back(wait);if(waits.size()>30)waits.erase(waits.begin());
      double average=0;for(double x:waits)average+=x;average/=waits.size();
      if(!recovered && i>=29 && average<=120)recovered=i+1;
    }
    const double mean=samples?interval_sum/samples:0;means+=mean;worst_gap=std::max(worst_gap,max_gap);
    if(max_gap>3600)++hour_gap_runs;
    if(recovered && recovered<=180)++recovered_runs;
    if(seed)std::cout<<',';
    std::cout<<"{\"seed\":"<<seed<<",\"processedBlocks\":"<<processed<<",\"modelHorizonExceeded\":"<<(stalled?"true":"false")<<",\"steadyMeanSeconds\":"<<mean<<",\"maxGapSeconds\":"<<max_gap<<",\"firstRecoveryBlock\":"<<recovered<<",\"maxDifficulty\":\""<<max_d<<"\"}";
  }
  std::cout<<"],\"meanSeconds\":"<<means/seeds<<",\"runsWithHourGap\":"<<hour_gap_runs<<",\"recoveredWithin180\":"<<recovered_runs<<",\"worstGapSeconds\":"<<worst_gap<<"}\n";
}
int main(int argc,char**argv) {
  try {
    if(argc==2 && std::string(argv[1])=="monetary"){monetary();return 0;}
    if(argc==2 && std::string(argv[1])=="policy") {
      scenario("stable-mature",1,false,false);scenario("tenfold-arrival",10,false,false);
      scenario("ninety-percent-departure",0.1,false,false);scenario("honest-launch",1,true,false);
      scenario("median-time-compression",1,false,true);return 0;
    }
    std::string operation;
    while(std::cin>>operation) {
      if(operation!="difficulty")throw std::runtime_error("unknown operation");
      size_t n;if(!(std::cin>>n)||n>735)throw std::runtime_error("history too large");
      std::vector<uint64_t> ts;std::vector<difficulty_type> cw;
      for(size_t i=0;i<n;++i){uint64_t t;std::string w;if(!(std::cin>>t>>w))throw std::runtime_error("bad row");ts.push_back(t);cw.emplace_back(w);}
      std::cout<<difficulty(ts,cw)<<'\n';
    }
  }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
