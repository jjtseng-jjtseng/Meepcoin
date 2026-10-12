// Finite availability model calling the actual production v17 arithmetic.
// It is not a network, a mining benchmark, or a security proof.
#include "cryptonote_basic/meepcoin_asert.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <string>
#include <vector>
constexpr double day = 86400;
constexpr double horizon = 30 * day;
struct Scenario { const char* name; double attacker; bool earliest; };
double rate(const std::string& scenario, double clock, double& next) {
  next = horizon;
  if (scenario == "daily-eight-hours") {
    const double date = std::floor(clock/day)*day;
    if (clock-date < 8*3600) { next = date+8*3600; return .5; }
    next = date+day; return 0;
  }
  if (scenario == "week-outage") {
    if (clock < 2*day) { next = 2*day; return .5; }
    if (clock < 9*day) { next = 9*day; return 0; }
  }
  if (scenario == "ninety-percent-departure") {
    if (clock < 2*day) { next = 2*day; return .5; }
    return .05;
  }
  if (scenario == "hundredfold-burst-return") {
    if (clock < 2*day) { next = 2*day; return 50; }
  }
  return scenario == "very-low-participation" ? .01 : .5;
}
double uniform(std::mt19937_64& rng) {
  return (double(rng() >> 11) + .5) / 9007199254740992.0;
}
void study(const Scenario& scenario) {
  constexpr unsigned seeds = 128;
  std::vector<double> mean_gaps, maximum_gaps, counts;
  unsigned hour_runs = 0, truncated = 0;
  uint64_t total_blocks = 0, malicious = 0, floor_blocks = 0;
  for (unsigned seed = 0; seed < seeds; ++seed) {
    std::mt19937_64 rng(0x415641494c000000ULL + seed);
    double clock = 3600, last = clock, largest = 0, sum = 0;
    uint64_t height = 0, parent_time = 0;
    std::vector<uint64_t> history{0};
    for (; height < 100000; ) {
      const auto difficulty = cryptonote::meepcoin_asert_difficulty(height, parent_time, 0);
      double needed = -std::log(uniform(rng))*difficulty.convert_to<double>();
      // Carry exponential work across scheduled rate changes. A zero-rate
      // interval advances wall time without inventing a block or changing DAA.
      while (clock < horizon) {
        double boundary;
        const double hashrate = rate(scenario.name, clock, boundary);
        const double available = hashrate*(boundary-clock);
        if (hashrate > 0 && needed < available) { clock += needed/hashrate; break; }
        needed -= available; clock = boundary;
      }
      if (clock >= horizon) break;
      const double gap = clock-last;
      sum += gap; largest = std::max(largest, gap); last = clock;
      auto sorted = history; std::sort(sorted.begin(), sorted.end());
      const size_t size = sorted.size();
      const auto median = size%2 ? sorted[size/2] : sorted[size/2-1]+(sorted[size/2]-sorted[size/2-1])/2;
      const bool bad = uniform(rng) < scenario.attacker;
      parent_time = bad ? (scenario.earliest ? median : uint64_t(clock)+120) : std::max(uint64_t(clock), median);
      if (parent_time < median || parent_time > uint64_t(clock)+120)
        throw std::runtime_error("invalid modeled timestamp");
      history.push_back(parent_time); if (history.size() > 11) history.erase(history.begin());
      ++height; ++total_blocks; malicious += bad; floor_blocks += difficulty == 20;
    }
    if (height == 100000) ++truncated;
    // Include the final right-censored wait in the maximum, but not in the
    // completed-gap mean. Report the censoring instead of manufacturing a block.
    largest = std::max(largest, horizon-last);
    hour_runs += largest > 3600;
    maximum_gaps.push_back(largest); counts.push_back(double(height));
    mean_gaps.push_back(height ? sum/height : 0);
  }
  auto quantile = [](std::vector<double> values, double p) {
    std::sort(values.begin(), values.end()); return values[size_t((values.size()-1)*p)];
  };
  std::cout << "{\"scenario\":\"" << scenario.name << "\",\"seeds\":" << seeds
    << ",\"days\":30,\"attackerFraction\":" << scenario.attacker
    << ",\"totalBlocks\":" << total_blocks << ",\"maliciousBlocks\":" << malicious
    << ",\"floorBlocks\":" << floor_blocks << ",\"runsWithHourGap\":" << hour_runs
    << ",\"blockLimitTruncatedRuns\":" << truncated
    << ",\"blocksMedian\":" << quantile(counts,.5)
    << ",\"completedGapMeanMedianSeconds\":" << quantile(mean_gaps,.5)
    << ",\"maximumGapP95Seconds\":" << quantile(maximum_gaps,.95)
    << ",\"worstGapSeconds\":" << quantile(maximum_gaps,1) << "}" << std::endl;
}
int main() {
  for (const auto& scenario : std::vector<Scenario>{
      {"stable",0,false}, {"very-low-participation",0,false},
      {"daily-eight-hours",0,false}, {"week-outage",0,false},
      {"ninety-percent-departure",0,false}, {"hundredfold-burst-return",0,false},
      {"earliest-median-40",.4,true}, {"earliest-median-51",.51,true},
      {"future-edge-40",.4,false}, {"future-edge-51",.51,false}}) study(scenario);
}
