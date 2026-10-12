// Copyright (c) 2014-2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <cstdio>

#include "cryptonote_basic/cryptonote_basic.h"
#include "blockchain_db/blockchain_db.h"
#include "hardfork.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "hardfork"

using namespace cryptonote;

namespace cryptonote
{

bool install_and_verify_hardfork_schedule(HardFork &hf,
                                          const std::vector<::hardfork_t> &schedule,
                                          uint8_t min_version_at_height_zero,
                                          std::string &error)
{
  error.clear();

  if (schedule.empty())
  {
    error = "hard fork schedule is empty";
    return false;
  }

  if (!hf.get_hardforks().empty())
  {
    error = "hard fork table already has " + std::to_string(hf.get_hardforks().size())
          + " entries before installing the schedule -- init() or add_fork() ran out of order";
    return false;
  }

  for (size_t n = 0; n < schedule.size(); ++n)
  {
    const ::hardfork_t &f = schedule[n];
    if (!hf.add_fork(f.version, f.height, f.threshold, f.time))
    {
      error = "add_fork() rejected schedule entry " + std::to_string(n) + ": version "
            + std::to_string((unsigned)f.version) + " at height " + std::to_string(f.height)
            + " (threshold " + std::to_string((unsigned)f.threshold) + ", time "
            + std::to_string((uint64_t)f.time) + ")";
      return false;
    }
  }

  hf.init();

  const std::vector<::hardfork_t> &installed = hf.get_hardforks();
  if (installed.size() != schedule.size())
  {
    error = "hard fork table has " + std::to_string(installed.size()) + " entries, expected "
          + std::to_string(schedule.size());
    return false;
  }
  for (size_t n = 0; n < installed.size(); ++n)
  {
    if (installed[n].version != schedule[n].version || installed[n].height != schedule[n].height)
    {
      error = "hard fork table entry " + std::to_string(n) + " is version "
            + std::to_string((unsigned)installed[n].version) + " at height "
            + std::to_string(installed[n].height) + ", expected version "
            + std::to_string((unsigned)schedule[n].version) + " at height "
            + std::to_string(schedule[n].height);
      return false;
    }
  }

  if (min_version_at_height_zero != 0)
  {
    const uint8_t v0 = hf.get_ideal_version(0);
    if (v0 < min_version_at_height_zero)
    {
      error = "hard fork table reports version " + std::to_string((unsigned)v0)
            + " at height 0, expected at least "
            + std::to_string((unsigned)min_version_at_height_zero);
      return false;
    }
  }

  return true;
}

}

static uint8_t get_block_vote(const cryptonote::block &b)
{
  // Pre-hardfork blocks have a minor version hardcoded to 0.
  // For the purposes of voting, we consider 0 to refer to
  // version number 1, which is what all blocks from the genesis
  // block are. It makes things simpler.
  if (b.minor_version == 0)
    return 1;
  return b.minor_version;
}

static uint8_t get_block_version(const cryptonote::block &b)
{
  return b.major_version;
}

HardFork::HardFork(cryptonote::BlockchainDB &db, uint8_t original_version, uint64_t original_version_till_height, time_t forked_time, time_t update_time, uint64_t window_size, uint8_t default_threshold_percent):
  db(db),
  forked_time(forked_time),
  update_time(update_time),
  window_size(window_size),
  default_threshold_percent(default_threshold_percent),
  original_version(original_version),
  original_version_till_height(original_version_till_height),
  current_fork_index(0)
{
  if (window_size == 0)
    throw "window_size needs to be strictly positive";
  if (default_threshold_percent > 100)
    throw "default_threshold_percent needs to be between 0 and 100";
}

bool HardFork::add_fork(uint8_t version, uint64_t height, uint8_t threshold, time_t time)
{
  CRITICAL_REGION_LOCAL(lock);

  // add in order
  if (version == 0)
    return false;
  if (!heights.empty()) {
    if (version <= heights.back().version)
      return false;
    if (height <= heights.back().height)
      return false;
    if (time <= heights.back().time)
      return false;
  }
  if (threshold > 100)
    return false;
  heights.push_back(hardfork_t(version, height, threshold, time));
  return true;
}

bool HardFork::add_fork(uint8_t version, uint64_t height, time_t time)
{
  return add_fork(version, height, default_threshold_percent, time);
}

uint8_t HardFork::get_effective_version(uint8_t voting_version) const
{
  if (!heights.empty()) {
    uint8_t max_version = heights.back().version;
    if (voting_version > max_version)
      voting_version = max_version;
  }
  return voting_version;
}

bool HardFork::do_check(uint8_t block_version, uint8_t voting_version) const
{
  return block_version == heights[current_fork_index].version
      && voting_version >= heights[current_fork_index].version;
}

bool HardFork::check(const cryptonote::block &block) const
{
  CRITICAL_REGION_LOCAL(lock);
  return do_check(::get_block_version(block), ::get_block_vote(block));
}

bool HardFork::do_check_for_height(uint8_t block_version, uint8_t voting_version, uint64_t height) const
{
  int fork_index = get_voted_fork_index(height);
  return block_version == heights[fork_index].version
      && voting_version >= heights[fork_index].version;
}

bool HardFork::check_for_height(const cryptonote::block &block, uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  return do_check_for_height(::get_block_version(block), ::get_block_vote(block), height);
}

bool HardFork::add(uint8_t block_version, uint8_t voting_version, uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);

  if (!do_check(block_version, voting_version))
    return false;

  db.set_hard_fork_version(height, heights[current_fork_index].version);

  voting_version = get_effective_version(voting_version);

  while (versions.size() >= window_size) {
    const uint8_t old_version = versions.front();
    assert(last_versions[old_version] >= 1);
    last_versions[old_version]--;
    versions.pop_front();
  }

  last_versions[voting_version]++;
  versions.push_back(voting_version);

  uint8_t voted = get_voted_fork_index(height + 1);
  if (voted > current_fork_index) {
    current_fork_index = voted;
  }

  return true;
}

bool HardFork::add(const cryptonote::block &block, uint64_t height)
{
  return add(::get_block_version(block), ::get_block_vote(block), height);
}

void HardFork::init()
{
  CRITICAL_REGION_LOCAL(lock);

  // add a placeholder for the default version, to avoid special cases
  if (heights.empty())
    heights.push_back(hardfork_t(original_version, 0, 0, 0));

  versions.clear();
  for (size_t n = 0; n < 256; ++n)
    last_versions[n] = 0;
  current_fork_index = 0;

  // restore state from DB
  uint64_t height = db.height();
  if (height > window_size)
    height -= window_size - 1;
  else
    height = 1;

  rescan_from_chain_height(height);
  MDEBUG("init done");
}

uint8_t HardFork::get_block_version(uint64_t height) const
{
  if (height <= original_version_till_height)
    return original_version;

  const cryptonote::block &block = db.get_block_from_height(height);
  return ::get_block_version(block);
}

bool HardFork::reorganize_from_block_height(uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);
  if (height >= db.height())
    return false;

  bool stop_batch = db.batch_start();

  versions.clear();

  for (size_t n = 0; n < 256; ++n)
    last_versions[n] = 0;
  const uint64_t rescan_height = height >= (window_size - 1) ? height - (window_size  -1) : 0;
  const uint8_t start_version = height == 0 ? original_version : db.get_hard_fork_version(height);
  while (current_fork_index > 0 && heights[current_fork_index].version > start_version) {
    --current_fork_index;
  }
  for (uint64_t h = rescan_height; h <= height; ++h) {
    cryptonote::block b = db.get_block_from_height(h);
    const uint8_t v = get_effective_version(get_block_vote(b));
    last_versions[v]++;
    versions.push_back(v);
  }

  uint8_t voted = get_voted_fork_index(height + 1);
  if (voted > current_fork_index) {
    current_fork_index = voted;
  }

  const uint64_t bc_height = db.height();
  for (uint64_t h = height + 1; h < bc_height; ++h) {
    add(db.get_block_from_height(h), h);
  }

  if (stop_batch)
    db.batch_stop();

  return true;
}

bool HardFork::reorganize_from_chain_height(uint64_t height)
{
  if (height == 0)
    return false;
  return reorganize_from_block_height(height - 1);
}

bool HardFork::rescan_from_block_height(uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);
  db_rtxn_guard rtxn_guard(&db);
  if (height >= db.height())
    return false;

  versions.clear();

  for (size_t n = 0; n < 256; ++n)
    last_versions[n] = 0;
  for (uint64_t h = height; h < db.height(); ++h) {
    cryptonote::block b = db.get_block_from_height(h);
    const uint8_t v = get_effective_version(get_block_vote(b));
    last_versions[v]++;
    versions.push_back(v);
  }

  uint8_t lastv = db.get_hard_fork_version(db.height() - 1);
  current_fork_index = 0;
  while (current_fork_index + 1 < heights.size() && heights[current_fork_index].version != lastv)
    ++current_fork_index;

  uint8_t voted = get_voted_fork_index(db.height());
  if (voted > current_fork_index) {
    current_fork_index = voted;
  }

  return true;
}

bool HardFork::rescan_from_chain_height(uint64_t height)
{
  if (height == 0)
    return false;
  return rescan_from_block_height(height - 1);
}

void HardFork::on_block_popped(uint64_t nblocks)
{
  CHECK_AND_ASSERT_THROW_MES(nblocks > 0, "nblocks must be greater than 0");

  CRITICAL_REGION_LOCAL(lock);

  const uint64_t new_chain_height = db.height();
  const uint64_t old_chain_height = new_chain_height + nblocks;
  uint8_t version;
  for (uint64_t height = old_chain_height - 1; height >= new_chain_height; --height)
  {
    version = versions.back();
    last_versions[version]--;
    versions.pop_back();
    version = db.get_hard_fork_version(height);
    versions.push_front(version);
    last_versions[version]++;
  }

  // does not take voting into account
  for (current_fork_index = heights.size() - 1; current_fork_index > 0; --current_fork_index)
    if (new_chain_height >= heights[current_fork_index].height)
      break;
}

int HardFork::get_voted_fork_index(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  uint32_t accumulated_votes = 0;
  for (int n = heights.size() - 1; n >= 0; --n) {
    uint8_t v = heights[n].version;
    accumulated_votes += last_versions[v];
    uint32_t threshold = (window_size * heights[n].threshold + 99) / 100;
    if (height >= heights[n].height && accumulated_votes >= threshold) {
      return n;
    }
  }
  return current_fork_index;
}

HardFork::State HardFork::get_state(time_t t) const
{
  CRITICAL_REGION_LOCAL(lock);

  // no hard forks setup yet
  if (heights.size() <= 1)
    return Ready;

  time_t t_last_fork = heights.back().time;
  if (t >= t_last_fork + forked_time)
    return LikelyForked;
  if (t >= t_last_fork + update_time)
    return UpdateNeeded;
  return Ready;
}

HardFork::State HardFork::get_state() const
{
  return get_state(time(NULL));
}

uint8_t HardFork::get(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  if (height > db.height()) {
    assert(false);
    return 255;
  }
  if (height == db.height()) {
    return get_current_version();
  }
  return db.get_hard_fork_version(height);
}

uint8_t HardFork::get_current_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  return heights[current_fork_index].version;
}

uint8_t HardFork::get_ideal_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  return heights.back().version;
}

uint8_t HardFork::get_ideal_version(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  // MeepCoin: scan every entry, including index 0. The original loop stopped before index 0,
  // relying on the first entry always being {version 1, height 1} (== original_version). MeepCoin
  // has a single {16, height 0} entry, so that loop never executed and this returned 1 for every
  // height -- which made the alternate-block path validate coinbases as version 1 and reject
  // txout_to_tagged_key outputs. Behaviour on a dense table is unchanged.
  for (unsigned int n = heights.size(); n-- > 0; ) {
    if (height >= heights[n].height) {
      return heights[n].version;
    }
  }
  return original_version;
}

uint64_t HardFork::get_earliest_ideal_height_for_version(uint8_t version) const
{
  uint64_t height = std::numeric_limits<uint64_t>::max();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (i->version >= version) {
      height = i->height;
    } else {
      break;
    }
  }
  return height;
}

uint8_t HardFork::get_next_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  uint64_t height = db.height();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (height >= i->height) {
      return (i == heights.rbegin() ? i : (i - 1))->version;
    }
  }
  return original_version;
}

bool HardFork::get_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  CRITICAL_REGION_LOCAL(lock);

  const uint8_t current_version = heights[current_fork_index].version;
  const bool enabled = current_version >= version;
  window = versions.size();
  votes = 0;
  for (size_t n = version; n < 256; ++n)
      votes += last_versions[n];
  threshold = (window * heights[current_fork_index].threshold + 99) / 100;
  //assert((votes >= threshold) == enabled);
  earliest_height = get_earliest_ideal_height_for_version(version);
  voting = heights.back().version;
  return enabled;
}

