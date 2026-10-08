#!/usr/bin/env python3
"""Blockchain::init discarded HardFork::add_fork()'s return value.

add_fork() returns false for any entry that is out of order:

    if (!heights.empty()) {
      if (version <= heights.back().version) return false;
      if (height  <= heights.back().height)  return false;
      if (time    <= heights.back().time)    return false;
    }

and HardFork::init() pushes a placeholder when the table is still empty:

    if (heights.empty())
      heights.push_back(hardfork_t(original_version, 0, 0, 0));

So if init() ever ran before the add_fork() loop, MeepCoin's single entry
{version 16, height 0, threshold 0, time 1785283200} would hit
`version <= heights.back().version` (16 <= 16) and be **silently discarded** -- upstream never
looked at the result. The daemon would then boot on a table nobody configured.

Precise about the blast radius: since the earlier patch sets original_version to
CURRENT_BLOCK_MAJOR_VERSION, that placeholder is {16, height 0, threshold 0, time 0} -- the same
version and height as the intended entry, but not its threshold or time. So the failure mode is a
table that happens to look right rather than a table that is obviously empty, which is worse to
diagnose, not better.

Fix, in three parts:
  1. Collect the schedule for the active network, then add every entry with its return value
     checked. A rejected entry aborts startup with a message naming the entry.
  2. Refuse to start on an empty schedule.
  3. After init(), verify the resulting table against the configured schedule entry by entry,
     and additionally assert version >= 16 at height 0 on the MeepCoin networks.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_core/blockchain.cpp")
MARK = "MeepCoin: add_fork() return values are checked"

OLD = """  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      m_hardfork->add_fork(test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, n + 1);
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < num_testnet_hard_forks; ++n)
      m_hardfork->add_fork(testnet_hard_forks[n].version, testnet_hard_forks[n].height, testnet_hard_forks[n].threshold, testnet_hard_forks[n].time);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < num_stagenet_hard_forks; ++n)
      m_hardfork->add_fork(stagenet_hard_forks[n].version, stagenet_hard_forks[n].height, stagenet_hard_forks[n].threshold, stagenet_hard_forks[n].time);
  }
  else
  {
    for (size_t n = 0; n < num_mainnet_hard_forks; ++n)
      m_hardfork->add_fork(mainnet_hard_forks[n].version, mainnet_hard_forks[n].height, mainnet_hard_forks[n].threshold, mainnet_hard_forks[n].time);
  }
  m_hardfork->init();
"""

NEW = """  // """ + MARK + """.
  //
  // add_fork() returns false for any out-of-order entry, and upstream discarded that result.
  // MeepCoin's schedule is the single entry {version 16, height 0}, so a rejection would leave
  // the table holding only HardFork::init()'s placeholder and the daemon would boot on consensus
  // rules that were never configured. Collect the schedule first, then add it checked.
  std::vector<::hardfork_t> meep_schedule;
  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      meep_schedule.push_back(::hardfork_t{test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, (time_t)(n + 1)});
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < num_testnet_hard_forks; ++n)
      meep_schedule.push_back(testnet_hard_forks[n]);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < num_stagenet_hard_forks; ++n)
      meep_schedule.push_back(stagenet_hard_forks[n]);
  }
  else
  {
    for (size_t n = 0; n < num_mainnet_hard_forks; ++n)
      meep_schedule.push_back(mainnet_hard_forks[n]);
  }

  if (meep_schedule.empty())
  {
    MERROR("FATAL: the hard fork schedule for this network is empty. Refusing to start.");
    return false;
  }

  for (const ::hardfork_t &f : meep_schedule)
  {
    if (!m_hardfork->add_fork(f.version, f.height, f.threshold, f.time))
    {
      MERROR("FATAL: HardFork::add_fork() rejected version " << (unsigned)f.version
          << " at height " << f.height << " (threshold " << (unsigned)f.threshold
          << ", time " << (uint64_t)f.time << "). The hard fork table would be incomplete and the "
          << "daemon would run consensus rules that were never configured. Refusing to start.");
      return false;
    }
  }
  m_hardfork->init();

  // Verify the table really holds what was configured, after init() has run. init() only pushes
  // its placeholder when the table is empty, so a correct table must match the schedule exactly.
  {
    const std::vector<::hardfork_t> &installed = m_hardfork->get_hardforks();
    if (installed.size() != meep_schedule.size())
    {
      MERROR("FATAL: hard fork table has " << installed.size() << " entries, expected "
          << meep_schedule.size() << ". Refusing to start.");
      return false;
    }
    for (size_t n = 0; n < installed.size(); ++n)
    {
      if (installed[n].version != meep_schedule[n].version || installed[n].height != meep_schedule[n].height)
      {
        MERROR("FATAL: hard fork table entry " << n << " is version " << (unsigned)installed[n].version
            << " at height " << installed[n].height << ", expected version "
            << (unsigned)meep_schedule[n].version << " at height " << meep_schedule[n].height
            << ". Refusing to start.");
        return false;
      }
    }
    // MeepCoin runs the modern ruleset from genesis on every real network slot. FAKECHAIN is
    // exempt because its schedule comes from test_options and tests legitimately use old versions.
    if (m_nettype != FAKECHAIN)
    {
      const uint8_t v_at_zero = m_hardfork->get_ideal_version(0);
      if (v_at_zero < CURRENT_BLOCK_MAJOR_VERSION)
      {
        MERROR("FATAL: hard fork table reports version " << (unsigned)v_at_zero << " at height 0, "
            << "expected at least " << (unsigned)CURRENT_BLOCK_MAJOR_VERSION
            << ". Refusing to start.");
        return false;
      }
      MINFO("hard fork table verified: " << installed.size() << " entry/entries, version "
          << (unsigned)v_at_zero << " from height 0");
    }
  }
"""

s = open(P).read()
if MARK in s:
    print("= add_fork return-value checking already patched")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found in Blockchain::init")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ add_fork() return values checked; post-init table verified")
print("HARDFORK_ADD_FORK_CHECKED_OK")
