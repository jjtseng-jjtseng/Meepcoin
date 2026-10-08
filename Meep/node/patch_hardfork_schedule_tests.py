#!/usr/bin/env python3
"""Append real-HardFork regression tests for the schedule install/verify guard.

These run against the actual cryptonote::HardFork over Monero's TestDB -- not a reimplementation --
so they test the code that ships. They cover:

  * the MeepCoin sparse schedule installing and verifying cleanly
  * REVERSED INITIALIZATION ORDERING: init() before add_fork(). Two tests, because there are two
    things worth proving separately: that the real add_fork() genuinely discards the entry (the
    silent failure upstream ignored), and that the guard refuses instead of continuing.
  * an empty schedule
  * a duplicate entry
  * a descending height
  * the height-0 version floor
  * DENSE Monero-style schedules still installing and still selecting the right version per
    height, so the fix cannot have broken upstream's normal case

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "tests/unit_tests/hardfork.cpp")
MARK = "meepcoin_sparse_schedule_installs_and_verifies"

TESTS = r'''

// ---------------------------------------------------------------------------------------------
// MeepCoin: regression tests for install_and_verify_hardfork_schedule().
//
// Context: Blockchain::init() used to call HardFork::add_fork() and discard the return value.
// add_fork() rejects any out-of-order entry, and HardFork::init() pushes a placeholder entry when
// the table is still empty. MeepCoin's schedule is the single entry {version 16, height 0}, so if
// init() ever ran first, add_fork(16, 0, ...) would fail `version <= heights.back().version` and
// be dropped without a word. These tests pin that down.
// ---------------------------------------------------------------------------------------------

static std::vector<::hardfork_t> meepcoin_schedule()
{
  // Matches src/hardforks/hardforks.cpp: a single entry, version 16 from height 0.
  return { ::hardfork_t{16, 0, 0, 1785283200} };
}

static std::vector<::hardfork_t> dense_monero_style_schedule()
{
  // Upstream shape: consecutive versions at ascending heights, ascending times.
  std::vector<::hardfork_t> s;
  for (uint8_t v = 1; v <= 16; ++v)
    s.push_back(::hardfork_t{v, (uint64_t)(v - 1) * 100, 0, (time_t)v});
  return s;
}

TEST(hardfork, meepcoin_sparse_schedule_installs_and_verifies)
{
  TestDB db;
  HardFork hf(db, 16, 0);
  std::string err;

  ASSERT_TRUE(install_and_verify_hardfork_schedule(hf, meepcoin_schedule(), 16, err)) << err;
  ASSERT_TRUE(err.empty());

  // The table must hold exactly the configured entry -- not a placeholder that resembles it.
  ASSERT_EQ(hf.get_hardforks().size(), 1u);
  ASSERT_EQ(hf.get_hardforks()[0].version, 16);
  ASSERT_EQ(hf.get_hardforks()[0].height, 0u);
  ASSERT_EQ(hf.get_hardforks()[0].threshold, 0);
  ASSERT_EQ(hf.get_hardforks()[0].time, 1785283200);   // NOT init()'s placeholder time of 0

  ASSERT_EQ(hf.get_ideal_version(0), 16);
  ASSERT_EQ(hf.get_ideal_version(1), 16);
  ASSERT_EQ(hf.get_ideal_version(2113), 16);
}

TEST(hardfork, meepcoin_reversed_ordering_really_does_discard_the_entry)
{
  // Evidence that the silent failure is real, at the level of the class itself.
  TestDB db;
  HardFork hf(db, 16, 0);

  hf.init();                                  // <-- deliberately out of order
  ASSERT_EQ(hf.get_hardforks().size(), 1u);   // placeholder is in place
  ASSERT_EQ(hf.get_hardforks()[0].time, 0);   // and it is the placeholder, not the real entry

  // The real schedule entry is now rejected: 16 <= 16 on version.
  ASSERT_FALSE(hf.add_fork(16, 0, 0, 1785283200));

  // Upstream ignored that false. The table still has one entry at version 16 height 0, so a check
  // that only compared version and height would be fooled -- which is exactly why the guard
  // requires the table to be empty before installing, and compares threshold-bearing entries.
  ASSERT_EQ(hf.get_hardforks().size(), 1u);
  ASSERT_EQ(hf.get_hardforks()[0].version, 16);
  ASSERT_EQ(hf.get_hardforks()[0].height, 0u);
}

TEST(hardfork, meepcoin_reversed_ordering_is_refused_not_absorbed)
{
  // Same disruption, now through the guard: it must fail loudly instead of continuing.
  TestDB db;
  HardFork hf(db, 16, 0);
  std::string err;

  hf.init();                                  // <-- deliberately out of order

  ASSERT_FALSE(install_and_verify_hardfork_schedule(hf, meepcoin_schedule(), 16, err));
  ASSERT_FALSE(err.empty());
  ASSERT_NE(err.find("out of order"), std::string::npos) << err;
}

TEST(hardfork, meepcoin_empty_schedule_is_refused)
{
  TestDB db;
  HardFork hf(db, 16, 0);
  std::string err;

  ASSERT_FALSE(install_and_verify_hardfork_schedule(hf, {}, 16, err));
  ASSERT_NE(err.find("empty"), std::string::npos) << err;
}

TEST(hardfork, meepcoin_duplicate_entry_is_refused)
{
  TestDB db;
  HardFork hf(db, 16, 0);
  std::string err;

  std::vector<::hardfork_t> s = meepcoin_schedule();
  s.push_back(s[0]);   // same version, same height, same time

  ASSERT_FALSE(install_and_verify_hardfork_schedule(hf, s, 16, err));
  ASSERT_NE(err.find("rejected schedule entry 1"), std::string::npos) << err;
}

TEST(hardfork, meepcoin_descending_height_is_refused)
{
  TestDB db;
  HardFork hf(db, 16, 0);
  std::string err;

  std::vector<::hardfork_t> s = { ::hardfork_t{16, 100, 0, 10}, ::hardfork_t{17, 50, 0, 20} };

  ASSERT_FALSE(install_and_verify_hardfork_schedule(hf, s, 16, err));
  ASSERT_NE(err.find("rejected schedule entry 1"), std::string::npos) << err;
}

TEST(hardfork, meepcoin_height_zero_version_floor_is_enforced)
{
  // A schedule that installs cleanly but starts below the required version must still be refused.
  TestDB db;
  HardFork hf(db, 1, 0);
  std::string err;

  std::vector<::hardfork_t> s = { ::hardfork_t{1, 0, 0, 10}, ::hardfork_t{16, 500, 0, 20} };

  ASSERT_FALSE(install_and_verify_hardfork_schedule(hf, s, 16, err));
  ASSERT_NE(err.find("at height 0"), std::string::npos) << err;
}

TEST(hardfork, meepcoin_dense_monero_style_schedule_still_installs)
{
  // The guard must not have broken upstream's normal dense schedule.
  TestDB db;
  HardFork hf(db, 1, 0);
  std::string err;

  const std::vector<::hardfork_t> s = dense_monero_style_schedule();
  ASSERT_TRUE(install_and_verify_hardfork_schedule(hf, s, 0, err)) << err;

  ASSERT_EQ(hf.get_hardforks().size(), s.size());
  for (size_t n = 0; n < s.size(); ++n)
  {
    ASSERT_EQ(hf.get_hardforks()[n].version, s[n].version);
    ASSERT_EQ(hf.get_hardforks()[n].height, s[n].height);
  }
}

TEST(hardfork, meepcoin_dense_schedule_still_selects_the_right_version_per_height)
{
  TestDB db;
  HardFork hf(db, 1, 0);
  std::string err;

  ASSERT_TRUE(install_and_verify_hardfork_schedule(hf, dense_monero_style_schedule(), 0, err)) << err;

  // Entry v is at height (v-1)*100.
  ASSERT_EQ(hf.get_ideal_version(0),    1);
  ASSERT_EQ(hf.get_ideal_version(99),   1);
  ASSERT_EQ(hf.get_ideal_version(100),  2);
  ASSERT_EQ(hf.get_ideal_version(101),  2);
  ASSERT_EQ(hf.get_ideal_version(1499), 15);
  ASSERT_EQ(hf.get_ideal_version(1500), 16);
  ASSERT_EQ(hf.get_ideal_version(999999), 16);
}

TEST(hardfork, meepcoin_dense_schedule_with_a_gap_installs_and_selects_correctly)
{
  // Sparse-but-not-single: versions 1 and 16 only. Neither shape may regress.
  TestDB db;
  HardFork hf(db, 1, 0);
  std::string err;

  const std::vector<::hardfork_t> s = { ::hardfork_t{1, 0, 0, 10}, ::hardfork_t{16, 1000, 0, 20} };
  ASSERT_TRUE(install_and_verify_hardfork_schedule(hf, s, 0, err)) << err;

  ASSERT_EQ(hf.get_ideal_version(0),    1);
  ASSERT_EQ(hf.get_ideal_version(999),  1);
  ASSERT_EQ(hf.get_ideal_version(1000), 16);
  ASSERT_EQ(hf.get_ideal_version(5000), 16);
}
'''

s = open(P).read()
if MARK in s:
    print("= schedule regression tests already present")
    sys.exit(0)

need = '#include "hardforks/hardforks.h"'
if need not in s:
    s = s.replace('#include "blockchain_db/testdb.h"',
                  '#include "blockchain_db/testdb.h"\n#include "hardforks/hardforks.h"', 1)
    print("+ added hardforks.h include")

open(P, "w").write(s.rstrip("\n") + "\n" + TESTS)
print("+ appended 10 real-HardFork schedule regression tests")
print("HARDFORK_SCHEDULE_TESTS_OK")
