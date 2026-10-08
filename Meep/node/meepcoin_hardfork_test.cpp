// MeepCoin: regression tests for install_and_verify_hardfork_schedule().
//
// These run against the REAL cryptonote::HardFork over the real src/blockchain_db/testdb.h, not a
// reimplementation, so they test the code that ships in the daemon.
//
// Why this is a standalone binary rather than a case in tests/unit_tests/hardfork.cpp: the pinned
// build configures BUILD_TESTS=OFF, so anything added there would never run. A test that never runs
// is worse than no test, because it looks like coverage.
//
// Context being pinned down: Blockchain::init() used to call HardFork::add_fork() and discard the
// return value. add_fork() rejects any out-of-order entry, and HardFork::init() pushes a
// placeholder when the table is still empty. MeepCoin's schedule is the single entry
// {version 16, height 0}, so if init() ever ran first, add_fork(16, 0, ...) would fail
// `version <= heights.back().version` and vanish silently.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "cryptonote_basic/cryptonote_format_utils.h"   // testdb.h needs t_serializable_object_to_blob
#include "cryptonote_basic/hardfork.h"
#include "blockchain_db/testdb.h"
#include "hardforks/hardforks.h"
#include "cryptonote_config.h"

using namespace cryptonote;

namespace
{

class TestDB : public cryptonote::BaseTestDB
{
public:
  virtual uint64_t height() const override { return blocks.size(); }
  virtual void add_block(const cryptonote::block &blk, size_t, uint64_t,
                         const cryptonote::difficulty_type &, const uint64_t &, uint64_t,
                         const crypto::hash &) override { blocks.push_back(blk); }
  virtual void remove_block() override { blocks.pop_back(); }
  virtual cryptonote::block get_block_from_height(const uint64_t &h) const override { return blocks.at(h); }
  virtual void set_hard_fork_version(uint64_t h, uint8_t v) override
  {
    if (versions.size() <= h) versions.resize(h + 1);
    versions[h] = v;
  }
  virtual uint8_t get_hard_fork_version(uint64_t h) const override { return versions.at(h); }
  virtual crypto::hash get_block_hash_from_height(const uint64_t &h) const override
  {
    crypto::hash hash = crypto::null_hash;
    *(uint64_t *)&hash = h;
    return hash;
  }

private:
  std::vector<cryptonote::block> blocks;
  std::vector<uint8_t> versions;
};

int g_pass = 0, g_fail = 0;

void chk(bool cond, const char *label)
{
  if (cond) { ++g_pass; printf("  [PASS] %s\n", label); }
  else      { ++g_fail; printf("  [FAIL] %s\n", label); }
}

void chk_contains(const std::string &haystack, const char *needle, const char *label)
{
  const bool ok = haystack.find(needle) != std::string::npos;
  if (ok) { ++g_pass; printf("  [PASS] %s\n", label); }
  else    { ++g_fail; printf("  [FAIL] %s  (error was: \"%s\")\n", label, haystack.c_str()); }
}

// Matches src/hardforks/hardforks.cpp: a single entry, version 16 from height 0.
std::vector<::hardfork_t> meepcoin_schedule()
{
  return { ::hardfork_t{16, 0, 0, 1785283200} };
}

// Upstream shape: consecutive versions at ascending heights and ascending times.
std::vector<::hardfork_t> dense_monero_style_schedule()
{
  std::vector<::hardfork_t> s;
  for (uint8_t v = 1; v <= 16; ++v)
    s.push_back(::hardfork_t{v, (uint64_t)(v - 1) * 100, 0, (time_t)v});
  return s;
}

} // namespace

int main()
{
  printf("MeepCoin hard-fork schedule regression tests (real HardFork class)\n");
  printf("=================================================================\n\n");

  // ---------------------------------------------------------------------------------------
  printf("1. MeepCoin sparse schedule installs and verifies\n");
  {
    TestDB db;
    HardFork hf(db, 16, 0);
    std::string err;

    chk(install_and_verify_hardfork_schedule(hf, meepcoin_schedule(), 16, err),
        "install_and_verify_hardfork_schedule succeeds");
    chk(err.empty(), "no error message on success");
    chk(hf.get_hardforks().size() == 1, "table holds exactly 1 entry");
    chk(hf.get_hardforks()[0].version == 16, "entry version is 16");
    chk(hf.get_hardforks()[0].height == 0, "entry height is 0");
    // The decisive one: init()'s placeholder carries time 0. The configured entry does not.
    chk(hf.get_hardforks()[0].time == 1785283200,
        "entry time is the configured 1785283200, NOT init()'s placeholder 0");
    chk(hf.get_ideal_version(0) == 16, "get_ideal_version(0) == 16");
    chk(hf.get_ideal_version(1) == 16, "get_ideal_version(1) == 16");
    chk(hf.get_ideal_version(2113) == 16, "get_ideal_version(2113) == 16");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n2. Reversed ordering really does discard the entry (the silent failure is real)\n");
  {
    TestDB db;
    HardFork hf(db, 16, 0);

    hf.init();   // <-- deliberately out of order

    chk(hf.get_hardforks().size() == 1, "init() pushed its placeholder");
    chk(hf.get_hardforks()[0].time == 0, "the entry present is the placeholder (time 0)");
    chk(!hf.add_fork(16, 0, 0, 1785283200),
        "add_fork() REJECTS the real schedule entry (16 <= 16 on version)");
    // Upstream ignored that false. Note the table still reads version 16 at height 0, so a check
    // comparing only version and height would be fooled -- which is why the guard requires an
    // empty table before installing.
    chk(hf.get_hardforks().size() == 1, "table still has 1 entry -- the rejection left no trace");
    chk(hf.get_hardforks()[0].version == 16 && hf.get_hardforks()[0].height == 0,
        "and it still reads version 16 at height 0, which is why version+height alone is not enough");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n3. Reversed ordering is refused by the guard, not absorbed\n");
  {
    TestDB db;
    HardFork hf(db, 16, 0);
    std::string err;

    hf.init();   // <-- deliberately out of order

    chk(!install_and_verify_hardfork_schedule(hf, meepcoin_schedule(), 16, err),
        "install_and_verify_hardfork_schedule FAILS");
    chk(!err.empty(), "an error message is produced");
    chk_contains(err, "out of order", "the error names the ordering problem");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n4. Disrupted initialization: a stray pre-existing entry\n");
  {
    TestDB db;
    HardFork hf(db, 16, 0);
    std::string err;

    chk(hf.add_fork(16, 0, 0, 1785283200), "a first add_fork succeeds");
    chk(!install_and_verify_hardfork_schedule(hf, meepcoin_schedule(), 16, err),
        "installing over a non-empty table FAILS");
    chk_contains(err, "already has", "the error reports the pre-existing entries");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n5. Empty schedule is refused\n");
  {
    TestDB db;
    HardFork hf(db, 16, 0);
    std::string err;

    chk(!install_and_verify_hardfork_schedule(hf, {}, 16, err), "an empty schedule FAILS");
    chk_contains(err, "empty", "the error says the schedule is empty");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n6. Malformed schedules are refused\n");
  {
    {
      TestDB db; HardFork hf(db, 16, 0); std::string err;
      std::vector<::hardfork_t> s = meepcoin_schedule();
      s.push_back(s[0]);   // exact duplicate
      chk(!install_and_verify_hardfork_schedule(hf, s, 16, err), "duplicate entry FAILS");
      chk_contains(err, "rejected schedule entry 1", "the error identifies entry 1");
    }
    {
      TestDB db; HardFork hf(db, 16, 0); std::string err;
      std::vector<::hardfork_t> s = { ::hardfork_t{16, 100, 0, 10}, ::hardfork_t{17, 50, 0, 20} };
      chk(!install_and_verify_hardfork_schedule(hf, s, 16, err), "descending height FAILS");
      chk_contains(err, "rejected schedule entry 1", "the error identifies entry 1");
    }
    {
      TestDB db; HardFork hf(db, 16, 0); std::string err;
      std::vector<::hardfork_t> s = { ::hardfork_t{16, 0, 0, 20}, ::hardfork_t{17, 100, 0, 10} };
      chk(!install_and_verify_hardfork_schedule(hf, s, 16, err), "descending time FAILS");
    }
    {
      TestDB db; HardFork hf(db, 16, 0); std::string err;
      std::vector<::hardfork_t> s = { ::hardfork_t{0, 0, 0, 10} };
      chk(!install_and_verify_hardfork_schedule(hf, s, 16, err), "version 0 FAILS");
    }
  }

  // ---------------------------------------------------------------------------------------
  printf("\n7. Height-0 version floor is enforced\n");
  {
    TestDB db;
    HardFork hf(db, 1, 0);
    std::string err;

    // Installs cleanly, but starts below version 16.
    std::vector<::hardfork_t> s = { ::hardfork_t{1, 0, 0, 10}, ::hardfork_t{16, 500, 0, 20} };
    chk(!install_and_verify_hardfork_schedule(hf, s, 16, err),
        "a schedule starting at version 1 FAILS the version-16 floor");
    chk_contains(err, "at height 0", "the error names height 0");
  }
  {
    TestDB db;
    HardFork hf(db, 1, 0);
    std::string err;
    std::vector<::hardfork_t> s = { ::hardfork_t{1, 0, 0, 10}, ::hardfork_t{16, 500, 0, 20} };
    chk(install_and_verify_hardfork_schedule(hf, s, 0, err),
        "the same schedule PASSES when the floor is disabled (FAKECHAIN case)");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n8. Dense Monero-style schedules are preserved\n");
  {
    TestDB db;
    HardFork hf(db, 1, 0);
    std::string err;
    const std::vector<::hardfork_t> s = dense_monero_style_schedule();

    chk(install_and_verify_hardfork_schedule(hf, s, 0, err), "a dense 1..16 schedule installs");
    chk(hf.get_hardforks().size() == s.size(), "all 16 entries are present");

    bool all_match = true;
    for (size_t n = 0; n < s.size(); ++n)
      if (hf.get_hardforks()[n].version != s[n].version || hf.get_hardforks()[n].height != s[n].height)
        all_match = false;
    chk(all_match, "every dense entry matches what was configured");

    chk(hf.get_ideal_version(0) == 1,       "dense: height 0 -> v1");
    chk(hf.get_ideal_version(99) == 1,      "dense: height 99 -> v1");
    chk(hf.get_ideal_version(100) == 2,     "dense: height 100 -> v2");
    chk(hf.get_ideal_version(1499) == 15,   "dense: height 1499 -> v15");
    chk(hf.get_ideal_version(1500) == 16,   "dense: height 1500 -> v16");
    chk(hf.get_ideal_version(999999) == 16, "dense: far future -> v16");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n9. Sparse-but-not-single schedules also work (neither shape may regress)\n");
  {
    TestDB db;
    HardFork hf(db, 1, 0);
    std::string err;
    const std::vector<::hardfork_t> s = { ::hardfork_t{1, 0, 0, 10}, ::hardfork_t{16, 1000, 0, 20} };

    chk(install_and_verify_hardfork_schedule(hf, s, 0, err), "a {v1, v16} schedule installs");
    chk(hf.get_ideal_version(0) == 1,     "gap: height 0 -> v1");
    chk(hf.get_ideal_version(999) == 1,   "gap: height 999 -> v1");
    chk(hf.get_ideal_version(1000) == 16, "gap: height 1000 -> v16");
    chk(hf.get_ideal_version(5000) == 16, "gap: height 5000 -> v16");
  }

  // ---------------------------------------------------------------------------------------
  printf("\n10. The compiled MeepCoin schedule itself installs and verifies\n");
  {
    // Not a hand-written schedule: the actual arrays the daemon uses.
    struct { const char *name; const ::hardfork_t *forks; size_t n; } nets[] = {
      { "mainnet slot",  mainnet_hard_forks,  num_mainnet_hard_forks  },
      { "testnet slot",  testnet_hard_forks,  num_testnet_hard_forks  },
      { "stagenet slot", stagenet_hard_forks, num_stagenet_hard_forks },
    };
    for (const auto &net : nets)
    {
      TestDB db;
      HardFork hf(db, CURRENT_BLOCK_MAJOR_VERSION, 0);
      std::string err;
      const std::vector<::hardfork_t> s(net.forks, net.forks + net.n);

      char label[160];
      snprintf(label, sizeof(label), "%s: compiled schedule installs and verifies", net.name);
      chk(install_and_verify_hardfork_schedule(hf, s, CURRENT_BLOCK_MAJOR_VERSION, err), label);

      snprintf(label, sizeof(label), "%s: version %u at height 0", net.name,
               (unsigned)CURRENT_BLOCK_MAJOR_VERSION);
      chk(hf.get_ideal_version(0) == CURRENT_BLOCK_MAJOR_VERSION, label);
    }
  }

  printf("\n=================================================================\n");
  printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
  printf("HARDFORK SCHEDULE TESTS: %s\n", g_fail == 0 ? "PASS" : "FAIL");
  return g_fail == 0 ? 0 : 1;
}
