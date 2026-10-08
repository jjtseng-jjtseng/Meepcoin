#!/usr/bin/env python3
"""Move the schedule install + verify logic out of Blockchain::init into a testable function.

patch_hardfork_add_fork_checked.py put the logic inline in Blockchain::init. That works, but
Blockchain::init cannot be unit tested without standing up a whole blockchain, which means the
guard that protects the consensus schedule would itself be untested. So it becomes a free function
in namespace cryptonote:

    bool install_and_verify_hardfork_schedule(HardFork &hf,
                                              const std::vector<::hardfork_t> &schedule,
                                              uint8_t min_version_at_height_zero,
                                              std::string &error);

which the unit tests call directly against a real HardFork over Monero's TestDB.

What it guarantees:
  1. The schedule is not empty.
  2. Every add_fork() return value is checked -- a rejected entry is an error, not a silent no-op.
     This is the check that catches reversed init()/add_fork() ordering, because init() pushes its
     placeholder when the table is empty and add_fork() then rejects the real entry for
     `version <= heights.back().version`.
  3. After init(), the installed table matches the configured schedule entry for entry.
  4. get_ideal_version(0) >= min_version_at_height_zero (0 disables the check, for FAKECHAIN).

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
H = os.path.join(ROOT, "src/cryptonote_basic/hardfork.h")
C = os.path.join(ROOT, "src/cryptonote_basic/hardfork.cpp")
B = os.path.join(ROOT, "src/cryptonote_core/blockchain.cpp")
MARK = "install_and_verify_hardfork_schedule"

# ---------------------------------------------------------------- hardfork.h
H_ANCHOR = "  class HardFork\n  {\n  public:"
H_DECL = """  class HardFork;

  /**
   * MeepCoin: install a hard fork schedule with every add_fork() return value checked, run
   * init(), then verify the resulting table against what was configured.
   *
   * Upstream called add_fork() and discarded the result. add_fork() returns false for any
   * out-of-order entry, and HardFork::init() pushes a placeholder when the table is still empty,
   * so a rejected entry left the daemon running a schedule nobody configured. MeepCoin's schedule
   * is a single entry {version 16, height 0}, which makes that failure mode a live risk rather
   * than a theoretical one.
   *
   * @param hf                          the HardFork to populate (must have no entries yet)
   * @param schedule                    entries to install, in ascending order
   * @param min_version_at_height_zero  minimum acceptable get_ideal_version(0); 0 disables
   * @param error                       set to a human-readable reason on failure
   * @return true only if the schedule installed cleanly and the table verifies
   */
  bool install_and_verify_hardfork_schedule(HardFork &hf,
                                            const std::vector<::hardfork_t> &schedule,
                                            uint8_t min_version_at_height_zero,
                                            std::string &error);

  class HardFork
  {
  public:"""

# ---------------------------------------------------------------- hardfork.cpp
C_ANCHOR = "using namespace cryptonote;\n"
C_IMPL = """using namespace cryptonote;

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
"""

# ---------------------------------------------------------------- blockchain.cpp
B_OLD_START = "  if (meep_schedule.empty())"
B_OLD_END = "  }\n\n  m_db->set_hard_fork(m_hardfork);"
B_NEW = """  {
    std::string hf_error;
    // MeepCoin runs the modern ruleset from genesis on every real network slot. FAKECHAIN is
    // exempt from the height-0 version floor because its schedule comes from test_options and
    // tests legitimately exercise old versions.
    const uint8_t min_v0 = (m_nettype == FAKECHAIN) ? 0 : (uint8_t)CURRENT_BLOCK_MAJOR_VERSION;
    if (!install_and_verify_hardfork_schedule(*m_hardfork, meep_schedule, min_v0, hf_error))
    {
      MERROR("FATAL: hard fork schedule could not be installed: " << hf_error
          << ". The daemon would run consensus rules that were never configured. Refusing to start.");
      return false;
    }
    MINFO("hard fork table verified: " << m_hardfork->get_hardforks().size()
        << " entry/entries, version " << (unsigned)m_hardfork->get_ideal_version(0)
        << " from height 0");
  }

  m_db->set_hard_fork(m_hardfork);"""


def patch(path, old, new, label):
    s = open(path).read()
    if MARK in s:
        print(f"= {label} already patched")
        return True
    if old not in s:
        print(f"! anchor not found in {label}")
        return False
    open(path, "w").write(s.replace(old, new, 1))
    print(f"+ {label}")
    return True


ok = True
ok &= patch(H, H_ANCHOR, H_DECL, "hardfork.h declaration")
ok &= patch(C, C_ANCHOR, C_IMPL, "hardfork.cpp implementation")

# blockchain.cpp: replace the inline block with a call to the helper
s = open(B).read()
if MARK in s:
    print("= blockchain.cpp already calls the helper")
elif B_OLD_START in s and B_OLD_END in s:
    i = s.index(B_OLD_START)
    j = s.index(B_OLD_END, i) + len(B_OLD_END)
    open(B, "w").write(s[:i] + B_NEW + s[j:])
    print("+ blockchain.cpp calls install_and_verify_hardfork_schedule()")
else:
    print("! anchor not found in blockchain.cpp")
    ok = False

if not ok:
    sys.exit(1)
print("HARDFORK_INSTALL_VERIFY_OK")
