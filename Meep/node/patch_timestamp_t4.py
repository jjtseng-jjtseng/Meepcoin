#!/usr/bin/env python3
"""EXPERIMENTAL consensus patch: timestamp candidate T4 — future-time limit on BOTH paths.

Applies to ~/meepcoin-node/src/cryptonote_core/blockchain.cpp, on top of T1+T2. EXPERIMENT on branch
`timestamp-rule-investigation`. Not adopted, not proposed for a frozen tag, not deployed.

THE DEFECT. `handle_alternative_block` validates timestamps by calling the vector overload

    bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b,
                                           uint64_t& median_ts) const

which compares only against the median. The future-time limit lives exclusively in the OTHER
overload, the one the main chain uses. A block whose timestamp is arbitrarily far in the future is
therefore accepted as an alternative block and rejected as a main-chain extension — the same bytes,
the same history, two verdicts. Reproduced at all 11 tested heights; see
docs/SPLIT_REGRESSION_*.md.

THE FIX. Move the future-time check into the shared vector overload, so both paths enforce both
bounds through one function. The main-chain overload keeps its own earlier check, which is now
redundant but harmless and identical in effect; leaving it in place keeps the diff to one hunk and
preserves the existing main-chain error message and ordering exactly.

TIME DEPENDENCE, STATED UP FRONT. The future-time limit is relative to each node's local wall clock,
so it is inherently time-dependent on either path. The dependence is one-directional: a block that is
too far in the future becomes valid as time passes, never the reverse. It cannot make an already
accepted block invalid. Whether that produces a persistent disagreement is measured, not assumed --
see node/t4_reorg_test.py.

Usage:  patch_timestamp_t4.py [--revert]
"""
import hashlib, io, os, sys

SRC = os.path.expanduser("~/meepcoin-node/src/cryptonote_core/blockchain.cpp")
MARK = "MEEPCOIN T4"

OLD = """bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)"""

NEW = """bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // MEEPCOIN T4 (EXPERIMENTAL): enforce the future-time limit HERE, in the shared overload, so that
  // the alternative-chain path enforces it too. Upstream checked it only in the block-taking
  // overload used by the main chain, so handle_alternative_block accepted arbitrarily far-future
  // timestamps. Same bytes, same history, two verdicts -- reproduced at every tested height.
  //
  // The main-chain overload still performs its own earlier check. That is now redundant and
  // deliberately left alone: it keeps this diff to one hunk and preserves the main-chain error
  // message and check ordering byte for byte.
  //
  // This bound is local-clock relative and therefore time-dependent on both paths, in one direction
  // only: a block too far in the future becomes valid later, never the reverse.
  if(b.timestamp > (uint64_t)time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than local time + 2 hours");
    return false;
  }

  median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)"""


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    if not os.path.exists(SRC):
        print(f"not found: {SRC}"); return 1
    s = io.open(SRC, encoding="utf-8").read()

    if "--revert" in sys.argv:
        if MARK not in s:
            print("= T4 not applied"); return 0
        if NEW not in s:
            print("FAIL: T4 present but not in its expected form -- cannot invert"); return 1
        io.open(SRC, "w", encoding="utf-8", newline="\n").write(s.replace(NEW, OLD, 1))
        print(f"reverted T4\n  sha256 {sha256(SRC)}")
        return 0

    if "MEEPCOIN T1+T2" not in s:
        print("FAIL: T4 is defined on top of T1+T2, which is not applied."); return 1
    if MARK in s:
        print(f"= T4 already applied\n  sha256 {sha256(SRC)}"); return 0
    if OLD not in s:
        print("FAIL: exact text not found -- refusing to guess"); return 1

    io.open(SRC, "w", encoding="utf-8", newline="\n").write(s.replace(OLD, NEW, 1))
    print(f"applied T4: future-time limit enforced in the shared overload")
    print(f"  sha256 {sha256(SRC)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
