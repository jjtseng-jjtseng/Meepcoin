#!/usr/bin/env python3
"""EXPERIMENTAL consensus patch: timestamp-rule candidates T1 + T2.

Applies to ~/meepcoin-node/src/cryptonote_core/blockchain.cpp ONLY. Nothing else is touched. This
is an EXPERIMENT on the branch `timestamp-rule-investigation`, run against fresh throwaway chain
directories. It is NOT adopted, NOT proposed for the frozen tags, and NOT deployed anywhere.

Specification: docs/TIMESTAMP_RULE_CANDIDATES.md

  T1  main chain: replace `if (h < 60) return true;` -- which computes no median at all and so
      permits a timestamp of zero -- with a median over the available prior history.

  T2  alternative chain: build the window with the SAME function the main chain uses, so equivalent
      history yields equivalent validity. Upstream's complete_timestamps_vector walks down to
      stop_offset+1, excluding genesis on a short chain, and applies the check with no
      below-60 guard; both paths now share one window and one guard.

Both reduce to one canonical window:

      window(parent_height) = timestamps of heights [max(0, p - 59) .. p]

which is bit-identical to upstream's main-chain window for p >= 59, so behaviour at candidate
heights 60 and above is unchanged.

Run with --revert to restore the file from git.
"""
import hashlib, io, os, sys

SRC = os.path.expanduser("~/meepcoin-node/src/cryptonote_core/blockchain.cpp")
MARK = "MEEPCOIN T1+T2"

HELPER = r'''
// ---------------------------------------------------------------------------------------------
// MEEPCOIN T1+T2 (EXPERIMENTAL -- branch timestamp-rule-investigation, not adopted)
//
// One canonical timestamp window, shared by the main-chain and alternative-chain paths:
//
//     window(p) = block timestamps of heights [ max(0, p - (W-1)) .. p ],  W = 60
//
// For p >= W-1 this is exactly upstream's main-chain window [h-60 .. h-1] with h = p+1, so nothing
// changes at candidate height 60 or above. For p < W-1 it is the whole available history INCLUDING
// genesis, which is where the two upstream paths previously disagreed with each other and where the
// main path performed no check at all.
//
// Heights are pushed in descending order, matching upstream complete_timestamps_vector. Order is
// irrelevant: epee::misc_utils::median sorts its input.
// ---------------------------------------------------------------------------------------------
static void meepcoin_timestamp_window(const BlockchainDB *db, uint64_t parent_height,
                                      size_t want, std::vector<uint64_t> &out)
{
  if (want == 0)
    return;
  const uint64_t stop = (parent_height + 1 > (uint64_t)want) ? parent_height + 1 - (uint64_t)want : 0;
  out.reserve(out.size() + (size_t)(parent_height + 1 - stop));
  for (uint64_t hh = parent_height + 1; hh-- > stop; )
    out.push_back(db->get_block_timestamp(hh));
}
'''

OLD_MAIN = """  const auto h = m_db->height();

  // if not enough blocks, no proper median yet, return true
  if(h < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = h - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  timestamps.reserve(h - offset);
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);"""

NEW_MAIN = """  const auto h = m_db->height();

  // MEEPCOIN T1 (EXPERIMENTAL): upstream returned true here whenever the chain held fewer than
  // BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW blocks, computing no median at all. A launching chain
  // therefore accepted ANY timestamp in [0, now+FTL], including zero, which gives next_difficulty
  // a time span of ~1.79e9 seconds and pins difficulty at 1. Confirmed live: see
  // docs/LIVE_LAUNCH_TIMESTAMP.md. The median is now taken over the available history instead.
  //
  // Genesis is INCLUDED, deliberately: excluding it would leave height 1 with an empty window and
  // therefore no bound at all, which is the hole being closed.
  if(h == 0)
  {
    // the genesis block itself; there is no prior history to take a median of
    return true;
  }

  std::vector<uint64_t> timestamps;
  meepcoin_timestamp_window(m_db, h - 1, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, timestamps);

  return check_block_timestamp(timestamps, b, median_ts);"""

OLD_ALT = """  size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  timestamps.reserve(timestamps.size() + start_top_height - stop_offset);
  while (start_top_height != stop_offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;"""

NEW_ALT = """  size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  // MEEPCOIN T2 (EXPERIMENTAL): upstream walked start_top_height down to stop_offset+1, which
  // EXCLUDES genesis whenever the chain is shorter than the window, while the main-chain path
  // includes it. Combined with the absence of any below-60 guard on this path, the same block bytes
  // on the same history could be accepted as a main-chain extension and rejected as an alternative
  // block. Confirmed live: see docs/LIVE_MEDIAN_BOUNDARY.md cases B and K. Both paths now build the
  // window with the same function.
  meepcoin_timestamp_window(m_db, start_top_height, need_elements, timestamps);
  return true;"""


ANCHOR = ("// for an alternate chain, get the timestamps from the main chain to complete\n"
          "// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.\n"
          "bool Blockchain::complete_timestamps_vector(")

# The MeepCoin baseline of this one file, stored in the repository so that reverting restores the
# MeepCoin baseline rather than upstream Monero. `git checkout` would be wrong here: MeepCoin's own
# changes to blockchain.cpp (hard-fork table installation, get_altblock_longhash signature,
# empty-chain weight guard) are uncommitted working-tree edits, so a checkout would discard them too.
BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "baseline", "blockchain.cpp.meepcoin-baseline")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def apply_patch(s):
    """baseline text -> patched text. Returns (text, notes). Idempotent."""
    if MARK in s:
        return s, ["already patched -- no change"]
    notes = []
    if ANCHOR not in s:
        raise RuntimeError("insertion anchor not found")
    s = s.replace(ANCHOR, HELPER + ANCHOR, 1)
    notes.append("inserted shared helper meepcoin_timestamp_window()")
    for name, old, new in (("T1 main-chain guard", OLD_MAIN, NEW_MAIN),
                           ("T2 shared alt window", OLD_ALT, NEW_ALT)):
        if old not in s:
            raise RuntimeError(f"exact text for {name} not found -- refusing to guess")
        s = s.replace(old, new, 1)
        notes.append(f"applied {name}")
    return s, notes


def unapply_patch(s):
    """patched text -> baseline text. Exact inverse of apply_patch."""
    if MARK not in s:
        return s, ["not patched -- no change"]
    notes = []
    for name, old, new in (("T2 shared alt window", OLD_ALT, NEW_ALT),
                           ("T1 main-chain guard", OLD_MAIN, NEW_MAIN)):
        if new not in s:
            raise RuntimeError(f"patched text for {name} not found -- cannot invert")
        s = s.replace(new, old, 1)
        notes.append(f"reverted {name}")
    if HELPER + ANCHOR not in s:
        raise RuntimeError("helper block not found in the expected position -- cannot invert")
    s = s.replace(HELPER + ANCHOR, ANCHOR, 1)
    notes.append("removed shared helper")
    return s, notes


def main():
    if not os.path.exists(SRC):
        print(f"not found: {SRC}"); return 1

    if "--make-baseline" in sys.argv:
        # Derive the baseline from the current (patched) file by exact inversion, then prove the
        # round trip: baseline -> apply -> byte-identical to what is on disk right now.
        cur = io.open(SRC, encoding="utf-8").read()
        base, notes = unapply_patch(cur)
        for n in notes:
            print("  " + n)
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        io.open(BASELINE, "w", encoding="utf-8", newline="\n").write(base)
        again, _ = apply_patch(base)
        print(f"baseline written to {BASELINE}")
        print(f"round trip baseline -> apply == current file on disk: "
              f"{'YES' if again == cur else 'NO'}")
        return 0 if again == cur else 1

    if "--revert" in sys.argv:
        if not os.path.exists(BASELINE):
            print(f"FAIL: no stored baseline at {BASELINE}"); return 1
        io.open(SRC, "w", encoding="utf-8", newline="\n").write(
            io.open(BASELINE, encoding="utf-8").read())
        print(f"restored the MeepCoin baseline from {BASELINE}")
        print(f"  sha256 {sha256(SRC)}")
        return 0

    if "--verify" in sys.argv:
        # Prove the three properties the review asked for, without touching SRC.
        if not os.path.exists(BASELINE):
            print(f"FAIL: no stored baseline at {BASELINE}"); return 1
        base = io.open(BASELINE, encoding="utf-8").read()
        cur = io.open(SRC, encoding="utf-8").read()
        p1, _ = apply_patch(base)
        p2, _ = apply_patch(p1)
        back, _ = unapply_patch(p1)
        print(f"  baseline sha256          {sha256(BASELINE)}")
        print(f"  current  sha256          {sha256(SRC)}")
        print(f"  1. apply(baseline) == current file on disk : "
              f"{'PASS' if p1 == cur else 'FAIL'}")
        print(f"  2. idempotent, apply(apply(x)) == apply(x)  : "
              f"{'PASS' if p2 == p1 else 'FAIL'}")
        print(f"  3. revert(apply(baseline)) == baseline      : "
              f"{'PASS' if back == base else 'FAIL'}")
        return 0 if (p1 == cur and p2 == p1 and back == base) else 1

    s = io.open(SRC, encoding="utf-8").read()
    before = sha256(SRC)
    out, notes = apply_patch(s)
    for n in notes:
        print("  " + n)
    if out == s:
        print(f"= no change; {SRC} sha256 {before}")
        return 0
    io.open(SRC, "w", encoding="utf-8", newline="\n").write(out)
    print(f"patched {SRC}")
    print(f"  sha256 before {before}")
    print(f"  sha256 after  {sha256(SRC)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
