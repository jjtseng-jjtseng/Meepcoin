#!/usr/bin/env python3
"""EXPERIMENTAL difficulty-bootstrap candidates A and B, for live confirmation only.

Applies to ~/meepcoin-node/src/cryptonote_core/blockchain.cpp, on top of T1+T2. These are
EXPERIMENTS on child branches of `timestamp-rule-investigation`. Neither is adopted, neither is
proposed for a frozen tag, and neither is deployed.

  Candidate A  for heights 1..30 inclusive, the difficulty returned may not exceed twice the
               difficulty of the previous block. Applied to the integer next_difficulty() already
               produced; it never raises a value, only caps it.

  Candidate B  for heights 1..30 inclusive, the AGGREGATE time span used by the difficulty formula
               is floored at 5 seconds per included interval. Implemented equivalently as a cap on
               the returned difficulty:
                     d_B = ceil(total_work * target / (5 * (cut_end - cut_begin - 1)))
                     d   = min(d_raw, d_B)
               which is exactly what a span floor does, since difficulty is monotonically
               decreasing in the span. The cut indices are recomputed with the same arithmetic
               next_difficulty() uses, over the same first-720 prefix, so no consensus logic is
               reinterpreted.

Usage:  patch_diff_candidates.py --a | --b | --revert
Only one candidate may be applied at a time; applying either requires the other to be absent.
"""
import hashlib, io, os, sys

SRC = os.path.expanduser("~/meepcoin-node/src/cryptonote_core/blockchain.cpp")
MARK_A = "MEEPCOIN CANDIDATE A"
MARK_B = "MEEPCOIN CANDIDATE B"
BOOT_N = 30

ANCHOR = """  size_t target = get_difficulty_target();
  difficulty_type diff = next_difficulty(timestamps, difficulties, target);
"""

A_BLOCK = """  size_t target = get_difficulty_target();
  difficulty_type diff = next_difficulty(timestamps, difficulties, target);

  // ---------------------------------------------------------------------------------------------
  // MEEPCOIN CANDIDATE A (EXPERIMENTAL, not adopted): for heights 1..%(boot)d inclusive the returned
  // difficulty may not exceed twice the previous block's difficulty. Applied to the integer
  // next_difficulty() already produced, so it can only lower a value, never raise one.
  //
  // Known trade-off, measured rather than assumed: this cap also slows RECOVERY after an attacker
  // has driven difficulty down, which is why it performs worse than the unmodified rule under a
  // 33%%+ adaptive timestamp attacker. See docs/DIFFICULTY_UNDER_T1T2.md.
  // ---------------------------------------------------------------------------------------------
  if (height >= 1 && height <= %(boot)d)
  {
    const difficulty_type prev = m_db->get_block_difficulty(height - 1);
    const difficulty_type cap = prev * 2;
    if (cap != 0 && diff > cap)
      diff = cap;
    if (diff == 0)
      diff = 1;
  }
""" % {"boot": BOOT_N}

B_BLOCK = """  size_t target = get_difficulty_target();
  difficulty_type diff = next_difficulty(timestamps, difficulties, target);

  // ---------------------------------------------------------------------------------------------
  // MEEPCOIN CANDIDATE B (EXPERIMENTAL, not adopted): for heights 1..%(boot)d inclusive the aggregate
  // time span is floored at 5 seconds per included interval. Difficulty is monotonically decreasing
  // in the span, so a span floor is exactly a difficulty cap:
  //     d_B = ceil(total_work * target / (5 * (cut_end - cut_begin - 1)))
  // The cut indices below repeat next_difficulty()'s own arithmetic over the same first-720 prefix,
  // so the window is not reinterpreted. Only the aggregate span is floored; individual timestamps
  // are untouched.
  // ---------------------------------------------------------------------------------------------
  if (height >= 1 && height <= %(boot)d && timestamps.size() >= 2)
  {
    size_t length = std::min(timestamps.size(), (size_t)DIFFICULTY_WINDOW);
    size_t cut_begin, cut_end;
    if (length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT)
    {
      cut_begin = 0;
      cut_end = length;
    }
    else
    {
      cut_begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) / 2;
      cut_end = cut_begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT);
    }
    if (cut_end > cut_begin + 1)
    {
      const uint64_t intervals = (uint64_t)(cut_end - cut_begin - 1);
      const uint64_t floor_span = 5 * intervals;
      const difficulty_type total_work = difficulties[cut_end - 1] - difficulties[cut_begin];
      if (floor_span > 0 && total_work > 0)
      {
        boost::multiprecision::uint256_t capped =
            (boost::multiprecision::uint256_t(total_work) * target + floor_span - 1) / floor_span;
        difficulty_type dB = capped.convert_to<difficulty_type>();
        if (dB == 0)
          dB = 1;
        if (diff > dB)
          diff = dB;
      }
    }
    if (diff == 0)
      diff = 1;
  }
""" % {"boot": BOOT_N}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def strip(s):
    """Remove whichever candidate is present, returning the T1+T2-only text."""
    for mark, block in ((MARK_A, A_BLOCK), (MARK_B, B_BLOCK)):
        if mark in s:
            if block not in s:
                raise RuntimeError(f"{mark} present but not in its expected form -- cannot invert")
            s = s.replace(block, ANCHOR, 1)
    return s


def main():
    if not os.path.exists(SRC):
        print(f"not found: {SRC}"); return 1
    s = io.open(SRC, encoding="utf-8").read()
    if "MEEPCOIN T1+T2" not in s:
        print("FAIL: T1+T2 is not applied. The candidates are only evaluated on top of it.")
        return 1

    want = None
    if "--a" in sys.argv: want = "A"
    if "--b" in sys.argv: want = "B"
    if "--revert" in sys.argv: want = None
    elif want is None:
        print(__doc__); return 1

    base = strip(s)
    if want is None:
        io.open(SRC, "w", encoding="utf-8", newline="\n").write(base)
        print(f"removed any difficulty candidate; back to T1+T2 only\n  sha256 {sha256(SRC)}")
        return 0

    block = A_BLOCK if want == "A" else B_BLOCK
    if ANCHOR not in base:
        print("FAIL: anchor not found in get_difficulty_for_next_block"); return 1
    out = base.replace(ANCHOR, block, 1)
    io.open(SRC, "w", encoding="utf-8", newline="\n").write(out)
    print(f"applied candidate {want} on top of T1+T2")
    print(f"  sha256 {sha256(SRC)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
