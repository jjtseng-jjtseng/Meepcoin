#!/usr/bin/env python3
"""EXPERIMENTAL-ONLY: make the genesis timestamp settable at run time, so every experimental chain
can be started with a genuinely fresh genesis instead of a compile-time constant.

WHY THIS EXISTS. The minority-attacker experiment needs a genesis whose age at first mining is close
to zero, for every one of ~10 runs. Rebuilding the daemon per run costs minutes each and still drifts,
because `cryptonote_config.h` is included nearly everywhere and a full rebuild is required. Reading
the value from the environment at genesis-construction time makes the age controllable to the second
at zero build cost.

THIS IS NOT A PROPOSED CONSENSUS CHANGE AND MUST NEVER BE ADOPTED. A run-time-settable genesis
timestamp means two nodes with different environments build different chains. It is deliberately:
  * opt-in only -- absent the variable, behaviour is byte-identical to the compiled constant;
  * loud -- it logs the override at startup so no run can use it unnoticed;
  * confined to the experimental binary meepcoind.expgen, never to the T1+T2+T4 candidate binary.

Applies on top of T1+T2+T4. Usage: patch_experimental_genesis_ts.py [--revert]
"""
import hashlib, io, os, sys

SRC = os.path.expanduser("~/meepcoin-node/src/cryptonote_core/cryptonote_tx_utils.cpp")
MARK = "MEEPCOIN EXPERIMENTAL GENESIS TIMESTAMP OVERRIDE"

OLD = """    bl.timestamp = MEEPCOIN_GENESIS_TIMESTAMP;  // MeepCoin: real genesis time, not 0"""

NEW = """    // ---------------------------------------------------------------------------------------
    // MEEPCOIN EXPERIMENTAL GENESIS TIMESTAMP OVERRIDE -- TEST BINARY ONLY, NEVER FOR ADOPTION.
    //
    // Absent MEEPCOIN_EXPERIMENTAL_GENESIS_TS the behaviour is byte-identical to the compiled
    // constant. When present, the genesis timestamp is taken from the environment so that an
    // isolated experimental chain can be started with a genesis age near zero, which is what the
    // minority-attacker experiment requires and what a compile-time constant cannot provide across
    // many runs.
    //
    // A run-time-settable genesis timestamp is NOT a valid consensus design: two nodes with
    // different environments would build different chains. It exists here only so that test chains
    // can be made genuinely fresh, and it announces itself loudly at startup.
    // ---------------------------------------------------------------------------------------
    bl.timestamp = MEEPCOIN_GENESIS_TIMESTAMP;  // MeepCoin: real genesis time, not 0
    {
      const char *meep_exp_gts = getenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS");
      if (meep_exp_gts && *meep_exp_gts)
      {
        const uint64_t v = strtoull(meep_exp_gts, NULL, 10);
        if (v)
        {
          bl.timestamp = v;
          MGINFO_RED("EXPERIMENTAL BUILD: genesis timestamp overridden from the environment to "
                     << v << " (compiled default " << (uint64_t)MEEPCOIN_GENESIS_TIMESTAMP
                     << "). This build is for isolated testing only and its chain is not "
                        "compatible with any other.");
        }
      }
    }"""


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
            print("= override not applied"); return 0
        if NEW not in s:
            print("FAIL: present but not in expected form"); return 1
        io.open(SRC, "w", encoding="utf-8", newline="\n").write(s.replace(NEW, OLD, 1))
        print(f"reverted\n  sha256 {sha256(SRC)}"); return 0
    if MARK in s:
        print(f"= already applied\n  sha256 {sha256(SRC)}"); return 0
    if OLD not in s:
        print("FAIL: exact text not found -- refusing to guess"); return 1
    io.open(SRC, "w", encoding="utf-8", newline="\n").write(s.replace(OLD, NEW, 1))
    print(f"applied experimental genesis-timestamp override\n  sha256 {sha256(SRC)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
