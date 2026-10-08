#!/usr/bin/env python3
"""Set the block target to 60 seconds -- the value the chain actually uses.

RECORDS AN EDIT THAT WAS NEVER RECORDED. patch_identity.py sets DIFFICULTY_TARGET_V2 to 30, but the
validated devnet runs at 60, and the economics depend on it: get_block_reward derives

    emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (DIFFICULTY_TARGET_V2/60 - 1)

so 60 s is what makes the effective shift 21 and the initial reward 1,192,092,895,507 atomic.

30 s is not merely wrong, it does not compile:

    static_assert(DIFFICULTY_TARGET_V2%60==0 && DIFFICULTY_TARGET_V1%60==0,
                  "difficulty targets must be a multiple of 60");

and 30/60 truncates to 0, which would make the shift 22 rather than 21 even if it did.

How this was found: restoring src/cryptonote_config.h from the node tree's git HEAD (which is
upstream Monero, not a MeepCoin baseline) discarded the working-tree state, and re-running every
recorded patch script left the target at 30. So the 60 s value had only ever existed as an
untracked edit to the working tree -- the same class of gap as the mainnet/stagenet genesis blobs.
Both are now recorded.

Lesson worth keeping: `git checkout <file>` in the node tree reverts to UPSTREAM, because the node
tree is a Monero checkout with uncommitted MeepCoin patches. The patch scripts are the only record
of MeepCoin's source state, so anything not expressed as a patch script does not exist.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
CFG = os.path.join(ROOT, "src/cryptonote_config.h")

OLD = "#define DIFFICULTY_TARGET_V2                            30  // seconds (MeepCoin devnet)"
NEW = ("#define DIFFICULTY_TARGET_V2                            60  // seconds (MeepCoin devnet)\n"
       "// MUST be a multiple of 60: get_block_reward() static_asserts it, and derives\n"
       "// emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target/60 - 1) from it.\n"
       "// 60 s is therefore the fastest legal target, and it is what makes the effective shift 21\n"
       "// and the initial reward 1,192,092,895,507 atomic. Changing this changes emission: the\n"
       "// block target is NOT economically neutral.")

s = open(CFG).read()

if NEW.split("\n")[0] in s:
    print("= block target already 60 s")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found: DIFFICULTY_TARGET_V2 at 30 s")
    print("  current value:")
    for line in s.split("\n"):
        if line.startswith("#define DIFFICULTY_TARGET_V2"):
            print("   ", line)
    sys.exit(1)

open(CFG, "w").write(s.replace(OLD, NEW, 1))
print("+ DIFFICULTY_TARGET_V2 30 -> 60 seconds")
print("BLOCK_TARGET_60_OK")
