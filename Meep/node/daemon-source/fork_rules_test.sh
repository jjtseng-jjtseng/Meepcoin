#!/bin/bash
# Source regression for patch 0007: the wallet's fork-rule activation predicate.
#
#   ./fork_rules_test.sh <reconstructed-checkout>
#
# <reconstructed-checkout> is the git checkout produced by reconstruct.sh, with the full series
# applied. The commit patch 0007 was applied to is found BY TREE, not by HEAD~n, so adding a later
# patch cannot silently make this regression compare the wrong two revisions.
#
# WHAT THIS PROVES. That the inherited expression really was there, that it is gone, that exactly
# one central predicate replaced it, and that no caller's transition offset and no fee constant was
# edited to get the answer. Nothing is built or run here; the compiled behaviour is
# meepcoin-fork-activation-test's job.
#
# It is not a framework: one file, a handful of greps over `git show` output.

set -u

# Resolved BEFORE the cd below: `bash fork_rules_test.sh <checkout>` run from this directory gives
# dirname ".", and reading it after the cd would look for the patches inside the checkout.
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

CHECKOUT=${1:-}
[ -n "$CHECKOUT" ] || { echo "usage: $0 <reconstructed-checkout>" >&2; exit 2; }
cd "$CHECKOUT" 2>/dev/null || { echo "not a directory: $CHECKOUT" >&2; exit 2; }
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "not a git checkout: $CHECKOUT" >&2; exit 2; }

PRE_0007_TREE=4eb00bbd0e14a13976657207a451529d6a48df18   # what patch 0007 was applied to (patch 0006)
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1: expected $2, got $3"; fi
}

# commit_for_tree <tree> -- the revision in this history whose tree is <tree>
commit_for_tree() {
  local c
  for c in $(git rev-list HEAD); do
    if [ "$(git rev-parse "$c^{tree}")" = "$1" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

PRE=$(commit_for_tree "$PRE_0007_TREE") || { echo "the pre-0007 tree is not in this history" >&2; exit 2; }
old() { git show "$PRE:$1" 2>/dev/null; }      # before patch 0007
new() { git show "HEAD:$1" 2>/dev/null; }      # after it

echo "-- the two revisions this regression compares --"
check "the pre-0007 tree is in this history" "$PRE_0007_TREE" "$(git rev-parse "$PRE^{tree}")"
check "HEAD is not that tree"                "different"      "$([ "$(git rev-parse 'HEAD^{tree}')" = "$PRE_0007_TREE" ] && echo same || echo different)"

echo "-- patches 0001-0006 are byte-identical --"
expect_patch() { # expect_patch <number-prefix> <sha256>
  local f
  f=$(ls "$SELF_DIR"/patches/"$1"* 2>/dev/null | head -1)
  check "patch $1 unchanged" "$2" "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
}
expect_patch 0001 23576588a8dd513f92c4126baab97974cd966b59f5dbf58689f1fb7d1934a660
expect_patch 0002 c2a5002921b2a811cfcaf759955ee7d50c4869529d824ce68f1617b14105240d
expect_patch 0003 daac1c701180eade6e1eeb5c099c8c4f715014474d6d933283dc6dfbfa9eae2a
expect_patch 0004 1ba887e6459be6e60043d63cc98c332005b103e2c903c14a937496982886f172
expect_patch 0005 62894189e52f734d1ed65382ef2b4aff2f0da4eb3ac790d3b85680742cae822f
expect_patch 0006 e69979a833a63ec5d46957ea8df13ca467a616332d55dbfb6b9230c56b9f1efb

echo "-- the defect was really there --"
check "pre-0007 use_fork_rules used the inherited subtraction" 1 \
  "$(old src/wallet/wallet2.cpp | grep -c '(int64_t)height >= (int64_t)earliest_height - early_blocks')"
check "pre-0007 had no central predicate header" 0 \
  "$(git ls-tree -r --name-only "$PRE" | grep -c '^src/wallet/fork_rules.h$')"

echo "-- and it is gone, replaced by exactly one central predicate --"
# The expression must be gone as CODE. It is deliberately still quoted as prose in three places --
# the predicate header, the call site's comment and the regression's witness function -- and this
# check names them, so a fourth occurrence, or a live one, fails.
check "no live use of the inherited subtraction" 0 \
  "$(new src/wallet/wallet2.cpp | grep -cF 'close_enough = (int64_t)height')"
check "it survives only as quoted prose, in exactly the three documented places" \
  "src/meepcoin_genesis/meepcoin_fork_activation_test.cpp src/wallet/fork_rules.h src/wallet/wallet2.cpp" \
  "$(git grep -lF '(int64_t)earliest_height - early_blocks' HEAD -- src | sed 's/^HEAD://' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
check "the predicate header exists" 1 \
  "$(git ls-tree -r --name-only HEAD | grep -c '^src/wallet/fork_rules.h$')"
check "it defines exactly one predicate" 1 \
  "$(new src/wallet/fork_rules.h | grep -c '^  inline bool fork_rules_active')"
check "use_fork_rules calls it, once" 1 \
  "$(new src/wallet/wallet2.cpp | grep -c 'close_enough = fork_rules_active(height, earliest_height, early_blocks);')"
check "nothing else in the tree calls it" 1 \
  "$(git grep -c 'fork_rules_active(height, earliest_height, early_blocks)' HEAD -- src | wc -l)"
check "the absent-fork case is still refused" 1 \
  "$(new src/wallet/fork_rules.h | grep -c 'if (earliest_height == std::numeric_limits<uint64_t>::max())')"
check "the genesis case is the repair" 1 \
  "$(new src/wallet/fork_rules.h | grep -c 'if (earliest_height == 0)')"

echo "-- no caller, no offset and no fee constant was edited to get the answer --"
for pair in "HF_VERSION_DYNAMIC_FEE, -30 * 1" "HF_VERSION_2021_SCALING, -30 * 1" \
            "HF_VERSION_PER_BYTE_FEE, 0" "3, -30 * 14" "HF_VERSION_BULLETPROOF_PLUS, -10" \
            "HF_VERSION_CLSAG, -10" "HF_VERSION_SMALLER_BP, -10"; do
  a=$(old src/wallet/wallet2.cpp | grep -cF "use_fork_rules($pair)")
  b=$(new src/wallet/wallet2.cpp | grep -cF "use_fork_rules($pair)")
  # Both the count AND its being non-zero matter: two zeroes would be a pattern that matches
  # nothing agreeing with itself, which is how a check like this silently stops checking.
  if [ "$a" -gt 0 ]; then check "caller use_fork_rules($pair) unchanged" "$a" "$b"
  else bad "caller use_fork_rules($pair): the pattern matched nothing before the patch either"; fi
done
check "the hard-fork schedule is untouched" \
  "$(old src/hardforks/hardforks.cpp | sha256sum | cut -d' ' -f1)" \
  "$(new src/hardforks/hardforks.cpp | sha256sum | cut -d' ' -f1)"
check "cryptonote_config.h is untouched" \
  "$(old src/cryptonote_config.h | sha256sum | cut -d' ' -f1)" \
  "$(new src/cryptonote_config.h | sha256sum | cut -d' ' -f1)"
check "the daemon's fee code is untouched" \
  "$(old src/cryptonote_core/blockchain.cpp | sha256sum | cut -d' ' -f1)" \
  "$(new src/cryptonote_core/blockchain.cpp | sha256sum | cut -d' ' -f1)"
check "MeepHash is untouched" \
  "$(old src/crypto/meep-hash.cpp | sha256sum | cut -d' ' -f1)" \
  "$(new src/crypto/meep-hash.cpp | sha256sum | cut -d' ' -f1)"

echo "-- patch 0005/0006 privacy repairs are still in place --"
check "no print_source_entry definition" 0 "$(new src/wallet/wallet2.h | grep -c 'print_source_entry')"
check "no transaction_created dump"      0 "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'transaction_created:')"

echo "-- the compiled regression is wired in --"
check "the test source is in the tree" 1 \
  "$(git ls-tree -r --name-only HEAD | grep -c '^src/meepcoin_genesis/meepcoin_fork_activation_test.cpp$')"
check "and has a build target" 1 \
  "$(new src/meepcoin_genesis/CMakeLists.txt | grep -c '^add_executable(meepcoin-fork-activation-test ')"
check "the test uses the production predicate header" 1 \
  "$(new src/meepcoin_genesis/meepcoin_fork_activation_test.cpp | grep -c '#include "wallet/fork_rules.h"')"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
