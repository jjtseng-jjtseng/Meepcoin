#!/bin/sh
# MeepCoin: source and configuration guards for the removed Monero trust anchors.
#
# Some of these corrections cannot be proved by a running binary. The historical block-id remap, for
# example, only fired for a block whose blob hashed to one exact Monero value; constructing that
# preimage is not practical, so the guard is that the constants are GONE from the consensus path. A
# constant that is absent cannot be substituted.
#
# The rest are configuration facts (a CMake option that must refuse to turn on) or scope facts (the
# hash implementation must be byte-identical, the genesis-guarded database fixup must be untouched).
#
# Run from the repository root:  sh src/meepcoin_genesis/meepcoin_trust_anchor_guards.sh
# Companion to the runtime tests in meepcoin_trust_anchor_test.cpp. Neither starts a daemon.
#
# LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

set -u

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
chk()  { if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi }

# The test source names the removed constants on purpose, to assert they never come back.
CONSENSUS_SRC="src/cryptonote_core/cryptonote_tx_utils.cpp
src/cryptonote_basic/cryptonote_format_utils.cpp
src/checkpoints/checkpoints.cpp
src/cryptonote_core/blockchain.cpp"

# A match on a line of CODE, ignoring // comments. The removals are all documented in comments that
# necessarily name the thing removed, so a plain grep would report the explanation as the offence.
code_grep() { # file pattern -> 0 if a non-comment line matches
  grep -n "$2" "$1" 2>/dev/null | sed 's/^[0-9]*://' | grep -v '^[[:space:]]*//' | grep -q .
}

printf '=================================================================\n'
printf 'MeepCoin trust-anchor source and configuration guards\n'
printf '=================================================================\n'

# ---------------------------------------------------------------- removed constants stay removed
printf '\n-- inherited Monero constants are absent from the consensus path --\n'
# A code line is one that is not a comment. The constants are discussed in comments explaining why
# they were removed; what must not exist is a line of code that uses one.
uses_constant() {
  for f in $CONSENSUS_SRC; do
    code_grep "$f" "$1" && return 0
  done
  return 1
}
for c in \
  84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000 \
  bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698 \
  3a8a2b3a29b50fc86ff73dd087ea43c6f0d6b8f936c849194d5c84c737903966 \
  ; do
  if uses_constant "$c"; then bad "constant $(echo "$c" | cut -c1-16)... is used in the consensus path"
  else ok "constant $(echo "$c" | cut -c1-16)... is not used in the consensus path"; fi
done

# ---------------------------------------------------------------- checkpoints
printf '\n-- built-in and DNS checkpoints --\n'
grep -q "ADD_CHECKPOINT2" src/checkpoints/checkpoints.cpp
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "no ADD_CHECKPOINT2 entries remain in checkpoints.cpp"

for d in checkpoints.moneropulse testpoints.moneropulse stagenetpoints.moneropulse; do
  if code_grep src/checkpoints/checkpoints.cpp "$d"; then bad "$d is used in the checkpoint implementation"
  else ok "$d is not used in the checkpoint implementation"; fi
done

if code_grep src/cryptonote_core/blockchain.cpp "load_checkpoints_from_dns"; then
  bad "blockchain.cpp still calls load_checkpoints_from_dns"
else
  ok "blockchain.cpp no longer calls load_checkpoints_from_dns"
fi

if code_grep src/cryptonote_core/cryptonote_core.cpp "set_enforce_dns_checkpoints(command_line"; then
  bad "--enforce-dns-checkpointing is still wired straight through"
else
  ok "--enforce-dns-checkpointing is no longer wired straight through"
fi

# ---------------------------------------------------------------- the per-block checkpoint blob
printf '\n-- the Monero per-block checkpoint blob --\n'
[ -e src/blocks/checkpoints.dat ]
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "src/blocks/checkpoints.dat is absent from the source tree"

grep -q "FATAL_ERROR" CMakeLists.txt && grep -q "PER_BLOCK_CHECKPOINT is not supported by MeepCoin" CMakeLists.txt
chk "$?" "CMakeLists.txt refuses PER_BLOCK_CHECKPOINT with a clear message"

# ---------------------------------------------------------------- the genesis-guarded fixup
printf '\n-- the genesis-guarded database fixup is untouched --\n'
grep -q '418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3' src/blockchain_db/blockchain_db.cpp
chk "$?" "fixup() still pins Monero's mainnet genesis constant"

grep -q 'if (get_block_hash_from_height(0) == mainnet_genesis_hash)' src/blockchain_db/blockchain_db.cpp
chk "$?" "fixup()'s body is still gated by exact equality with that genesis"

if git rev-parse --git-dir >/dev/null 2>&1; then
  git diff --quiet HEAD -- src/blockchain_db/blockchain_db.cpp
  chk "$?" "blockchain_db.cpp is unmodified by this change"
fi

# ---------------------------------------------------------------- scope
printf '\n-- scope: the hash and the chain parameters are untouched --\n'
printf 'add2ef940214e3eb7fd7a72495d5c99cf86fe3b57346419c4f60ab5b7450a925  src/crypto/meep-hash.cpp\n2a4239a3fac4cd5879cb4c5144eb3363ad26d7f006985ff29dbcbf017822599a  src/crypto/meep-hash.h\n' \
  | sha256sum -c --status
chk "$?" "MeepHash-W v2 sources are byte-identical to the locked baseline"

if git rev-parse --git-dir >/dev/null 2>&1; then
  for f in src/cryptonote_config.h src/hardforks/hardforks.cpp src/cryptonote_basic/hardfork.cpp \
           src/cryptonote_basic/hardfork.h src/cryptonote_core/cryptonote_tx_utils.h \
           src/wallet/wallet2.cpp src/simplewallet/simplewallet.cpp; do
    git diff --quiet HEAD -- "$f"
    chk "$?" "$f is unmodified (genesis/emission/difficulty/hardfork/wallet/ports unchanged)"
  done
fi

# ---------------------------------------------------------------- the CMake refusal, for real
printf '\n-- configuring with PER_BLOCK_CHECKPOINT=1 fails clearly --\n'
if command -v cmake >/dev/null 2>&1 && [ "${MEEPCOIN_GUARD_SKIP_CMAKE:-0}" != "1" ]; then
  TMPB=$(mktemp -d)
  OUT="$TMPB/out.log"
  cmake -S . -B "$TMPB/b" -DPER_BLOCK_CHECKPOINT=1 >"$OUT" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "cmake -DPER_BLOCK_CHECKPOINT=1 was ACCEPTED; it must be refused"
  else
    ok "cmake -DPER_BLOCK_CHECKPOINT=1 fails (exit $rc)"
    grep -q "PER_BLOCK_CHECKPOINT is not supported by MeepCoin" "$OUT"
    chk "$?" "and says why, naming the removed Monero blob"
  fi
  rm -rf "$TMPB"
else
  bad "cmake is unavailable, so the configuration refusal was NOT checked"
fi

printf '\n=================================================================\n'
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
printf 'TRUST ANCHOR GUARDS: %s\n' "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" -eq 0 ]
