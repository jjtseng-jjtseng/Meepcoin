#!/bin/bash
# Negative tests for the MeepCoin source lock. Each one mutates a DISPOSABLE COPY of the lock
# directory and asserts the verifier refuses it. Nothing here touches the live repositories.
#
# These are quick fail-closed checks, not a test framework. A verifier that only ever sees valid
# input has not been tested.

# Paths are derived, not hard-coded, so this runs from a checkout anywhere.
#   SRC  = this script's own directory (node/daemon-source)
#   REPO = the repository root two levels up, which the MeepHash manifest's paths are relative to
#   BASE = a disposable scratch directory; override with MEEPCOIN_MUT_DIR
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$SRC/../.." && pwd)
BASE=${MEEPCOIN_MUT_DIR:-/tmp/meepcoin-mut}
MIRROR=${MEEPCOIN_BASE_MIRROR:-/home/tseng/meepcoin-node}
PASS=0
FAIL=0

rm -rf "$BASE"; mkdir -p "$BASE"

fresh() {          # fresh <name> -> echoes a disposable copy of the lock dir
  local d="$BASE/$1"
  rm -rf "$d"; mkdir -p "$d"
  cp -a "$SRC/." "$d/"
  echo "$d"
}

# expect_fail <label> <command...>   : the command MUST exit non-zero
expect_fail() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    FAIL=$((FAIL+1)); printf '  FAIL  %s (was ACCEPTED)\n' "$label"
  else
    PASS=$((PASS+1)); printf '  ok    %s (refused)\n' "$label"
  fi
}

expect_ok() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS+1)); printf '  ok    %s (accepted)\n' "$label"
  else
    FAIL=$((FAIL+1)); printf '  FAIL  %s (was REFUSED)\n' "$label"
  fi
}

echo "================================================================="
echo "MeepCoin source-lock mutation tests"
echo "================================================================="

echo
echo "-- baseline: the real lock must pass --"
expect_ok "unmutated lock passes the contract"  python3 "$SRC/verify_lock.py" contract "$SRC"
expect_ok "unmutated MeepHash manifest passes"  python3 "$SRC/verify_lock.py" meepow "$SRC" "$REPO"

echo
echo "-- patch bytes --"
d=$(fresh wrongbyte)
printf '\n' >> "$d/patches/0002-consensus-quarantine-inherited-Monero-trust-anchors.patch"
expect_fail "one extra byte in patch 0002" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh flipbyte)
python3 - "$d" <<'PY'
import sys, os
p = os.path.join(sys.argv[1], "patches", "0001-daemon-preserve-current-MeepCoin-source-baseline.patch")
b = bytearray(open(p, "rb").read())
b[len(b)//2] ^= 0x01          # flip one bit; the SIZE is unchanged, only the hash moves
open(p, "wb").write(bytes(b))
PY
expect_fail "one flipped bit in patch 0001 (size unchanged)" python3 "$d/verify_lock.py" contract "$d"

echo
echo "-- patch set shape --"
d=$(fresh missing)
rm -f "$d/patches/0003-"*.patch
expect_fail "a declared patch is missing" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh extra)
cp "$d/patches/0003-"*.patch "$d/patches/0004-undeclared.patch"
expect_fail "an undeclared extra patch is present" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh renamed)
mv "$d/patches/0003-daemon-make-genesis-and-runtime-network-defaults-sel.patch" \
   "$d/patches/0003-renamed.patch"
expect_fail "a patch is renamed on disk" python3 "$d/verify_lock.py" contract "$d"

echo
echo "-- the JSON contract --"
mutate() {   # mutate <dir> <python-expression-body>
  python3 - "$1" "$2" <<'PY'
import json, sys, io, os, collections
d, code = sys.argv[1], sys.argv[2]
p = os.path.join(d, "SOURCE_LOCK.json")
lock = json.load(open(p), object_pairs_hook=collections.OrderedDict)
exec(code)
io.open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(lock, indent=2) + "\n")
PY
}
resum() {    # rewrite SHA256SUMS so the mutation is not merely caught by the checksum file
  ( cd "$1" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )
}

d=$(fresh badname);  mutate "$d" 'lock["patches"][2]["name"] = "0003-something-else.patch"'; resum "$d"
expect_fail "declared patch name does not match disk" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh badhash);  mutate "$d" 'lock["patches"][1]["sha256"] = "0"*64'; resum "$d"
expect_fail "declared patch sha256 is wrong" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh badsize);  mutate "$d" 'lock["patches"][0]["bytes"] = 12345'; resum "$d"
expect_fail "declared patch byte size is wrong" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh badcount); mutate "$d" 'lock["patch_count"] = 2'; resum "$d"
expect_fail "patch_count disagrees with the entries" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh misnumber); mutate "$d" 'lock["patches"][2]["order"] = 5'; resum "$d"
expect_fail "patch orders are not 1..N consecutive" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh reorder)
mutate "$d" 'lock["patches"][0]["order"], lock["patches"][1]["order"] = 2, 1'
resum "$d"
expect_fail "patches 1 and 2 are swapped in the declared order" sh -c "
  python3 '$d/verify_lock.py' emit '$d' | grep -q \"LOCK_PATCH_NAMES='0001\""

d=$(fresh unsafename); mutate "$d" 'lock["patches"][2]["name"] = "../escape.patch"'; resum "$d"
expect_fail "a patch name that escapes the directory" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh dupkey)
python3 - "$d" <<'PY'
import sys, os, io, re
p = os.path.join(sys.argv[1], "SOURCE_LOCK.json")
s = io.open(p, encoding="utf-8").read()
# Whatever the real count is, the duplicate must actually be inserted, or this test proves nothing.
s, n = re.subn(r'("patch_count": [0-9]+,)', r'\1\n  "patch_count": 99,', s, count=1)
assert n == 1, "no patch_count key to duplicate"
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
PY
resum "$d"
expect_fail "a duplicate top-level JSON key" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh badjson)
echo "{ not json" > "$d/SOURCE_LOCK.json"; resum "$d"
expect_fail "the lock is not valid JSON" python3 "$d/verify_lock.py" contract "$d"

echo
echo "-- SHA256SUMS coverage --"
d=$(fresh sumsmissing)
grep -v "verify_lock.py" "$d/SHA256SUMS" > "$d/SHA256SUMS.tmp" && mv "$d/SHA256SUMS.tmp" "$d/SHA256SUMS"
expect_fail "SHA256SUMS omits a lock file" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh sumsextra)
echo "$(printf '0%.0s' $(seq 64))  not-a-lock-file.txt" >> "$d/SHA256SUMS"
expect_fail "SHA256SUMS lists a file that is not part of the lock" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh sumsdup)
head -1 "$d/SHA256SUMS" >> "$d/SHA256SUMS"
expect_fail "SHA256SUMS lists the same file twice" python3 "$d/verify_lock.py" contract "$d"

d=$(fresh sumsstale)
mutate "$d" 'lock["base_tag"] = "tampered"'          # changes the file, SHA256SUMS not regenerated
expect_fail "a lock file changed without updating SHA256SUMS" python3 "$d/verify_lock.py" contract "$d"

echo
echo "-- base identity (requires a real reconstruction attempt) --"
d=$(fresh basecommit); mutate "$d" 'lock["base_commit"] = "1"*40'; resum "$d"
expect_fail "wrong base commit is refused" \
  sh "$d/reconstruct.sh" --dest "$BASE/out-basecommit" --from "$MIRROR"

d=$(fresh basetree); mutate "$d" 'lock["base_tree"] = "2"*40'; resum "$d"
expect_fail "wrong base tree is refused" \
  sh "$d/reconstruct.sh" --dest "$BASE/out-basetree" --from "$MIRROR"

d=$(fresh finaltree); mutate "$d" 'lock["expected_final_tree"] = "3"*40'; resum "$d"
expect_fail "wrong expected final tree is refused" \
  sh "$d/reconstruct.sh" --dest "$BASE/out-finaltree" --from "$MIRROR"

d=$(fresh finalinv); mutate "$d" 'lock["expected_source_inventory_digest"] = "4"*64'; resum "$d"
expect_fail "wrong source-inventory digest is refused" \
  sh "$d/reconstruct.sh" --dest "$BASE/out-finalinv" --from "$MIRROR"

echo
echo "-- destination shape --"
mkdir -p "$BASE/nonempty" && touch "$BASE/nonempty/something"
expect_fail "a non-empty --dest is refused" \
  sh "$SRC/reconstruct.sh" --dest "$BASE/nonempty" --from "$MIRROR"

ln -sfn "$BASE/nonempty" "$BASE/symlinked"
expect_fail "a symlinked --dest is refused" \
  sh "$SRC/reconstruct.sh" --dest "$BASE/symlinked" --from "$MIRROR"

mkdir -p "$BASE/insiderepo"
( cd "$BASE/insiderepo" && git init -q . && mkdir -p sub )
expect_fail "a --dest inside an existing git work tree is refused" \
  sh "$SRC/reconstruct.sh" --dest "$BASE/insiderepo/sub" --from "$MIRROR"

expect_fail "--in-place is gone and is rejected as an unknown argument" \
  sh "$SRC/reconstruct.sh" --in-place "$MIRROR"

echo
echo "-- MeepHash compile inputs --"
mkmeepow() {   # a disposable copy of just the declared MeepHash inputs, under a fake repo root
  local d="$BASE/$1"
  rm -rf "$d"; mkdir -p "$d"
  python3 - "$SRC" "$REPO" "$d" <<'PY'
import json, os, shutil, sys
lockdir, repo, dest = sys.argv[1], sys.argv[2], sys.argv[3]
man = json.load(open(os.path.join(lockdir, "MEEPOW_BUILD_INPUTS.json")))
for e in man["files"]:
    src = os.path.join(repo, e["path"])
    dst = os.path.join(dest, e["path"])
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
PY
  echo "$d"
}

m=$(mkmeepow mw-ok)
expect_ok "an exact copy of the declared MeepHash inputs passes" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-changed)
printf '\n// tampered\n' >> "$m/meepow/src/v2_api.cpp"
expect_fail "a changed MeepHash source is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-changed-hdr)
printf '\n' >> "$m/meepow/include/meepow/v2.hpp"
expect_fail "a changed MeepHash public header is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-changed-cmake)
printf '\n# tampered\n' >> "$m/meepow/CMakeLists.txt"
expect_fail "a changed MeepHash build-selection input is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-missing)
rm -f "$m/meepow/third_party/blake3/blake3_portable.c"
expect_fail "a missing MeepHash input is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-symlink)
rm -f "$m/meepow/src/v2_capi.cpp"
ln -s /etc/hostname "$m/meepow/src/v2_capi.cpp"
expect_fail "a symlinked MeepHash input is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

m=$(mkmeepow mw-dir)
rm -f "$m/meepow/src/vm.hpp"; mkdir -p "$m/meepow/src/vm.hpp"
expect_fail "a MeepHash input replaced by a directory is refused" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

# An ADDED file: the manifest cannot see it directly, and that is the honest position -- what
# protects the build is that meepow/CMakeLists.txt names every source explicitly and IS in the
# manifest, so a new file cannot be compiled without a change the manifest does catch.
m=$(mkmeepow mw-added)
printf '// unreferenced\n' > "$m/meepow/src/brand_new.cpp"
expect_ok "an unreferenced ADDED file does not fail the manifest (documented limit)" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"
m=$(mkmeepow mw-added2)
printf '\nadd_library(sneaky STATIC src/brand_new.cpp)\n' >> "$m/meepow/CMakeLists.txt"
expect_fail "...but adding it to CMakeLists.txt IS caught" \
  python3 "$SRC/verify_lock.py" meepow "$SRC" "$m"

echo
echo "-- manifest self-consistency --"
d=$(fresh mwagg)
python3 - "$d" <<'PY'
import json, sys, os, io, collections
p = os.path.join(sys.argv[1], "MEEPOW_BUILD_INPUTS.json")
m = json.load(open(p), object_pairs_hook=collections.OrderedDict)
m["aggregate_identity"] = "5"*64
io.open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(m, indent=2) + "\n")
PY
resum "$d"
expect_fail "a wrong aggregate identity is refused" python3 "$d/verify_lock.py" meepow "$d" "$REPO"

d=$(fresh mwcount)
python3 - "$d" <<'PY'
import json, sys, os, io, collections
p = os.path.join(sys.argv[1], "MEEPOW_BUILD_INPUTS.json")
m = json.load(open(p), object_pairs_hook=collections.OrderedDict)
m["file_count"] = 99
io.open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(m, indent=2) + "\n")
PY
resum "$d"
expect_fail "a wrong file_count is refused" python3 "$d/verify_lock.py" meepow "$d" "$REPO"

echo
echo "================================================================="
echo "RESULT: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then echo "MUTATION TESTS: PASS"; else echo "MUTATION TESTS: FAIL"; fi
echo "disposable directory: $BASE"
[ "$FAIL" -eq 0 ]
