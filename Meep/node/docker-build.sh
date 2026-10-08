#!/usr/bin/env bash
# MeepCoin daemon build entrypoint.
#
# Reconstructs the daemon source from the pinned Monero base using the CANONICAL ordered patch
# series in node/daemon-source/, verifies the MeepHash compile inputs, builds, and emits a manifest
# recording what actually went in.
#
# WHAT CHANGED, AND WHY IT MATTERS
#
#   - The previous version called reconstruct.sh --in-place /src/meepcoin-node. reconstruct.sh
#     refused every path ending in "meepcoin-node", so this script could not run at all: it exited
#     1 before applying a single patch. The canonical build path was broken, and nothing noticed
#     because nothing ran it. It now reconstructs into a fresh container-owned directory with
#     --dest, which is the same code path a reviewer uses.
#
#   - The MeepHash tree was bind-mounted at run time and checked only for the EXISTENCE of one
#     header. A modified or dirty proof-of-work implementation compiled happily while the daemon
#     source lock passed. The locked inputs are now COPIED INTO THE IMAGE and verified against
#     MEEPOW_BUILD_INPUTS.json, by hash, before cmake is invoked.
#
#   - The manifest called a post-patch commit id "monero_commit", printed an unverified MeepHash
#     tag as though it were evidence, emitted binaries only if they happened to exist, and ended
#     with `cp ... || true` so a failed copy could not fail the build. All four are fixed.
#
#   - The SUPERPROJECT reconstruction, the MeepCoin source inventory and the MeepHash identity all
#     matched, but the complete build checkout did not: reconstruct.sh clones the base with a plain
#     `git clone`, so the four pinned top-level submodule worktrees were absent, MANUAL_SUBMODULES=1
#     hid that from Monero's own check, and CMake failed on external/randomx and
#     external/supercop/functions.cmake. The build could not have produced a daemon. The submodules
#     are now hydrated from the image-local mirror only, with every identity checked, and Monero's
#     own submodule check is switched back on. The two self-test programs this script already built
#     but copied only "if present" are now required artifacts.
#
#   - With the submodules present, CMake's generate step then failed on meepow/src/meepow.cpp: the
#     legacy v1 `meepow` library is declared before meepow/CMakeLists.txt's MEEPOW_LIB_ONLY return,
#     so the path must exist, but it was outside the build context. It is now admitted as ONE
#     configure-only file, pinned here by size and SHA-256 (before CMake and after the build), kept
#     OUT of the 24-file MeepHash-v2 compile identity, and the build fails if its object or
#     libmeepow.a appears -- because then it would have entered the compile closure after all.
#
#   - meepcoin-blockhashing is dynamically linked to the pinned build image's Boost 1.83 libraries.
#     Exporting only the executable made it fail before HELLO on a WSL installation with another
#     Boost version. The two exact SONAMEs are now required, hashed in the manifest, and copied into
#     a closed runtime-libs directory beside the executable.
#
#   - meepcoind needs three additional Boost 1.83 SONAMEs on that WSL installation. Export their
#     exact build-image bytes into the same hashed runtime-libs directory, so a future direct-WSL
#     launcher can use the fresh daemon without silently borrowing host Boost libraries. This is
#     packaging only; this script still neither launches a daemon nor proves cross-distro ABI safety.
#
# WHAT THIS DOES NOT CLAIM. One build does not make a binary reproducible. That needs two
# independent clean builds producing identical artifacts and has not been done.

set -euo pipefail

LOCKDIR=/src/daemon-source
# MEEPOW_ROOT is the repo root the manifest's paths are relative to (they read 'meepow/src/...'),
# so the tree itself lives at $MEEPOW_ROOT/meepow.
MEEPOW_ROOT=/src/meephash
MEEPOW=$MEEPOW_ROOT/meepow
OUT=${OUT:-/out}

# A fresh directory this script owns. It is created here, it did not exist before, and nothing
# outside it is written.
SRC=/src/build-$(date -u +%Y%m%dT%H%M%SZ)-$$

# The binaries this build MUST produce. A missing one is fatal, not a silently shorter manifest.
# The v16 generator can derive the exact expected block-0 hash for a private timestamp without
# starting a daemon. Its published, deterministic genesis tx scalar is not a user wallet key.
REQUIRED_BINARIES=(meepcoind meepcoin-wallet-cli meepcoin-wallet-rpc meepcoin-genesis meepcoin-genesis16 meepcoin-blockhashing)
# The converter is intentionally a small dynamically linked tool. These exact Boost SONAMEs are
# part of its runtime closure and must travel with the binary because the execution WSL may carry a
# different Boost release. Discovery below is from the just-built ELF, never from a caller path.
REQUIRED_CONVERTER_RUNTIME_LIBRARIES=(libboost_filesystem.so.1.83.0 libboost_thread.so.1.83.0)
# Additional daemon dependencies; the two shared SONAMEs above are copied only once.
REQUIRED_DAEMON_RUNTIME_LIBRARIES=(libboost_chrono.so.1.83.0 libboost_program_options.so.1.83.0 libboost_serialization.so.1.83.0)
# The MeepCoin source/runtime regression programs built alongside them. Just as required: a build
# that silently omitted them could not show that the trust-anchor and runtime quarantines hold.
REQUIRED_TESTS=(meepcoin-trust-anchor-test meepcoin-runtime-quarantine-test meepcoin-fork-activation-test)

# The reconstructed superproject tree, and the ONLY submodules this build may hydrate, with the
# exact commits the pinned base's gitlinks record. external/miniupnp is not one of them and must
# stay absent.
# Patch 0008 (the owned block-hashing converter protocol) moved it from 66685010, which patch
# 0007 (a fork scheduled at genesis is active at genesis) moved from 4eb00bbd, which patch
# 0006 (wallet: no automatic sensitive log payloads) had moved from 77665903, which patch 0005
# (no true-ring-member logging) had moved from d699f64c, which patch 0004 (fixed
# MeepHash seed schedule, no RandomX block-PoW priming) had moved from 354ab669.
EXPECTED_SOURCE_TREE=9ce29e2c482910d911d8d3277bf7de4e85fd679b
SUBMODULES=(
  "external/randomx 6c4340ba4561aec9a3611c1aedf9931239777fb3"
  "external/rapidjson 129d19ba7f496df5e33658527a7158c79b99c21c"
  "external/supercop 633500ad8c8759995049ccd022107d1fa8a1bbc9"
  "external/trezor-common bff7fdfe436c727982cc553bdfb29a9021b423b0"
)
# The recursive clone the image made of the pinned base. The only place submodule objects may come from.
MIRROR=/src/monero

# THE ONE CMAKE CONFIGURE-ONLY INPUT. Not part of the 24-file MeepHash-v2 compile identity: it must
# exist for CMake to generate, and must never be compiled by the requested targets.
CONFIGURE_ONLY_REL=meepow/src/meepow.cpp
CONFIGURE_ONLY_PATH=$MEEPOW_ROOT/$CONFIGURE_ONLY_REL
CONFIGURE_ONLY_BYTES=9499
CONFIGURE_ONLY_SHA256=f390315cd94f9cf9292ed5f06e6e591fe5d2ff7897f44049f63f249fa4ce1cbf

fail() { echo "FATAL: $*" >&2; exit 4; }

verify_configure_only() {
  local when="$1" size digest
  [ ! -L "$CONFIGURE_ONLY_PATH" ] || fail "$CONFIGURE_ONLY_REL is a symbolic link ($when)"
  [ -f "$CONFIGURE_ONLY_PATH" ] || fail "$CONFIGURE_ONLY_REL is missing or not a regular file ($when)"
  size=$(stat -c '%s' "$CONFIGURE_ONLY_PATH")
  [ "$size" = "$CONFIGURE_ONLY_BYTES" ] || fail "$CONFIGURE_ONLY_REL is $size bytes, expected $CONFIGURE_ONLY_BYTES ($when)"
  digest=$(sha256sum "$CONFIGURE_ONLY_PATH" | cut -d' ' -f1)
  [ "$digest" = "$CONFIGURE_ONLY_SHA256" ] || fail "$CONFIGURE_ONLY_REL sha256 is $digest, expected $CONFIGURE_ONLY_SHA256 ($when)"
  echo "configure-only input  : $CONFIGURE_ONLY_REL  $CONFIGURE_ONLY_BYTES bytes  $digest  ($when: ok)"
}

mkdir -p "$OUT"

# ---------------------------------------------------------------- job count, deliberately bounded
# `nproc` on a build host is not a budget. Default to 4, or 2 when this looks like a battery-powered
# machine, and cap explicit values conservatively.
validate_jobs() {
  local j="$1"
  [[ "$j" =~ ^[1-9][0-9]?$ ]] || { echo "FATAL: MEEPCOIN_BUILD_JOBS must be a small positive integer, got: $j" >&2; exit 2; }
  (( j >= 1 && j <= 16 )) || { echo "FATAL: MEEPCOIN_BUILD_JOBS must be between 1 and 16, got: $j" >&2; exit 2; }
  echo "$j"
}
if [ -n "${MEEPCOIN_BUILD_JOBS:-}" ]; then
  JOBS=$(validate_jobs "$MEEPCOIN_BUILD_JOBS")
else
  JOBS=4
  for bat in /sys/class/power_supply/BAT*; do
    if [ -e "$bat" ]; then JOBS=2; break; fi
  done
fi
echo "=== build jobs: $JOBS ==="

# ---------------------------------------------------------------- 1. verify the MeepHash inputs
# Before anything is reconstructed or configured. These bytes are the proof-of-work; if they are
# not the locked ones, nothing else in this build is worth doing.
echo "=== verifying the MeepHash compile inputs ==="
python3 "$LOCKDIR/verify_lock.py" meepow "$LOCKDIR" "$MEEPOW_ROOT"
# Separately: the one configure-only file, before anything reaches CMake.
verify_configure_only "before cmake"

# ---------------------------------------------------------------- 2. reconstruct the daemon source
# Fail-closed: validates the lock's own JSON contract and checksums, that the patch set is exactly
# the locked one, that the base commit and tree are the pinned ones, that every patch applies, and
# that the resulting tree and source-inventory digest match. Nothing is compiled otherwise.
#
# --from points at the mirror the image already cloned, so the build does not re-clone from the
# network. The identity checks are what bind the result, not where the objects came from.
echo "=== reconstructing the MeepCoin source from the locked patch series ==="
export HOME=/src
sh "$LOCKDIR/reconstruct.sh" --dest "$SRC" --from /src/monero --meepow "$MEEPOW_ROOT" --keep

WORK="$SRC/src"
SOURCE_TREE=$(cd "$WORK" && git rev-parse 'HEAD^{tree}')
[ "$SOURCE_TREE" = "$EXPECTED_SOURCE_TREE" ] || fail "reconstructed tree is $SOURCE_TREE, expected $EXPECTED_SOURCE_TREE"

# A private fresh-genesis build is a separate, opt-in source variant. The canonical patch series
# and its reconstructed checkout remain untouched. Both settings are required together; the
# variant generator refuses a dirty/wrong source and records its exact two-file source tree.
PRIVATE_VARIANT=0
VARIANT_MANIFEST=
if [ -n "${MEEPCOIN_PRIVATE_GENESIS_TS:-}" ] || [ -n "${MEEPCOIN_PRIVATE_VARIANT_ID:-}" ]; then
  [ -n "${MEEPCOIN_PRIVATE_GENESIS_TS:-}" ] && [ -n "${MEEPCOIN_PRIVATE_VARIANT_ID:-}" ] \
    || fail "private variant requires both MEEPCOIN_PRIVATE_GENESIS_TS and MEEPCOIN_PRIVATE_VARIANT_ID"
  PRIVATE_VARIANT=1
  echo "=== deriving a separate private genesis source variant ==="
  python3 "$LOCKDIR/private_genesis_variant.py" \
    --source "$WORK" --dest "$SRC/private-variant" \
    --genesis-ts "$MEEPCOIN_PRIVATE_GENESIS_TS" --variant-id "$MEEPCOIN_PRIVATE_VARIANT_ID" \
    > "$OUT/private-variant-generator.log"
  WORK="$SRC/private-variant/src"
  VARIANT_MANIFEST="$SRC/private-variant/VARIANT_SOURCE_MANIFEST.json"
  [ -f "$VARIANT_MANIFEST" ] || fail "private variant generator produced no manifest"
fi

verify_source_checkout() {
  [ "$(git -C "$WORK" rev-parse 'HEAD^{tree}')" = "$EXPECTED_SOURCE_TREE" ] \
    || fail "source checkout HEAD tree drifted"
  if [ "$PRIVATE_VARIANT" -eq 0 ]; then
    [ -z "$(git -C "$WORK" status --porcelain --untracked-files=all)" ] \
      || fail "canonical source checkout is not clean"
    return
  fi
  local want_status got_status
  want_status=$(printf ' M src/cryptonote_config.h\n M src/hardforks/hardforks.cpp')
  got_status=$(git -C "$WORK" status --porcelain --untracked-files=all)
  [ "$got_status" = "$want_status" ] \
    || fail "private variant checkout has unexpected source changes: $got_status"
  python3 - "$WORK" "$VARIANT_MANIFEST" "$EXPECTED_SOURCE_TREE" <<'PY'
import hashlib, json, pathlib, sys
work = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
expected_base = sys.argv[3]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
def require(condition, message):
    if not condition:
        raise SystemExit(message)
require(manifest["schema"] == "meepcoin-private-genesis-source-variant/1", "wrong variant schema")
require(manifest["canonical_source_tree"] == expected_base, "wrong canonical tree")
require(manifest["status"] == "SOURCE_ONLY_NOT_BUILT_NOT_TESTED_NO_LAUNCH", "wrong variant status")
expected = {"src/cryptonote_config.h", "src/hardforks/hardforks.cpp"}
require(set(manifest["changed_files"]) == expected, "wrong variant changed-file inventory")
for rel, hashes in manifest["changed_files"].items():
    require(hashlib.sha256((work / rel).read_bytes()).hexdigest() == hashes["after_sha256"],
            f"changed variant source bytes: {rel}")
PY
  [ $? -eq 0 ] || fail "private variant source manifest does not match source bytes"
  git -C "$WORK" diff --check || fail "private variant has whitespace errors"
  local expected_variant_tree actual_variant_tree
  expected_variant_tree=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["variant_source_tree"])' "$VARIANT_MANIFEST")
  git -C "$WORK" add -- src/cryptonote_config.h src/hardforks/hardforks.cpp
  actual_variant_tree=$(git -C "$WORK" write-tree)
  git -C "$WORK" reset --quiet -- src/cryptonote_config.h src/hardforks/hardforks.cpp
  [ "$actual_variant_tree" = "$expected_variant_tree" ] \
    || fail "private variant source tree differs from the generator manifest"
}

# ---------------------------------------------------------------- 2b. hydrate the pinned submodules
# reconstruct.sh proves the SUPERPROJECT. Its plain clone leaves every submodule worktree empty, so
# this step supplies them -- and only these four, only from the image-local mirror, and only when
# five identities agree for each: the .gitmodules path, the reconstructed gitlink, the commit pinned
# above, the mirror checkout's HEAD, and the hydrated checkout's HEAD.
#
# NO NETWORK. The committed GitHub URL is overridden in the reconstructed checkout's own .git/config,
# for this build only; global and system Git configuration are never touched. The Git commands may use
# the local file transport and nothing else (protocol.allow=never, protocol.file.allow=always), and
# --no-fetch makes a missing object fail instead of reaching for a remote. The compile container is
# also run with --network none.
#
# NOT RECURSIVE. external/rapidjson/thirdparty/gtest and external/trezor-common/defs/ethereum/tokens
# are nested gitlinks outside the BUILD_TESTS=OFF / USE_DEVICE_TREZOR=OFF build closure. They are
# recorded in the manifest and deliberately left uninitialized.
echo "=== hydrating the pinned submodules from the image-local mirror ==="
cd "$WORK"
[ ! -e external/miniupnp ] || fail "external/miniupnp must remain absent"

# The reconstructed gitlinks must be EXACTLY the allowlist: nothing extra, nothing missing.
want_paths=$(for e in "${SUBMODULES[@]}"; do echo "${e%% *}"; done | LC_ALL=C sort)
got_paths=$(git ls-tree -r HEAD | awk '$2 == "commit" {print $4}' | LC_ALL=C sort)
[ "$got_paths" = "$want_paths" ] || fail "the reconstructed gitlinks are not exactly the pinned submodule allowlist"

SUBMODULE_LINES=()
NESTED_LINES=()
for entry in "${SUBMODULES[@]}"; do
  path=${entry%% *}
  want=${entry##* }
  # (1) the committed .gitmodules declares this path exactly once, which names the submodule.
  names=$(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' \
          | awk -v p="$path" '$2 == p { k = $1; sub(/^submodule\./, "", k); sub(/\.path$/, "", k); print k }')
  [ -n "$names" ] || fail "$path is not declared in .gitmodules"
  [ "$(printf '%s\n' "$names" | wc -l)" -eq 1 ] || fail "$path is declared more than once in .gitmodules"
  name=$names
  # (2) the reconstructed superproject's gitlink, and (3) the pinned commit.
  link=$(git rev-parse "HEAD:$path")
  [ "$link" = "$want" ] || fail "$path: reconstructed gitlink is $link, expected $want"
  # (4) the image-local mirror's checkout.
  [ -d "$MIRROR/$path" ] || fail "$path: the image mirror has no such checkout"
  mirror_head=$(git -C "$MIRROR/$path" rev-parse HEAD)
  [ "$mirror_head" = "$want" ] || fail "$path: the image mirror is at $mirror_head, expected $want"
  # Hydrate from that mirror only. Local transport only, no fetch, no recursion.
  git config --local "submodule.$name.url" "$MIRROR/$path"
  git -c protocol.allow=never -c protocol.file.allow=always \
      submodule update --init --no-fetch --checkout -- "$path"
  # (5) the hydrated checkout: exact, and clean.
  got=$(git -C "$path" rev-parse HEAD)
  [ "$got" = "$want" ] || fail "$path: hydrated checkout is at $got, expected $want"
  [ -z "$(git -C "$path" status --porcelain --untracked-files=all)" ] || fail "$path: hydrated checkout is not clean"
  SUBMODULE_LINES+=("$(printf '%-24s commit=%s tree=%s' "$path" "$got" "$(git -C "$path" rev-parse 'HEAD^{tree}')")")
  while read -r _mode _type nested_commit nested_path; do
    [ -n "${nested_commit:-}" ] || continue
    NESTED_LINES+=("$(printf '%-44s commit=%s (not initialized)' "$path/$nested_path" "$nested_commit")")
  done < <(git -C "$path" ls-tree -r HEAD | awk '$2 == "commit"')
done

# The superproject is still exactly the locked source, and clean with its submodules in place.
verify_source_checkout
if git submodule status -- "${SUBMODULES[@]%% *}" | grep -qv '^ '; then
  fail "a hydrated submodule is not at its recorded commit"
fi

# ---------------------------------------------------------------- 3. configure and build
# MANUAL_SUBMODULES=0: Monero's own CMake check independently compares each of the four submodule
# HEADs with the superproject's gitlinks, and stops the build if one differs.
echo "=== configuring ==="
mkdir -p "$WORK/build/release"
cd "$WORK/build/release"
cmake -D CMAKE_BUILD_TYPE=Release \
      -D BUILD_TESTS=OFF \
      -D USE_DEVICE_TREZOR=OFF \
      -D MANUAL_SUBMODULES=0 \
      -D MEEPCOIN_MEEPOW_DIR="$MEEPOW" \
      ../.. > "$OUT/cmake.log" 2>&1
CMAKE_SUBMODULE_CHECKS=$(grep -cE "^-- Submodule '(external/randomx|external/rapidjson|external/supercop|external/trezor-common)' is up-to-date$" "$OUT/cmake.log" || true)
[ "$CMAKE_SUBMODULE_CHECKS" = "${#SUBMODULES[@]}" ] \
  || fail "CMake reported $CMAKE_SUBMODULE_CHECKS of ${#SUBMODULES[@]} submodules up-to-date"

echo "=== building (-j$JOBS) ==="
make -j"$JOBS" daemon simplewallet wallet_rpc_server meepcoin-genesis meepcoin-genesis16 meepcoin-blockhashing \
     meepcoin-trust-anchor-test meepcoin-runtime-quarantine-test meepcoin-fork-activation-test \
     > "$OUT/build.log" 2>&1

# ---------------------------------------------------------------- 4. every required binary exists
echo "=== checking required artifacts ==="
missing=()
for b in "${REQUIRED_BINARIES[@]}" "${REQUIRED_TESTS[@]}"; do
  [ -f "$WORK/build/release/bin/$b" ] || missing+=("$b")
done
if [ ${#missing[@]} -ne 0 ]; then
  echo "FATAL: the build did not produce: ${missing[*]}" >&2
  exit 3
fi

# Resolve the converter's required Boost libraries from the build container's own dynamic-link map.
# Exactly one absolute regular-file match per SONAME is required. The paths and hashes are retained
# for the manifest and copied only after the complete manifest has been written.
CONVERTER_RUNTIME_LIBRARY_PATHS=()
for lib in "${REQUIRED_CONVERTER_RUNTIME_LIBRARIES[@]}"; do
  mapfile -t matches < <(ldd "$WORK/build/release/bin/meepcoin-blockhashing" \
    | awk -v wanted="$lib" '$1 == wanted && $2 == "=>" { print $3 }')
  [ "${#matches[@]}" -eq 1 ] || fail "converter resolved ${#matches[@]} paths for required runtime library $lib"
  [[ "${matches[0]}" = /* ]] || fail "converter runtime library $lib did not resolve to an absolute path"
  [ -f "${matches[0]}" ] || fail "converter runtime library $lib is not a regular file: ${matches[0]}"
  [ "$(basename -- "${matches[0]}")" = "$lib" ] || fail "converter runtime library basename drifted for $lib"
  CONVERTER_RUNTIME_LIBRARY_PATHS+=("${matches[0]}")
done
DAEMON_RUNTIME_LIBRARY_PATHS=()
for lib in "${REQUIRED_DAEMON_RUNTIME_LIBRARIES[@]}"; do
  mapfile -t matches < <(ldd "$WORK/build/release/bin/meepcoind" \
    | awk -v wanted="$lib" '$1 == wanted && $2 == "=>" { print $3 }')
  [ "${#matches[@]}" -eq 1 ] || fail "daemon resolved ${#matches[@]} paths for required runtime library $lib"
  [[ "${matches[0]}" = /* ]] || fail "daemon runtime library $lib did not resolve to an absolute path"
  [ -f "${matches[0]}" ] || fail "daemon runtime library $lib is not a regular file: ${matches[0]}"
  [ "$(basename -- "${matches[0]}")" = "$lib" ] || fail "daemon runtime library basename drifted for $lib"
  DAEMON_RUNTIME_LIBRARY_PATHS+=("${matches[0]}")
done

# ---------------------------------------------------------------- 5. re-verify MeepHash after build
# Cheap, and it catches a tree that changed under a long build.
echo "=== re-verifying the MeepHash compile inputs after the build ==="
python3 "$LOCKDIR/verify_lock.py" meepow "$LOCKDIR" "$MEEPOW_ROOT"
verify_configure_only "after build"
verify_source_checkout

# ---------------------------------------------------------------- 5b. the legacy v1 target was NOT compiled
# PROVED FROM THE FRESH BUILD TREE, not assumed. If meepow.cpp was compiled, or libmeepow.a was
# archived, the file entered the build closure and keeping it outside the 24-file identity would be
# false -- so that is a build failure, not a note. The log is checked too, but only as a second look.
echo "=== checking that the legacy v1 meepow target was not compiled ==="
LEGACY_V1_OUTPUTS=$(find "$WORK/build/release" \( -name 'meepow.cpp.o' -o -name 'meepow.cpp.obj' -o -name 'libmeepow.a' \) -print)
[ -z "$LEGACY_V1_OUTPUTS" ] || fail "the legacy v1 meepow target was compiled: $LEGACY_V1_OUTPUTS"
if grep -qE 'meepow\.dir/src/meepow\.cpp|libmeepow\.a' "$OUT/build.log"; then
  fail "build.log shows the legacy v1 meepow target being built"
fi
echo "legacy v1 meepow      : no meepow.cpp.o/.obj or libmeepow.a in the fresh build tree; no compile line in build.log"

# ---------------------------------------------------------------- 6. manifest
echo "=== manifest ==="
M="$OUT/BUILD_MANIFEST.txt"
{
  echo "# MeepCoin daemon build manifest"
  echo "generated_utc            = $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source_date_epoch        = ${SOURCE_DATE_EPOCH:-unset}"
  echo
  echo "## source identity"
  # The BASE is Monero's; the RESULT is MeepCoin's. The old manifest labelled the post-patch HEAD
  # "monero_commit", which named the wrong thing twice over: it is not Monero, and it is a synthetic
  # replay commit rather than a pinned identity.
  echo "monero_base_commit       = $(python3 -c "import json,sys;print(json.load(open('$LOCKDIR/SOURCE_LOCK.json'))['base_commit'])")"
  echo "monero_base_tree         = $(python3 -c "import json,sys;print(json.load(open('$LOCKDIR/SOURCE_LOCK.json'))['base_tree'])")"
  echo "meepcoin_source_tree     = $SOURCE_TREE"
  if [ "$PRIVATE_VARIANT" -eq 1 ]; then
    echo "source_variant_mode      = PRIVATE_GENESIS_SOURCE_VARIANT"
    echo "source_variant_id        = $MEEPCOIN_PRIVATE_VARIANT_ID"
    echo "source_variant_genesis_ts = $MEEPCOIN_PRIVATE_GENESIS_TS"
    echo "source_variant_manifest_sha256 = $(sha256sum "$VARIANT_MANIFEST" | cut -d' ' -f1)"
    echo "source_variant_tree      = $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["variant_source_tree"])' "$VARIANT_MANIFEST")"
    echo "old_genesis_runtime_quarantine_test = INAPPLICABLE (built but not passed for this variant)"
  else
    echo "source_variant_mode      = CANONICAL"
  fi
  echo "source_lock_sha256       = $(sha256sum "$LOCKDIR/SOURCE_LOCK.json" | cut -d' ' -f1)"
  echo "reconstruct_sh_sha256    = $(sha256sum "$LOCKDIR/reconstruct.sh" | cut -d' ' -f1)"
  echo "verify_lock_py_sha256    = $(sha256sum "$LOCKDIR/verify_lock.py" | cut -d' ' -f1)"
  echo "docker_builder_sha256    = $(sha256sum /usr/local/bin/meepcoin-build | cut -d' ' -f1)"
  if [ "$PRIVATE_VARIANT" -eq 1 ]; then
    echo "private_variant_generator_sha256 = $(sha256sum "$LOCKDIR/private_genesis_variant.py" | cut -d' ' -f1)"
  fi
  echo
  echo "## proof-of-work build inputs"
  # Verified by hash above, twice. Not a tag, not a vector file: the manifest of every file the
  # meepow_v2 compile closure reads.
  echo "meephash_manifest_sha256 = $(sha256sum "$LOCKDIR/MEEPOW_BUILD_INPUTS.json" | cut -d' ' -f1)"
  echo "meephash_identity        = $(python3 -c "import json;print(json.load(open('$LOCKDIR/MEEPOW_BUILD_INPUTS.json'))['aggregate_identity'])")"
  echo "meephash_file_count      = $(python3 -c "import json;print(json.load(open('$LOCKDIR/MEEPOW_BUILD_INPUTS.json'))['file_count'])")"
  echo
  echo "## CMake configure-only input -- NOT part of the MeepHash-v2 compile identity"
  echo "path                     = $CONFIGURE_ONLY_REL"
  echo "role                     = declared by meepow/CMakeLists.txt (legacy v1 meepow target); required by CMake generate; not compiled by the requested targets"
  echo "bytes                    = $CONFIGURE_ONLY_BYTES"
  echo "sha256                   = $CONFIGURE_ONLY_SHA256"
  echo "verified                 = before cmake: ok; after build: ok"
  echo "legacy_v1_compiled       = no (no meepow.cpp.o/.obj or libmeepow.a in the fresh build tree; no compile line in build.log)"
  echo
  echo "## pinned submodules (hydrated from the image-local mirror $MIRROR; no network)"
  for line in "${SUBMODULE_LINES[@]}"; do echo "  $line"; done
  echo "  cmake_submodule_checks = $CMAKE_SUBMODULE_CHECKS of ${#SUBMODULES[@]} up-to-date"
  echo "  nested gitlinks, outside the BUILD_TESTS=OFF / USE_DEVICE_TREZOR=OFF build closure:"
  for line in "${NESTED_LINES[@]}"; do echo "    $line"; done
  echo
  echo "## platform"
  echo "target_platform          = ${MEEPCOIN_TARGET_PLATFORM:-linux/amd64}"
  echo "uname_m                  = $(uname -m)"
  echo "kernel                   = $(uname -r)"
  echo "os                       = $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "build_jobs               = $JOBS"
  echo
  echo "## toolchain"
  echo "gcc                      = $(gcc --version | head -1)"
  echo "g++                      = $(g++ --version | head -1)"
  echo "cmake                    = $(cmake --version | head -1)"
  echo "make                     = $(make --version | head -1)"
  echo "ld                       = $(ld --version | head -1)"
  echo "python3                  = $(python3 --version)"
  echo
  echo "## dependency versions"
  echo "boost                    = $(grep -oP '(?<=#define BOOST_LIB_VERSION ")[^"]+' /usr/include/boost/version.hpp)"
  for p in libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind-dev liblzma-dev \
           libreadline-dev libexpat1-dev libudev-dev libprotobuf-dev libboost-all-dev; do
    printf '%-24s = %s\n' "$p" "$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || echo absent)"
  done
  echo
  echo "## build options"
  echo "CMAKE_BUILD_TYPE         = Release"
  echo "BUILD_TESTS              = OFF"
  echo "USE_DEVICE_TREZOR        = OFF"
  echo "MANUAL_SUBMODULES        = $(grep -E '^MANUAL_SUBMODULES:' CMakeCache.txt | cut -d= -f2)"
  echo "MEEPOW_LIB_ONLY          = $(grep -E '^MEEPOW_LIB_ONLY:' CMakeCache.txt | cut -d= -f2)"
  echo "MEEPOW_BLAKE3_PORTABLE   = $(grep -E '^MEEPOW_BLAKE3_PORTABLE:' CMakeCache.txt | cut -d= -f2)"
  echo
  echo "## consensus identity"
  grep -E '^#define (CRYPTONOTE_NAME|DIFFICULTY_TARGET_V2|CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW|MEEPCOIN_GENESIS_TIMESTAMP)' \
       "$WORK/src/cryptonote_config.h" | sed 's/#define /  /'
  echo
  echo "## required binaries (sha256)"
  for b in "${REQUIRED_BINARIES[@]}"; do
    printf '%-34s = %s\n' "$b" "$(sha256sum "$WORK/build/release/bin/$b" | cut -d' ' -f1)"
  done
  echo
  echo "## required converter runtime libraries (sha256)"
  for i in "${!REQUIRED_CONVERTER_RUNTIME_LIBRARIES[@]}"; do
    lib="${REQUIRED_CONVERTER_RUNTIME_LIBRARIES[$i]}"
    path="${CONVERTER_RUNTIME_LIBRARY_PATHS[$i]}"
    printf '%-54s = %s\n' "runtime-libs/$lib" "$(sha256sum "$path" | cut -d' ' -f1)"
  done
  echo "## additional required daemon runtime libraries (sha256)"
  for i in "${!REQUIRED_DAEMON_RUNTIME_LIBRARIES[@]}"; do
    lib="${REQUIRED_DAEMON_RUNTIME_LIBRARIES[$i]}"
    path="${DAEMON_RUNTIME_LIBRARY_PATHS[$i]}"
    printf '%-54s = %s\n' "runtime-libs/$lib" "$(sha256sum "$path" | cut -d' ' -f1)"
  done
  echo
  echo "## required test programs (sha256)"
  for b in "${REQUIRED_TESTS[@]}"; do
    printf '%-34s = %s\n' "$b" "$(sha256sum "$WORK/build/release/bin/$b" | cut -d' ' -f1)"
  done
  echo
  echo "## NOT established by this build"
  echo "  - reproducibility: one build proves nothing about bit-for-bit reproducibility."
  echo "  - correctness, safety, or fitness of the daemon. It was compiled, not reviewed and not run."
} > "$M"

# ---------------------------------------------------------------- 7. copy out, errors are fatal
# The old `cp ... 2>/dev/null || true` meant a failed copy produced a green build with no binaries.
echo "=== copying artifacts ==="
for b in "${REQUIRED_BINARIES[@]}" "${REQUIRED_TESTS[@]}"; do
  cp -f "$WORK/build/release/bin/$b" "$OUT/"
done
if [ "$PRIVATE_VARIANT" -eq 1 ]; then
  cp "$VARIANT_MANIFEST" "$OUT/VARIANT_SOURCE_MANIFEST.json"
  [ "$(sha256sum "$VARIANT_MANIFEST" | cut -d' ' -f1)" = "$(sha256sum "$OUT/VARIANT_SOURCE_MANIFEST.json" | cut -d' ' -f1)" ] \
    || fail "private variant manifest changed during export"
fi
if [ -e "$OUT/runtime-libs" ]; then
  fail "output runtime-libs path already exists; refusing stale or caller-supplied libraries"
fi
install -d -m 0755 "$OUT/runtime-libs"
for i in "${!REQUIRED_CONVERTER_RUNTIME_LIBRARIES[@]}"; do
  lib="${REQUIRED_CONVERTER_RUNTIME_LIBRARIES[$i]}"
  source_path="${CONVERTER_RUNTIME_LIBRARY_PATHS[$i]}"
  install -m 0644 "$source_path" "$OUT/runtime-libs/$lib"
  [ "$(sha256sum "$source_path" | cut -d' ' -f1)" = "$(sha256sum "$OUT/runtime-libs/$lib" | cut -d' ' -f1)" ] \
    || fail "copied converter runtime library changed bytes: $lib"
done
for i in "${!REQUIRED_DAEMON_RUNTIME_LIBRARIES[@]}"; do
  lib="${REQUIRED_DAEMON_RUNTIME_LIBRARIES[$i]}"
  source_path="${DAEMON_RUNTIME_LIBRARY_PATHS[$i]}"
  install -m 0644 "$source_path" "$OUT/runtime-libs/$lib"
  [ "$(sha256sum "$source_path" | cut -d' ' -f1)" = "$(sha256sum "$OUT/runtime-libs/$lib" | cut -d' ' -f1)" ] \
    || fail "copied daemon runtime library changed bytes: $lib"
done

cat "$M"
echo
echo "Artifacts and manifest in $OUT"
echo "Reconstructed source kept at $WORK"
