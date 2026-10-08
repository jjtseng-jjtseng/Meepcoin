#!/usr/bin/env bash
# Build meepow-v2-helper, the long-lived native frozen-v2 verifier the local development pool
# cross-checks its WebAssembly result against.
#
#   bash scripts/build-native-helper.sh
#
# The output is a BUILD ARTIFACT and is never committed: it lands under meepow/build/, which
# .gitignore already excludes. Nothing here rebuilds the Wasm, touches the algorithm sources, or
# runs during pool startup -- if the helper is missing the pool fails closed and tells you to run
# this script.
set -euo pipefail

# Repository root, derived from this script's own location. No hard-coded path, no interpolation.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/meepow/build/native-helper"

INVENTORY="${REPO_ROOT}/scripts/helper-source-inventory.txt"

echo "repository : ${REPO_ROOT}"
echo "build dir  : ${BUILD_DIR}  (gitignored)"

# --- build-source identity -------------------------------------------------------------------
# sha256 of the sorted "<sha256>  <path>" listing of a CONSERVATIVE COVERED SOURCE SET. Compiled
# into the binary, reported in HELLO, and independently recomputed by pool/dev/source_identity.mjs,
# so the pool refuses a helper built from sources other than the ones on disk. It binds the binary
# to a source tree; it says nothing about the compiler, the flags, this script, meepow/CMakeLists.txt
# or the ELF's own bytes -- the build recipe is deliberately OUTSIDE the id.
#
# A listed file that is missing is a HARD FAILURE. Hashing a shorter inventory would produce a
# stable-looking id that quietly means something else.
#
# CANONICALISATION IS SHARED, NOT ASSUMED. pool/dev/source_identity.mjs applies the same rules --
# same comment/blank selection, same rejections -- so the two readers cannot disagree about what
# the listing contains. Anything ambiguous is refused by both rather than resolved by either.
#
# THE FINAL-NEWLINE RULE. `while IFS= read -r` drops a final line with no terminator; Node's
# split('\n') keeps it. Rather than paper over that asymmetry, BOTH readers require the inventory
# to end with LF. Command substitution strips trailing newlines, so this is empty exactly when the
# last byte is LF.
if [ -n "$(tail -c 1 "${INVENTORY}")" ]; then
  echo "source inventory does not end with a newline: ${INVENTORY}" >&2
  echo "Bash would drop its final line and Node would keep it, giving two different ids." >&2
  exit 1
fi

LISTING=""
SEEN=""
LINENO_INV=0
while IFS= read -r line; do
  LINENO_INV=$((LINENO_INV + 1))
  line="${line%%$'\r'}"
  case "${line}" in ''|'#'*) continue ;; esac
  # Canonical repository-relative path: printable ASCII, forward slashes, no leading slash, no
  # drive letter, no backslash, no '.'/'..' segment, no empty segment, no leading/trailing space.
  case "${line}" in
    */) echo "inventory line ${LINENO_INV}: trailing slash: ${line}" >&2; exit 1 ;;
    /*) echo "inventory line ${LINENO_INV}: absolute path: ${line}" >&2; exit 1 ;;
    [A-Za-z]:*) echo "inventory line ${LINENO_INV}: drive-qualified path: ${line}" >&2; exit 1 ;;
    *\\*) echo "inventory line ${LINENO_INV}: backslash is not portable: ${line}" >&2; exit 1 ;;
    './'*|'../'*|*'/./'*|*'/../'*|*'/.'|*'/..')
      echo "inventory line ${LINENO_INV}: '.'/'..' traversal is not allowed: ${line}" >&2; exit 1 ;;
    *'//'*) echo "inventory line ${LINENO_INV}: empty path segment: ${line}" >&2; exit 1 ;;
    ' '*|*' ') echo "inventory line ${LINENO_INV}: leading/trailing space: ${line}" >&2; exit 1 ;;
  esac
  if printf '%s' "${line}" | LC_ALL=C grep -q '[^!-~/]'; then
    echo "inventory line ${LINENO_INV}: not printable ASCII: ${line}" >&2
    exit 1
  fi
  # A duplicate, or two entries differing only by case, would make the id depend on spelling.
  lower="$(printf '%s' "${line}" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
  case "${SEEN}" in
    *"|${lower}|"*) echo "inventory line ${LINENO_INV}: duplicate or case-collision: ${line}" >&2; exit 1 ;;
  esac
  SEEN="${SEEN}|${lower}|"
  if [ ! -f "${REPO_ROOT}/${line}" ]; then
    echo "source inventory lists a file that does not exist (or is not a regular file): ${line}" >&2
    exit 1
  fi
  LISTING="${LISTING}$(sha256sum "${REPO_ROOT}/${line}" | cut -d' ' -f1)  ${line}"$'\n'
done < "${INVENTORY}"

SOURCE_ID="$(printf '%s' "${LISTING}" | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
SOURCE_FILES="$(printf '%s' "${LISTING}" | grep -c .)"
echo "inventory  : ${SOURCE_FILES} files from scripts/helper-source-inventory.txt"
echo "source id  : ${SOURCE_ID}"

cmake -S "${REPO_ROOT}/meepow" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release \
      -DMEEPOW_HELPER_SOURCE_ID="${SOURCE_ID}" >/dev/null
cmake --build "${BUILD_DIR}" --target meepow-v2-helper -j "$(nproc)"

HELPER="${BUILD_DIR}/meepow-v2-helper"
if [ ! -x "${HELPER}" ]; then
  echo "build finished but ${HELPER} is missing or not executable" >&2
  exit 1
fi

echo ""
echo "helper     : ${HELPER}"
echo "sha256     : $(sha256sum "${HELPER}" | cut -d' ' -f1)"
echo "size       : $(stat -c %s "${HELPER}") bytes"
echo "compiler   : $("$(cmake -LA -N -B "${BUILD_DIR}" 2>/dev/null | sed -n 's/^CMAKE_CXX_COMPILER:.*=//p' | head -1)" --version 2>/dev/null | head -1)"
echo "source id  : ${SOURCE_ID}"
echo ""
echo "The sha256 above is an OBSERVATION of this build on this machine, not a portable"
echo "expectation: a different compiler over the same sources gives a different ELF. The"
echo "source id is the value the pool actually checks."
echo ""
echo "Confirm the algorithm itself with the frozen-v2 vectors:"
echo "  node meepow/wasm/v2_regress.mjs"
