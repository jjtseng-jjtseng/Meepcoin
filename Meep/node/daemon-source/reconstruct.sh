#!/bin/sh
# Reconstruct and verify the locked MeepCoin daemon source from the pinned official Monero base.
#
#   ./reconstruct.sh --dest <new-or-empty-dir> [--from <url-or-local-path>] [--meepow <dir>] [--keep]
#
# THERE IS EXACTLY ONE MODE, AND IT NEVER TOUCHES A TREE IT DID NOT CREATE.
#
# An earlier version also had --in-place, which applied the series to a checkout the caller already
# had. It was removed, and it is worth saying why so nobody helpfully adds it back:
#
#   - its only safety check was the BASENAME of the supplied path, so a symlink or a differently
#     named copy of the live checkout walked straight past it;
#   - it committed into a repository it did not create, so a failure part-way through the series
#     left an earlier patch committed in somebody's working tree;
#   - the header claimed the script "refuses an existing tree it did not create" while --in-place
#     did exactly that. The documentation was false, which is worse than the behaviour.
#
# The container build now uses --dest into a fresh container-owned directory, exactly as a reviewer
# does, so the image and the reviewer run the same code path rather than two that can drift.
#
# WHAT THIS PROVES. That the MeepCoin daemon source is a deterministic patch series over an exact,
# publicly identifiable Monero commit -- so a reviewer can rebuild the reviewed bytes without
# trusting one developer's working directory. It proves SOURCE REPRODUCIBILITY and nothing else:
# it is not a build, not a test, not a security review, and not a claim about any network.
#
# WHAT IT WILL NOT DO. It writes only inside --dest, which must be new or empty. It starts no
# daemon, opens no socket, resolves no name beyond the clone, needs no wallet, and reads no secret.
#
# FAIL CLOSED. Every step is checked before the next one runs. A malformed lock, a missing or extra
# patch, a patch whose bytes do not match the lock, a wrong base commit or tree, a failed apply, a
# final tree that is not the expected one, an inventory digest that does not match, or a MeepHash
# build input that has moved all stop the script non-zero with the reason.

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK="$SELF_DIR/SOURCE_LOCK.json"
SUMS="$SELF_DIR/SHA256SUMS"
PATCH_DIR="$SELF_DIR/patches"
VERIFY="$SELF_DIR/verify_lock.py"

DEST=""
FROM=""
MEEPOW=""
KEEP=0

die() { printf 'reconstruct: %s\n' "$*" >&2; exit 1; }
say() { printf '== %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dest)   [ $# -ge 2 ] || die "--dest needs a value";   DEST="$2";   shift 2 ;;
    --from)   [ $# -ge 2 ] || die "--from needs a value";   FROM="$2";   shift 2 ;;
    --meepow) [ $# -ge 2 ] || die "--meepow needs a value"; MEEPOW="$2"; shift 2 ;;
    --keep)   KEEP=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$DEST" ] || die "--dest is required (a NEW or EMPTY directory; no existing tree is ever modified)"
[ -f "$LOCK" ]   || die "missing lock: $LOCK"
[ -f "$SUMS" ]   || die "missing checksums: $SUMS"
[ -f "$VERIFY" ] || die "missing verifier: $VERIFY"
[ -d "$PATCH_DIR" ] || die "missing patch directory: $PATCH_DIR"

command -v git >/dev/null 2>&1       || die "git is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v python3 >/dev/null 2>&1   || die "python3 is required (the lock is validated with a real JSON parser)"

# --------------------------------------------- 1. the lock, the patch contract and SHA256SUMS
# Validated by verify_lock.py with a real JSON parser: schema, patch_count, consecutive orders,
# exact and safe names, sha256 and byte size per patch, uniqueness, no undeclared patch, and a
# SHA256SUMS that covers exactly the intended files. The old sed-based reader could not tell a
# top-level key from one nested in a patch entry and treated an unreadable field as absent.
say "validating the lock, the patch contract and SHA256SUMS"
python3 "$VERIFY" contract "$SELF_DIR" || die "the lock or the patch series did not validate"

# Pull the validated values back as shell variables. verify_lock.py has already checked that every
# one of these is present, well-formed and safe, so this eval consumes checked data.
EMIT=$(python3 "$VERIFY" emit "$SELF_DIR") || die "could not read the validated lock"
eval "$EMIT"

[ -n "$FROM" ] || FROM="$LOCK_BASE_URL"

# --------------------------------------------- 2. the destination, which we must create or own
if [ -L "$DEST" ]; then
  die "--dest is a symlink: $DEST (refusing; the real target may be a tree we must not touch)"
fi
if [ -e "$DEST" ]; then
  [ -d "$DEST" ] || die "--dest exists and is not a directory: $DEST"
  if [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    die "--dest is not empty: $DEST (refusing to write into an existing tree)"
  fi
else
  mkdir -p "$DEST"
fi
DEST=$(CDPATH= cd -- "$DEST" && pwd)

# Belt and braces: even an empty directory must not be inside a git work tree, because a failed
# apply there would leave artefacts inside somebody's repository.
if ( cd "$DEST" && git rev-parse --is-inside-work-tree >/dev/null 2>&1 ); then
  die "--dest is inside an existing git work tree: $DEST (refusing)"
fi

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$KEEP" -eq 0 ]; then
    printf 'reconstruct: FAILED (exit %s); leaving %s for inspection\n' "$status" "$DEST" >&2
    printf 'reconstruct: nothing outside that directory was modified.\n' >&2
  fi
  exit "$status"
}
trap cleanup EXIT

# --------------------------------------------- 3. the base, verified before anything is applied
say "cloning the pinned base from: $FROM"
git clone --quiet --no-tags "$FROM" "$DEST/src" || die "clone failed"
WORK="$DEST/src"
cd "$WORK"
git checkout --quiet "$LOCK_BASE_COMMIT" 2>/dev/null \
  || die "the pinned base commit is not in that repository: $LOCK_BASE_COMMIT"

GOT_COMMIT=$(git rev-parse HEAD)
GOT_TREE=$(git rev-parse "HEAD^{tree}")
say "base commit: $GOT_COMMIT"
say "base tree:   $GOT_TREE"
[ "$GOT_COMMIT" = "$LOCK_BASE_COMMIT" ] || die "base commit mismatch: got $GOT_COMMIT, expected $LOCK_BASE_COMMIT"
[ "$GOT_TREE" = "$LOCK_BASE_TREE" ]     || die "base tree mismatch: got $GOT_TREE, expected $LOCK_BASE_TREE"
if [ -n "$LOCK_BASE_TAG" ]; then say "base tag (informational): $LOCK_BASE_TAG"; fi

# --------------------------------------------- 4. apply, in the locked order, fail closed
# Fixed identity and --committer-date-is-author-date make the replayed commits deterministic, so
# two reconstructions of the same series produce the same commit ids as well as the same tree.
# That is a convenience, not the contract: the TREE and the source-inventory digest are what the
# lock pins and what is checked below. Commit ids are not compared, because a reviewer using a
# different git version should still pass.
git config --local user.name "meepcoin-reconstruct"
git config --local user.email "reconstruct@localhost"

say "applying the patch series, in the locked order"
printf '%s\n' "$LOCK_PATCH_NAMES" | while IFS= read -r name; do
  [ -n "$name" ] || continue
  printf '   applying %s\n' "$name"
  # --keep-cr is REQUIRED, not cosmetic. `git am` strips a trailing CR from every patch body line
  # by default, because patches that travelled through email often gain them. Some MeepCoin sources
  # were authored on the Windows side and legitimately have CRLF terminators; without --keep-cr,
  # git am silently rewrites those files to LF and the reconstructed tree does not match the lock.
  # --whitespace=nowarn: git flags the preserved CRs as "trailing whitespace". Preserving the bytes
  # exactly IS the job here, so the warning is noise, not a finding.
  git am --quiet --keep-cr --whitespace=nowarn --committer-date-is-author-date \
      "$PATCH_DIR/$name" || {
    git am --abort >/dev/null 2>&1 || true
    echo "reconstruct: failed to apply $name -- the base or the series is not what the lock describes" >&2
    exit 1
  }
done || die "the patch series did not apply"

# The subshell above cannot fail the outer script on its own in every shell, so re-check that the
# series actually completed rather than trusting the pipeline's exit status.
if [ -d .git/rebase-apply ]; then die "a patch application was left incomplete"; fi

# --------------------------------------------- 5. verify what came out
FINAL_GOT_TREE=$(git rev-parse "HEAD^{tree}")
say "reconstructed tree: $FINAL_GOT_TREE"
say "expected tree:      $LOCK_FINAL_TREE"
[ "$FINAL_GOT_TREE" = "$LOCK_FINAL_TREE" ] || die "reconstructed tree does not match the lock"

if [ -n "$LOCK_FINAL_INV" ]; then
  say "verifying the MeepCoin source inventory digest"
  INV_GOT=$( { echo src/crypto/meep-hash.cpp
               echo src/crypto/meep-hash.h
               find src/meepcoin_genesis -maxdepth 1 -type f
             } | LC_ALL=C sort | xargs sha256sum | LC_ALL=C sort -k2 | sha256sum | cut -d' ' -f1 )
  say "inventory digest:   $INV_GOT"
  say "expected:           $LOCK_FINAL_INV"
  [ "$INV_GOT" = "$LOCK_FINAL_INV" ] || die "MeepCoin source inventory digest does not match the lock"
fi

# The reconstructed tree must be clean: `git am` leaving anything behind means the series and the
# lock disagree about the result.
[ -z "$(git status --porcelain)" ] || die "the reconstructed checkout is not clean"

# Exclusions the lock asserts. A reconstructed tree that contains them is not this source.
if [ -e external/miniupnp ]; then die "external/miniupnp must NOT be part of the locked source"; fi
if [ -e src/blocks/checkpoints.dat ] && [ "$LOCK_CHECKPOINT_BLOB" = "removed" ]; then
  die "src/blocks/checkpoints.dat is present but the lock says it was removed"
fi

# --------------------------------------------- 6. the MeepHash build inputs, if we were given them
# The daemon does not vendor MeepHash: it compiles the meepow/ tree it is pointed at. Verifying the
# reconstructed daemon source while accepting arbitrary proof-of-work bytes would lock the wrong
# half of the build, so --meepow checks the other half against MEEPOW_BUILD_INPUTS.json.
if [ -n "$MEEPOW" ]; then
  say "verifying the MeepHash compile inputs under: $MEEPOW"
  python3 "$VERIFY" meepow "$SELF_DIR" "$MEEPOW" || die "the MeepHash build inputs did not validate"
fi

printf '\nOK: the locked MeepCoin daemon source was reconstructed from %s and verified.\n' "$LOCK_BASE_COMMIT"
printf '    Source tree: %s\n' "$FINAL_GOT_TREE"
printf '    This is source reproducibility only -- not a build, not a test, not a security or\n'
printf '    network claim.\n'
trap - EXIT
exit 0
