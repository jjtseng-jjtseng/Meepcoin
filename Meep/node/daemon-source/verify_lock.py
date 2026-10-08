#!/usr/bin/env python3
"""Validate SOURCE_LOCK.json, SHA256SUMS and MEEPOW_BUILD_INPUTS.json.

WHY THIS EXISTS AS PYTHON. The previous verifier read the lock with sed. A sed "parser" cannot
tell a top-level key from the same key nested inside a patch entry or a comment string, cannot
notice a duplicate key, and silently takes whichever match happens to come first. Every field it
failed to read it simply treated as absent, so a malformed lock produced a PASS. This reads the
file with a real JSON parser, rejects duplicate keys outright, and enforces the whole declared
contract rather than the two fields the shell happened to need.

WHAT IT ENFORCES
  - the lock is valid JSON with no duplicate keys, and has the expected schema id;
  - patch_count matches the number of declared entries AND the number of files on disk;
  - patch orders are 1..N, consecutive, no gaps or repeats;
  - every patch name is a safe relative filename (no /, no \\, no "..", no leading dash/dot);
  - every declared patch exists, with exactly the declared sha256 and byte size;
  - names and hashes are unique across entries;
  - no undeclared *.patch file is present in patches/;
  - SHA256SUMS covers exactly the intended set of files -- no missing, extra or duplicate entry --
    and every checksum matches;
  - the MeepHash build-input manifest's declared files exist, are regular files (not symlinks, not
    directories), have the declared hashes and sizes, contain no case-collision or unsafe path, and
    reproduce the declared aggregate identity.

WHAT IT DOES NOT DO. It does not clone, patch or build anything: reconstruct.sh does that, and
calls this first. It performs no network access of any kind.

Usage:
  verify_lock.py contract <lock-dir>          # lock + patch contract + SHA256SUMS
  verify_lock.py emit <lock-dir>              # print shell-eval'able KEY=VALUE for reconstruct.sh
  verify_lock.py meepow <lock-dir> <repo-root>  # MeepHash compile-input manifest
"""

import hashlib
import json
import os
import stat
import sys

SCHEMA_LOCK = "meepcoin-daemon-source-lock/1"
SCHEMA_MEEPOW = "meepcoin-meepow-build-inputs/1"

# Files that must be listed in SHA256SUMS, besides the patches. SHA256SUMS never lists itself.
LOCK_FILES = ["MEEPOW_BUILD_INPUTS.json", "SOURCE_LOCK.json", "fork_rules_test.sh",
              "mutation_tests.sh", "reconstruct.sh", "verify_lock.py", "wallet_log_privacy_test.sh"]

HEX64 = "0123456789abcdef"


def die(msg):
    sys.stderr.write("verify_lock: %s\n" % msg)
    sys.exit(1)


def no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            die("duplicate key %r in JSON object -- a lock that says a thing twice says nothing" % k)
        seen[k] = v
    return seen


def load_json(path):
    if not os.path.isfile(path):
        die("missing file: %s" % path)
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except ValueError as e:
        die("%s is not valid JSON: %s" % (os.path.basename(path), e))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_hex64(s):
    """A sha256 digest: exactly 64 hex characters."""
    return isinstance(s, str) and len(s) == 64 and all(c in HEX64 for c in s.lower())


def is_git_oid(s):
    """A git object id. 40 hex for SHA-1 repositories, 64 for SHA-256 ones -- both are valid, and
    pinning only one would reject a legitimate checkout rather than catch a real problem."""
    return isinstance(s, str) and len(s) in (40, 64) and all(c in HEX64 for c in s.lower())


def safe_name(name):
    """A bare filename that cannot escape its directory or be read as an option."""
    if not isinstance(name, str) or not name:
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    if name in (".", "..") or name.startswith("-") or name.startswith("."):
        return False
    return True


def safe_relpath(p):
    """A relative path that stays inside the tree."""
    if not isinstance(p, str) or not p or "\\" in p or "\x00" in p:
        return False
    if p.startswith("/") or p.startswith("-"):
        return False
    parts = p.split("/")
    return all(seg not in ("", ".", "..") for seg in parts)


def require(d, key, kind, where):
    if key not in d:
        die("%s is missing required field %r" % (where, key))
    v = d[key]
    if not isinstance(v, kind):
        die("%s: %r has the wrong type (%s, expected %s)"
            % (where, key, type(v).__name__, getattr(kind, "__name__", kind)))
    return v


# --------------------------------------------------------------------------- the patch contract
def check_contract(lockdir):
    lock = load_json(os.path.join(lockdir, "SOURCE_LOCK.json"))

    schema = require(lock, "schema", str, "SOURCE_LOCK.json")
    if schema != SCHEMA_LOCK:
        die("unexpected schema %r (expected %r)" % (schema, SCHEMA_LOCK))

    for key in ("base_repository", "base_commit", "base_tree",
                "expected_final_tree", "expected_source_inventory_digest"):
        v = require(lock, key, str, "SOURCE_LOCK.json")
        if not v:
            die("SOURCE_LOCK.json: %r is empty" % key)
    for key in ("base_commit", "base_tree", "expected_final_tree"):
        if not is_git_oid(lock[key]):
            die("SOURCE_LOCK.json: %r is not a git object id (40 or 64 hex characters)" % key)
    if not is_hex64(lock["expected_source_inventory_digest"]):
        die("SOURCE_LOCK.json: 'expected_source_inventory_digest' is not a sha256")

    count = require(lock, "patch_count", int, "SOURCE_LOCK.json")
    patches = require(lock, "patches", list, "SOURCE_LOCK.json")
    if count != len(patches):
        die("patch_count is %d but %d patch entries are declared" % (count, len(patches)))
    if count < 1:
        die("patch_count must be at least 1")

    patchdir = os.path.join(lockdir, "patches")
    if not os.path.isdir(patchdir):
        die("missing patch directory: %s" % patchdir)

    seen_names, seen_hashes, seen_orders = set(), set(), set()
    ordered = []
    for i, p in enumerate(patches):
        where = "patches[%d]" % i
        if not isinstance(p, dict):
            die("%s is not an object" % where)
        order = require(p, "order", int, where)
        name = require(p, "name", str, where)
        digest = require(p, "sha256", str, where)
        nbytes = require(p, "bytes", int, where)

        if order in seen_orders:
            die("%s: duplicate order %d" % (where, order))
        seen_orders.add(order)
        if not safe_name(name):
            die("%s: %r is not a safe bare filename" % (where, name))
        if name in seen_names:
            die("%s: duplicate patch name %r" % (where, name))
        seen_names.add(name)
        if not is_hex64(digest):
            die("%s: sha256 is not a 64-character hex digest" % where)
        if digest in seen_hashes:
            die("%s: two entries declare the same sha256 %s" % (where, digest))
        seen_hashes.add(digest)
        if nbytes <= 0:
            die("%s: bytes must be positive" % where)
        ordered.append((order, name, digest, nbytes))

    if sorted(seen_orders) != list(range(1, count + 1)):
        die("patch orders are not 1..%d consecutive: got %s" % (count, sorted(seen_orders)))

    ordered.sort(key=lambda t: t[0])

    # Every declared patch must be on disk with exactly the declared bytes.
    for order, name, digest, nbytes in ordered:
        ap = os.path.join(patchdir, name)
        if not os.path.isfile(ap):
            die("declared patch %d is missing on disk: %s" % (order, name))
        got_bytes = os.path.getsize(ap)
        if got_bytes != nbytes:
            die("patch %s is %d bytes, the lock declares %d" % (name, got_bytes, nbytes))
        got = sha256_file(ap)
        if got != digest:
            die("patch %s hashes to %s, the lock declares %s" % (name, got, digest))

    # And nothing else may be in patches/: an extra patch is a different source.
    on_disk = sorted(f for f in os.listdir(patchdir) if f.endswith(".patch"))
    if on_disk != sorted(seen_names):
        extra = [f for f in on_disk if f not in seen_names]
        missing = [f for f in seen_names if f not in on_disk]
        die("patches/ does not match the lock. undeclared: %s; declared but absent: %s"
            % (extra or "none", missing or "none"))

    check_sha256sums(lockdir, sorted(seen_names))
    return lock, ordered


# --------------------------------------------------------------------------------- SHA256SUMS
def check_sha256sums(lockdir, patch_names):
    path = os.path.join(lockdir, "SHA256SUMS")
    if not os.path.isfile(path):
        die("missing SHA256SUMS")

    expected = set(LOCK_FILES) | set("patches/" + n for n in patch_names)

    entries = {}
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            # "<64 hex><two spaces or space+star><path>"
            if len(line) < 67:
                die("SHA256SUMS line %d is malformed" % lineno)
            digest, rest = line[:64], line[64:]
            if not is_hex64(digest):
                die("SHA256SUMS line %d does not start with a sha256" % lineno)
            name = rest[2:] if rest[:2] in ("  ", " *") else rest.lstrip(" *")
            if name in entries:
                die("SHA256SUMS lists %s more than once" % name)
            entries[name] = digest

    if "SHA256SUMS" in entries:
        die("SHA256SUMS must not list itself")

    missing = sorted(expected - set(entries))
    extra = sorted(set(entries) - expected)
    if missing:
        die("SHA256SUMS is missing: %s" % ", ".join(missing))
    if extra:
        die("SHA256SUMS lists files that are not part of the lock: %s" % ", ".join(extra))

    for name, digest in sorted(entries.items()):
        if not safe_relpath(name):
            die("SHA256SUMS entry %r is not a safe relative path" % name)
        ap = os.path.join(lockdir, name.replace("/", os.sep))
        if not os.path.isfile(ap):
            die("SHA256SUMS lists a file that does not exist: %s" % name)
        got = sha256_file(ap)
        if got != digest:
            die("%s hashes to %s, SHA256SUMS says %s" % (name, got, digest))


# ------------------------------------------------------------------- MeepHash compile inputs
def check_meepow(lockdir, repo_root):
    man = load_json(os.path.join(lockdir, "MEEPOW_BUILD_INPUTS.json"))

    schema = require(man, "schema", str, "MEEPOW_BUILD_INPUTS.json")
    if schema != SCHEMA_MEEPOW:
        die("unexpected meepow manifest schema %r (expected %r)" % (schema, SCHEMA_MEEPOW))

    files = require(man, "files", list, "MEEPOW_BUILD_INPUTS.json")
    count = require(man, "file_count", int, "MEEPOW_BUILD_INPUTS.json")
    aggregate = require(man, "aggregate_identity", str, "MEEPOW_BUILD_INPUTS.json")
    if not is_hex64(aggregate):
        die("aggregate_identity is not a 64-character hex digest")
    if count != len(files):
        die("file_count is %d but %d files are declared" % (count, len(files)))

    lines = []
    seen, seen_lower = set(), {}
    for i, e in enumerate(files):
        where = "files[%d]" % i
        if not isinstance(e, dict):
            die("%s is not an object" % where)
        rel = require(e, "path", str, where)
        digest = require(e, "sha256", str, where)
        nbytes = require(e, "bytes", int, where)

        if not safe_relpath(rel):
            die("%s: %r is not a safe relative path" % (where, rel))
        if rel in seen:
            die("%s: %r is declared twice" % (where, rel))
        seen.add(rel)
        low = rel.lower()
        if low in seen_lower and seen_lower[low] != rel:
            die("%s: %r and %r differ only by case, which is ambiguous on some filesystems"
                % (where, seen_lower[low], rel))
        seen_lower[low] = rel
        if not is_hex64(digest):
            die("%s: sha256 is not a 64-character hex digest" % where)

        ap = os.path.join(repo_root, rel.replace("/", os.sep))
        if not os.path.exists(ap):
            die("declared MeepHash build input is missing: %s" % rel)
        st = os.lstat(ap)
        if stat.S_ISLNK(st.st_mode):
            die("declared MeepHash build input is a symlink: %s" % rel)
        if not stat.S_ISREG(st.st_mode):
            die("declared MeepHash build input is not a regular file: %s" % rel)
        if st.st_size != nbytes:
            die("%s is %d bytes, the manifest declares %d" % (rel, st.st_size, nbytes))
        got = sha256_file(ap)
        if got != digest:
            die("%s hashes to %s, the manifest declares %s" % (rel, got, digest))
        lines.append("%s  %s\n" % (digest, rel))

    got_aggregate = hashlib.sha256("".join(sorted(lines)).encode("utf-8")).hexdigest()
    if got_aggregate != aggregate:
        die("MeepHash build inputs aggregate to %s, the manifest declares %s"
            % (got_aggregate, aggregate))

    return aggregate, len(files)


# ------------------------------------------------------------------------------------- main
def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    mode, lockdir = argv[1], argv[2]

    if mode == "contract":
        lock, ordered = check_contract(lockdir)
        print("lock schema           : %s" % lock["schema"])
        print("base commit           : %s" % lock["base_commit"])
        print("base tree             : %s" % lock["base_tree"])
        print("patches               : %d, order and bytes verified" % len(ordered))
        for order, name, digest, nbytes in ordered:
            print("  %d. %s  %s  %d bytes" % (order, name, digest[:16] + "...", nbytes))
        print("expected final tree   : %s" % lock["expected_final_tree"])
        print("SHA256SUMS            : exactly the intended files, all matching")
        return 0

    if mode == "emit":
        lock, ordered = check_contract(lockdir)
        print("LOCK_BASE_URL=%s" % lock["base_repository"])
        print("LOCK_BASE_COMMIT=%s" % lock["base_commit"])
        print("LOCK_BASE_TREE=%s" % lock["base_tree"])
        print("LOCK_BASE_TAG=%s" % lock.get("base_tag", ""))
        print("LOCK_FINAL_TREE=%s" % lock["expected_final_tree"])
        print("LOCK_FINAL_INV=%s" % lock["expected_source_inventory_digest"])
        print("LOCK_PATCH_COUNT=%d" % len(ordered))
        print("LOCK_CHECKPOINT_BLOB=%s" % lock.get("monero_checkpoint_blob", ""))
        # Ordered, newline-separated; names are validated as safe bare filenames above.
        print("LOCK_PATCH_NAMES='%s'" % "\n".join(n for _, n, _, _ in ordered))
        return 0

    if mode == "meepow":
        if len(argv) < 4:
            die("meepow mode needs <lock-dir> <repo-root>")
        aggregate, n = check_meepow(lockdir, argv[3])
        print("MeepHash build inputs : %d files, all present, regular and matching" % n)
        print("aggregate identity    : %s" % aggregate)
        return 0

    die("unknown mode: %s" % mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
