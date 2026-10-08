#!/usr/bin/env python3
"""Historical-bundle integrity: a sealed bundle, its sibling log archive, and that archive's
sidecar.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE. READ-ONLY BY CONSTRUCTION: this module opens files only
for reading, creates nothing, and extracts nothing.

THIS IS NOT A QUALIFICATION GATE AND HAS NO Q NUMBER.

In CADENCEQ v1 the authorised Q14 was sterile relocated verification. The implemented Q14 checked a
directory-name prefix plus some Gate-N facts instead, and then failed because it looked for the
daemon-log archive INSIDE the bundle when, like every prior gate's archive, it is a sibling of it.
Sterile relocation lives in qual_verify_v2 and is a qualification gate. Historical-bundle integrity
lives here, under its own name, and is a standing integrity check that no qualification numbering
may absorb.

THE SECOND CORRECTIVE AUDIT ADDED THREE, ALL REPRODUCED FIRST

  no seal / listed link / tar link member -- see the git history of this file.

THE THIRD CORRECTIVE AUDIT REPRODUCED THREE MORE (R3-7)

  fake seal            a FINAL_SEAL.json carrying nothing but {"note": "...",
                       "sha256sums_sha256": <correct digest>} PASSED. It declared no schema, no
                       finality, no inventory and no count, and no external pin was required, so a
                       JSON pointer at a checksum list was accepted as proof of sealing. Finality
                       is not inferable from a pointer.
  inspect_archive_members=false
                       a caller could switch off member inspection and still get passed=True with
                       archive_members=None. An unexamined archive is not an examined one; that
                       flag can no longer produce a pass.
  caller-expanded self_files
                       `self_files=("SHA256SUMS","FINAL_SEAL.json","planted.json")` hid an
                       unlisted planted file from the present-but-not-listed check. The exclusion
                       list is now a module constant and there is no parameter for it.

WHAT A PASS NOW REQUIRES

  * a FINAL_SEAL.json with a RECOGNISED schema and version, an EXPLICIT sealed/final status, the
    checksum-list digest it binds, and the file count and inventory it claims -- each agreeing
    with what is actually on disk;
  * EXTERNAL pins for the seal, the checksum list, the archive and the file count, supplied by
    the caller from outside the bundle;
  * every listed member present exactly once, every present file listed, all of them regular
    files resolving inside the bundle, with no traversal, absolute or case-colliding path, no
    symlink, hardlink, junction or reparse point, no device, and no bytecode;
  * exactly one sibling archive by exact name, an exact-grammar sidecar, and an archive whose
    members are all inspected and all of safe type with no link target;
  * a byte-for-byte identical bundle and parent directory before and after checking.
"""
import json
import os
import re
import sys
import tarfile

sys.dont_write_bytecode = True
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import evidence_envelope as _ENV

SCHEMA = "meepcoin-historical-integrity/1"
ARCHIVE_SUFFIX = "__daemon_logs.tar.gz"
SIDECAR_SUFFIX = ".sha256"
SEAL_NAME = "FINAL_SEAL.json"
SUMS_NAME = "SHA256SUMS"
# IMMUTABLE. Files a bundle's own checksum list cannot contain, by the self-reference argument the
# evidence envelope documents. There is deliberately NO parameter for this: R3-7 expanded it.
SELF_FILES = (SUMS_NAME, SEAL_NAME)
DEFAULT_SELF_FILES = SELF_FILES                       # kept as the historical name
# A seal must say what it is. A JSON object that merely points at a checksum list is not a seal.
BUNDLE_SEAL_SCHEMAS = ("meepcoin-sealed-bundle/1",)
REQUIRED_EXTERNAL_PINS = ("seal_sha256", "sums_sha256", "archive_sha256", "file_count")
# EXACT sidecar grammar, matched against the WHOLE line. The policy is stated rather than merely
# claimed: exactly 64 LOWERCASE hex characters, exactly TWO spaces, then the archive basename with
# no leading asterisk and no trailing whitespace. R4-14 reproduced one space, a leading asterisk,
# trailing spaces and a tab separator all passing a check documented as exact.
SIDECAR_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([^\s*][^\s]*)$")
SIDECAR_GRAMMAR = ("exactly one line: 64 lowercase hex characters, exactly two spaces, then the "
                   "archive basename. No leading '*', no tab, no extra or trailing whitespace, "
                   "and no second line.")


def sha256_file(path):
    return _ENV.sha256_file(path)


def file_kind(path):
    """regular / directory / symlink / reparse_point / hardlinked / other / absent.

    Shared with the envelope module on purpose: one implementation, so a junction cannot be a
    link in one checker and a directory in the other."""
    return _ENV.file_kind(path)


def walk_relpaths(root):
    return _ENV.walk_relpaths(root)


def walk_typed(root):
    return _ENV.walk_typed(root)


def typed_inventory(root):
    return _ENV.typed_inventory(root)


def parse_sums(path):
    """Parse `<digest>  [kind]  <relpath>` lines. Returns (mapping, malformed_lines)."""
    out, bad = {}, []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            parts = [p for p in line.split("  ") if p != ""]
            if len(parts) < 2:
                bad.append(line[:120])
                continue
            digest, rel = parts[0].strip(), parts[-1].strip().lstrip("*")
            if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
                bad.append(line[:120])
                continue
            out.setdefault(rel, []).append(digest.lower())
    return out, bad


def unsafe_relpath(rel):
    """Why a bundle-relative path may not be listed or present, or None when it is safe."""
    if not isinstance(rel, str) or rel == "":
        return "empty path"
    if "\\" in rel:
        return "backslash separator in %r" % rel
    if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
        return "absolute path %r" % rel
    parts = rel.split("/")
    if any(p == "" for p in parts):
        return "empty path segment in %r" % rel
    if any(p in ("..", ".") for p in parts):
        return "traversal or dot segment in %r" % rel
    return None


def case_collisions(relpaths):
    return _ENV.case_collisions(relpaths)


def contained_in(root, path):
    return _ENV.contained_in(root, path)


# Tar member types that are never acceptable in a log archive. A symlink or hardlink member is a
# pointer, and a pointer's meaning depends on where it is unpacked; a device or FIFO member has no
# business in a log archive at all. There is no declared safe-link policy, so all of them fail.
_SAFE_TAR_TYPES = (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)


def unsafe_member(ti):
    """Why a tar member is unsafe, or None. Takes a TarInfo: the NAME is not the whole story --
    a symlink member's linkname is where the danger lives."""
    name = ti.name if hasattr(ti, "name") else str(ti)
    why = unsafe_relpath(name.rstrip("/") or name)
    if why:
        return "%s (member)" % why
    if hasattr(ti, "type"):
        if ti.type not in _SAFE_TAR_TYPES:
            kind = {tarfile.SYMTYPE: "symlink", tarfile.LNKTYPE: "hardlink",
                    tarfile.CHRTYPE: "character device", tarfile.BLKTYPE: "block device",
                    tarfile.FIFOTYPE: "fifo"}.get(ti.type, "type %r" % ti.type)
            return ("member %r is a %s; only regular files and directories are accepted, because "
                    "a pointer's meaning depends on where it is unpacked" % (name, kind))
        link = getattr(ti, "linkname", "") or ""
        if link:
            return "member %r carries a link target %r" % (name, link)
    return None


def seal_failures(seal_path, sums_path, on_disk, on_disk_dirs, typed_digest,
                  expected):
    """Everything wrong with a FINAL_SEAL.json. Returns (seal_or_None, failures)."""
    fails = []
    if file_kind(seal_path) != "regular":
        return None, ["no regular %s: an unsealed directory is not a sealed bundle, and the "
                      "first version of this checker passed one" % SEAL_NAME]
    try:
        seal = json.load(open(seal_path, encoding="utf-8"))
    except Exception as e:
        return None, ["%s is unreadable: %s: %s" % (SEAL_NAME, type(e).__name__, e)]
    if not isinstance(seal, dict):
        return None, ["%s is not an object" % SEAL_NAME]

    if seal.get("schema") not in BUNDLE_SEAL_SCHEMAS:
        fails.append("%s declares schema %r, which is not one of the recognised sealed-bundle "
                     "schemas %s; a JSON object that merely points at a checksum list is not a "
                     "seal" % (SEAL_NAME, seal.get("schema"), list(BUNDLE_SEAL_SCHEMAS)))
    if seal.get("sealed") is not True and seal.get("final") is not True:
        fails.append("%s declares no explicit finality (sealed/final is not true); finality is "
                     "never inferred from the presence of a checksum-list pointer" % SEAL_NAME)

    declared = seal.get("sha256sums_sha256") or seal.get("sums_sha256")
    if declared is None:
        fails.append("%s declares no digest for %s, so it binds nothing" % (SEAL_NAME, SUMS_NAME))
    elif file_kind(sums_path) != "regular":
        fails.append("%s names a checksum list that is not a regular file" % SEAL_NAME)
    elif declared != sha256_file(sums_path):
        fails.append("%s names %s digest %s but the file hashes to %s"
                     % (SEAL_NAME, SUMS_NAME, str(declared)[:16], sha256_file(sums_path)[:16]))

    count = seal.get("file_count")
    if not isinstance(count, int) or isinstance(count, bool):
        fails.append("%s declares no integer file_count, so it binds no inventory size"
                     % SEAL_NAME)
    elif count != len(on_disk) + len(SELF_FILES):
        fails.append("%s declares %d files but the bundle holds %d"
                     % (SEAL_NAME, count, len(on_disk) + len(SELF_FILES)))

    inv = seal.get("inventory")
    if not isinstance(inv, list):
        fails.append("%s declares no inventory list, so a renamed or replaced member could not "
                     "be seen" % SEAL_NAME)
    else:
        if sorted(inv) != sorted(on_disk):
            fails.append("%s declares an inventory that is not the bundle's non-self files: "
                         "extra=%s missing=%s"
                         % (SEAL_NAME, sorted(set(inv) - set(on_disk))[:6],
                            sorted(set(on_disk) - set(inv))[:6]))
    # R4-11: a file-only inventory cannot see an unlisted EMPTY directory. The seal must bind the
    # complete typed object graph, directories included.
    dd = seal.get("directories")
    if not isinstance(dd, list):
        fails.append("%s declares no directory inventory, so an empty directory added to this "
                     "bundle would be invisible" % SEAL_NAME)
    elif sorted(dd) != sorted(on_disk_dirs):
        fails.append("%s declares directories that are not the bundle's: extra=%s missing=%s"
                     % (SEAL_NAME, sorted(set(dd) - set(on_disk_dirs))[:6],
                        sorted(set(on_disk_dirs) - set(dd))[:6]))
    dc = seal.get("directory_count")
    if not isinstance(dc, int) or isinstance(dc, bool) or dc != len(on_disk_dirs):
        fails.append("%s declares directory_count %r but the bundle holds %d directories"
                     % (SEAL_NAME, dc, len(on_disk_dirs)))
    ti = seal.get("typed_inventory_sha256")
    if ti is not None and ti != typed_digest:
        fails.append("%s declares typed inventory %s but the bundle hashes to %s"
                     % (SEAL_NAME, str(ti)[:16], typed_digest[:16]))
    if expected and expected.get("seal_sha256") \
            and sha256_file(seal_path) != expected["seal_sha256"]:
        fails.append("%s digest %s != expected %s"
                     % (SEAL_NAME, sha256_file(seal_path)[:16], expected["seal_sha256"][:16]))
    return seal, fails


def verify_bundle(bundle_dir, expected=None, archive_dir=None, inspect_archive_members=True,
                  require_external_pins=True):
    """Verify a sealed historical bundle plus its sibling archive and sidecar.

    `expected` MUST pin seal_sha256, sums_sha256, archive_sha256 and file_count from outside the
    bundle. Returns a result dict with a `failures` list. Never writes; never extracts."""
    fails, notes = [], {}
    expected = dict(expected or {})
    bundle_dir = os.path.abspath(bundle_dir)
    if file_kind(bundle_dir) != "directory":
        return {"schema": SCHEMA, "bundle": bundle_dir, "passed": False,
                "failures": ["%r is %s, not a plain directory"
                             % (bundle_dir, file_kind(bundle_dir))], "notes": notes}

    name = os.path.basename(bundle_dir.rstrip(os.sep))
    parent = archive_dir or os.path.dirname(bundle_dir)

    # ---- zero mutations: the object graph before and after this function runs ----
    before = {"bundle": typed_inventory(bundle_dir),
              "parent": sorted(os.listdir(parent))}
    notes["diagnostic_only"] = not require_external_pins

    if not inspect_archive_members:
        fails.append("inspect_archive_members=False cannot produce a pass: an archive whose "
                     "members were never enumerated has not been checked, and reporting that as "
                     "integrity is exactly the substitution this module exists to prevent")
    diagnostic_only = not require_external_pins
    if diagnostic_only:
        # R4-10: this was a public flag that produced passed=True with no pins at all. A no-pin
        # mode is a DIAGNOSTIC and always fails; it can never become a passing route.
        fails.append("require_external_pins=False is a DIAGNOSTIC mode: it inspects the bundle "
                     "but can never pass, because a bundle cannot vouch for itself and every "
                     "digest inside it is as editable as the files it describes")
    else:
        missing_pins = [p for p in REQUIRED_EXTERNAL_PINS if not expected.get(p)]
        if missing_pins:
            fails.append("no external pin supplied for %s; a bundle cannot vouch for itself"
                         % missing_pins)

    # ---- 1. the checksum list, and EVERY member it names ----
    sums_path = os.path.join(bundle_dir, SUMS_NAME)
    if file_kind(sums_path) != "regular":
        fails.append("no regular %s in %r" % (SUMS_NAME, bundle_dir))
        return {"schema": SCHEMA, "bundle": bundle_dir, "passed": False, "failures": fails,
                "notes": notes}

    graph = walk_typed(bundle_dir)
    unsafe_objects = sorted((r, k) for r, k in graph.items() if k not in _ENV.SAFE_KINDS)
    if unsafe_objects:
        fails.append("unrepresentable object(s) inside the bundle -- a link, hardlink, junction, "
                     "reparse point or device: %s" % unsafe_objects[:6])
    on_disk = [r for r, k in sorted(graph.items())
               if k == "regular" and r not in SELF_FILES]

    seal_path = os.path.join(bundle_dir, SEAL_NAME)
    on_disk_dirs = sorted(r for r, k in graph.items() if k == "directory")
    typed_digest = _ENV.inventory_digest(
        {r: v for r, v in typed_inventory(bundle_dir).items() if r not in SELF_FILES})
    seal, seal_fails = seal_failures(seal_path, sums_path, on_disk, on_disk_dirs, typed_digest,
                                     expected)
    fails.extend(seal_fails)
    if seal is not None:
        notes["seal_sha256"] = sha256_file(seal_path)

    notes["sums_sha256"] = sha256_file(sums_path)
    if expected.get("sums_sha256") and notes["sums_sha256"] != expected["sums_sha256"]:
        fails.append("%s digest %s != expected %s"
                     % (SUMS_NAME, notes["sums_sha256"][:16], expected["sums_sha256"][:16]))

    listed, malformed = parse_sums(sums_path)
    for m in malformed:
        fails.append("malformed %s line: %r" % (SUMS_NAME, m))
    dups = sorted(k for k, v in listed.items() if len(v) > 1)
    if dups:
        fails.append("%s lists these paths more than once: %s" % (SUMS_NAME, dups))

    notes["file_count"] = sum(1 for k in graph.values() if k == "regular")
    notes["directory_count"] = sum(1 for k in graph.values() if k == "directory")
    if expected.get("file_count") is not None and notes["file_count"] != expected["file_count"]:
        fails.append("bundle holds %d files, expected %d"
                     % (notes["file_count"], expected["file_count"]))

    unlisted = sorted(set(on_disk) - set(listed))
    absent = sorted(set(listed) - set(on_disk))
    if unlisted:
        fails.append("files present but not listed (post-seal insertion): %s" % unlisted[:8])
    if absent:
        fails.append("files listed but absent: %s" % absent[:8])

    for rel in sorted(set(on_disk) | set(listed)):
        why = unsafe_relpath(rel)
        if why:
            fails.append("unsafe bundle path: %s" % why)
    coll = case_collisions(list(graph))
    if coll:
        fails.append("case-colliding bundle paths: %s" % coll)

    verified = 0
    for rel in sorted(set(on_disk) & set(listed)):
        full = os.path.join(bundle_dir, rel.replace("/", os.sep))
        kind = file_kind(full)
        if kind != "regular":
            fails.append("listed member %r is a %s, not a regular file; a pointer's identity is "
                         "its target and it may resolve outside the bundle" % (rel, kind))
            continue
        if not contained_in(bundle_dir, full):
            fails.append("listed member %r resolves outside the bundle" % rel)
            continue
        if sha256_file(full) != listed[rel][0]:
            fails.append("member %r does not match its listed digest" % rel)
        else:
            verified += 1
    notes["members_verified"] = verified
    notes["members_listed"] = len(listed)

    stray = [r for r in graph if r.endswith(".pyc") or "__pycache__" in r]
    if stray:
        fails.append("bytecode inside the sealed bundle: %s" % stray[:5])

    # ---- 2. the sibling archive, by EXACT name ----
    archive_name = name + ARCHIVE_SUFFIX
    archive_path = os.path.join(parent, archive_name)
    decoys = [r for r in graph if os.path.basename(r) == archive_name]
    if decoys:
        fails.append("decoy archive(s) named %r found INSIDE the bundle at %s; the archive is a "
                     "SIBLING of the bundle directory and an inside copy never satisfies it"
                     % (archive_name, decoys))
    siblings = [f for f in sorted(os.listdir(parent))
                if f.startswith(name + "__") and f.endswith(".tar.gz")]
    if len(siblings) > 1:
        fails.append("more than one candidate sibling archive: %s" % siblings)
    if file_kind(archive_path) != "regular":
        fails.append("no regular sibling archive %r beside the bundle" % archive_name)
        return _finish(bundle_dir, fails, notes, before, parent)
    notes["archive"] = archive_name
    notes["archive_sha256"] = sha256_file(archive_path)
    if expected.get("archive_sha256") and notes["archive_sha256"] != expected["archive_sha256"]:
        fails.append("archive digest %s != expected %s"
                     % (notes["archive_sha256"][:16], expected["archive_sha256"][:16]))

    # ---- 3. the sidecar, by EXACT name and EXACT grammar ----
    sidecar_path = archive_path + SIDECAR_SUFFIX
    if file_kind(sidecar_path) != "regular":
        fails.append("no regular digest sidecar %r" % (archive_name + SIDECAR_SUFFIX))
    else:
        raw_text = ""
        try:
            raw_text = open(sidecar_path, encoding="utf-8").read()
        except Exception as e:
            fails.append("sidecar unreadable: %s: %s" % (type(e).__name__, e))
        notes["sidecar_grammar"] = SIDECAR_GRAMMAR
        lines = raw_text.split("\n")
        if len(lines) != 2 or lines[1] != "":
            fails.append("sidecar must be exactly one line terminated by a single newline; "
                         "grammar: %s" % SIDECAR_GRAMMAR)
        else:
            m = SIDECAR_LINE_RE.match(lines[0])
            if not m:
                fails.append("sidecar line %r does not match the exact grammar: %s"
                             % (lines[0][:80], SIDECAR_GRAMMAR))
            else:
                if m.group(1) != notes["archive_sha256"]:
                    fails.append("sidecar digest %s does not match the archive (%s)"
                                 % (m.group(1)[:16], notes["archive_sha256"][:16]))
                if m.group(2) != archive_name:
                    fails.append("sidecar names %r, not %r" % (m.group(2), archive_name))

    # ---- 4. safe member inventory inside the archive (read-only, never extracted) ----
    if inspect_archive_members:
        try:
            with tarfile.open(archive_path, "r:gz") as tf:
                members = tf.getmembers()
        except Exception as e:
            members = []
            fails.append("archive unreadable: %s: %s" % (type(e).__name__, e))
        notes["archive_members"] = len(members)
        seen = {}
        for ti in members:
            why = unsafe_member(ti)
            if why:
                fails.append("unsafe archive member: %s" % why)
            n = ti.name
            k = n.casefold()
            if k in seen and seen[k] != n:
                fails.append("case-colliding archive members: %r and %r" % (seen[k], n))
            elif k in seen:
                fails.append("duplicate archive member %r" % n)
            seen[k] = n

    return _finish(bundle_dir, fails, notes, before, parent)


def _finish(bundle_dir, fails, notes, before, parent):
    after = {"bundle": typed_inventory(bundle_dir), "parent": sorted(os.listdir(parent))}
    if after != before:
        fails.append("this checker changed something: bundle_diff=%s parent_before=%d "
                     "parent_after=%d"
                     % (_ENV.inventory_diff(before["bundle"], after["bundle"]),
                        len(before["parent"]), len(after["parent"])))
    notes["mutations_during_checking"] = 0 if after == before else "SEE FAILURES"
    return {"schema": SCHEMA, "bundle": bundle_dir, "passed": not fails, "failures": fails,
            "notes": notes, "diagnostic_only": bool(notes.get("diagnostic_only")),
            "read_only": "this checker opened files for reading only and extracted nothing; the "
                         "bundle's typed inventory and its parent listing were compared before "
                         "and after"}


def main(argv):
    arg = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in argv if "=" in a}
    pos = [a for a in argv if not a.startswith("--")]
    if not pos:
        print(__doc__)
        return 2
    exp = {}
    for k, flag in (("sums_sha256", "--sums"), ("archive_sha256", "--archive"),
                    ("seal_sha256", "--seal"), ("file_count", "--files")):
        if flag in arg:
            exp[k] = int(arg[flag]) if k == "file_count" else arg[flag]
    res = verify_bundle(pos[0], expected=exp or None)
    print("bundle:", res["bundle"])
    for k, v in sorted(res["notes"].items()):
        print("  %-24s %s" % (k, v))
    for f in res["failures"]:
        print("  !", f)
    print("HISTORICAL INTEGRITY:", "PASS" if res["passed"] else "FAIL")
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
