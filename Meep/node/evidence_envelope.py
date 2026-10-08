#!/usr/bin/env python3
"""The immutable outer evidence envelope: build, seal, publish, verify, attest.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE. Nothing here launches, measures or judges an experiment.

WHAT THE FIRST CORRECTIVE AUDIT REPRODUCED, AND WHAT CHANGED

  forged role metadata     ENVELOPE_SEAL.json is excluded from the checksum list, so its `roles`
                           block was attacker-editable. Roles are now cross-checked against the
                           real inventory in BOTH directions, and expect_spec_sha256 is compared
                           against the ACTUAL bound bytes.
  reserved-name hijack     a role could bind to ENVELOPE_SEAL.json. Reserved names are refused
                           case-insensitively at bind time.
  dishonest finality       the state file said final:true before the seal existed. There is now an
                           explicit SEALING state; the state file never claims finality.
  attestation aliasing     lexical containment was defeated by a symlink. Containment is now
                           realpath/normcase/commonpath on the destination's parent.

WHAT THE THIRD CORRECTIVE AUDIT REPRODUCED, AND WHAT CHANGED

  R3-3  roles could SHRINK. `need = require_roles or seal.required_roles or REQUIRED_ROLES` let a
        caller REPLACE the floor, and EnvelopeBuilder accepted a shortened required_roles, so an
        envelope with no qualification_spec and no source_inventory sealed, verified clean and
        passed G17. Effective roles are now the UNION of the hard-coded authoritative minimum, the
        verified seal-declared set, the verified authorized-spec set and any caller extras. A
        caller may ADD and can never subtract. AUTHORIZED_REQUIRED_ROLES is now USED, not merely
        defined.
  R3-4  the inventory was FILES ONLY. An unlisted empty directory could be added after sealing, a
        directory present at sealing could be deleted or renamed, and verification stayed clean;
        the relocation inventory could not see any of it either. The canonical inventory is now
        TYPED and covers directories, empty ones included.
  R3-9a a Windows directory junction (IO_REPARSE_TAG_MOUNT_POINT) is NOT a symlink to
        os.path.islink on native Windows Python. file_kind said "directory", has_link_anywhere
        returned [], the walk descended THROUGH it, and the builder bound a tree whose members
        physically live outside the envelope. WSL Python refused the very same object. Reparse
        points are now detected by st_reparse_tag / FILE_ATTRIBUTE_REPARSE_POINT, the walk never
        descends into one, and anything the platform cannot classify fails closed.
  R3-12 inner_seal_relpath="../OUTSIDE_SEAL" hashed a file OUTSIDE the collection, and the copied
        collection then contained no seal at all; separately, forging the two mutually consistent
        metadata copies of the inner-seal digest verified clean while the real nested seal
        differed. The inner seal must now be a safe relative path contained beneath the collection,
        must be a checksum-listed regular file, is RE-HASHED from the copy, and its schema,
        finality and checksum-list binding are validated.
  R3-13 EnvelopeBuilder accepted a pre-existing empty directory as a staging root, and
        write_attestation published a CANONICAL attestation from an arbitrary caller dictionary
        with no authentic G17 result behind it. The staging root is now created exclusively, and
        canonical publication re-derives every claim against external pins.

STATE MACHINE, FAIL CLOSED

    STAGING -> COLLECTION_BOUND -> TRACE_BOUND -> CHECKED -> SEALING -> (seal written)

ENVELOPE_STATE.json is written at every transition and NEVER says final. Its last value is SEALING.

THE SELF-FILE RULE

ENVELOPE_SHA256SUMS and ENVELOPE_SEAL.json are the only files excluded from the checksum
inventory, because each would otherwise have to contain its own digest. Because the seal is
excluded it CANNOT authenticate itself: a decision-gate verification must pin the exact outer-seal
digest from outside.
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import time

sys.dont_write_bytecode = True

SCHEMA = "meepcoin-evidence-envelope/1"
STATE_FILE = "ENVELOPE_STATE.json"
SUMS_FILE = "ENVELOPE_SHA256SUMS"
SEAL_FILE = "ENVELOPE_SEAL.json"
SELF_FILES = (SUMS_FILE, SEAL_FILE)
# Reserved case-insensitively. No role may bind to, or collide with, any of these.
RESERVED_NAMES = frozenset(n.casefold() for n in (STATE_FILE, SUMS_FILE, SEAL_FILE))
RESERVED_SUFFIXES = (".partial", ".tmp", ".swp")

STAGING = "STAGING"
COLLECTION_BOUND = "COLLECTION_BOUND"
TRACE_BOUND = "TRACE_BOUND"
CHECKED = "CHECKED"
SEALING = "SEALING"
ORDER = (STAGING, COLLECTION_BOUND, TRACE_BOUND, CHECKED, SEALING)

TRACE_COMPLETE = "COMPLETE"
TRACE_INCOMPLETE = "INCOMPLETE"
TRACE_STATUSES = (TRACE_COMPLETE, TRACE_INCOMPLETE)

ROLES = ("inner_collection", "environment_trace", "pre_seal_gate_results", "driver_log",
         "daemon_log_archive", "daemon_log_sidecar", "launcher", "tracer",
         "qualification_checker", "finalizer", "outer_verifier", "qualification_spec",
         "preflight_lead_in", "preflight_pre_launch", "source_inventory")
# THE AUTHORITATIVE MINIMUM for any envelope. It is a floor, never a target: see
# effective_required_roles, which only ever unions.
REQUIRED_ROLES = ("inner_collection", "environment_trace", "pre_seal_gate_results",
                  "qualification_spec", "source_inventory")
# What an AUTHORIZED run must bind: every artefact the report claims. Used, not merely defined --
# verify_envelope(authorized_run=True) folds it into the effective set.
AUTHORIZED_REQUIRED_ROLES = ROLES

KIND_FILE = "file"
KIND_DIR = "directory"

# Object kinds the envelope can represent safely. Anything else fails closed.
SAFE_KINDS = ("regular", "directory")

# An inner (collection) seal must satisfy this contract before the collection counts as sealed.
INNER_SEAL_SUMS_DEFAULT = "SHA256SUMS"


class EnvelopeError(RuntimeError):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ object typing
def _reparse_tag(st):
    """Non-zero when the OS says this entry is a reparse point (junction, mount point, appexec
    link, cloud placeholder ...). Zero on platforms that have no such concept."""
    tag = getattr(st, "st_reparse_tag", 0) or 0
    if tag:
        return tag
    attrs = getattr(st, "st_file_attributes", 0) or 0
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return -1                                     # a reparse point whose tag we cannot read
    return 0


def file_kind(path):
    """regular / directory / symlink / reparse_point / hardlinked / other / absent.

    TYPE is part of identity. os.path.islink alone is NOT reparse detection: on native Windows
    Python a directory junction is islink()==False and isdir()==True, which is precisely how R3-9a
    got bytes from outside an envelope hashed as though they were inside it."""
    try:
        st = os.lstat(path)
    except (OSError, TypeError, ValueError):
        return "absent"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if _reparse_tag(st):
        return "reparse_point"
    if stat.S_ISDIR(st.st_mode):
        return "directory"
    if stat.S_ISREG(st.st_mode):
        if getattr(st, "st_nlink", 1) and st.st_nlink > 1:
            # Two names for one inode: which name is "the" object is ambiguous, and ambiguity
            # fails closed rather than being resolved silently.
            return "hardlinked"
        return "regular"
    return "other"


def walk_typed(root, _rel="", _out=None):
    """{relpath: kind} for EVERY object beneath root, directories included, NEVER descending into
    a symlink or a reparse point. `root` itself is not listed."""
    out = {} if _out is None else _out
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError as e:                              # pragma: no cover - unreadable directory
        out[_rel.rstrip("/") or "."] = "unreadable:%s" % type(e).__name__
        return out
    for e in entries:
        rel = (_rel + e.name) if not _rel else _rel + e.name
        kind = file_kind(e.path)
        out[rel] = kind
        if kind == "directory":
            walk_typed(e.path, rel + "/", out)
    return out


def walk_relpaths(root, follow=False):
    """Regular files only, sorted. The checksum list is a list of FILES; walk_typed is the
    complete object graph."""
    return sorted(r for r, k in walk_typed(root).items() if k == "regular")


def walk_dirs(root):
    """Every directory beneath root, empty ones included."""
    return sorted(r for r, k in walk_typed(root).items() if k == "directory")


def unsafe_objects(root):
    """[(relpath, kind)] for every object the envelope may not represent."""
    return sorted((r, k) for r, k in walk_typed(root).items() if k not in SAFE_KINDS)


def has_link_anywhere(root):
    """Every link, junction, reparse point or otherwise unclassifiable object under root.

    Kept under its original name because callers depend on it; it now catches strictly more."""
    return sorted(r for r, k in walk_typed(root).items() if k not in SAFE_KINDS)


def typed_inventory(root):
    """The canonical inventory: {relpath: (kind, size, sha256)}.

    Directories appear with size None and digest None, so an EMPTY directory is a first-class
    member. Unsafe objects appear with their kind so they can never be silently equal to a regular
    file with the same bytes."""
    out = {}
    for rel, kind in sorted(walk_typed(root).items()):
        full = os.path.join(root, rel.replace("/", os.sep))
        if kind == "regular":
            out[rel] = (kind, os.path.getsize(full), sha256_file(full))
        elif kind == "directory":
            out[rel] = (kind, None, None)
        elif kind == "symlink":
            try:
                out[rel] = (kind, None, "->" + os.readlink(full))
            except OSError:                           # pragma: no cover - platform dependent
                out[rel] = (kind, None, "->?")
        else:
            out[rel] = (kind, None, None)
    return out


def inventory_digest(inv):
    """A deterministic digest over a typed inventory, TYPE included."""
    h = hashlib.sha256()
    for rel in sorted(inv):
        kind, size, digest = inv[rel]
        h.update(("%s\x1f%s\x1f%s\x1f%s\x1e" % (rel, kind, size, digest)).encode("utf-8"))
    return h.hexdigest()


def inventory_diff(before, after):
    return {"added": sorted(set(after) - set(before)),
            "removed": sorted(set(before) - set(after)),
            "changed": sorted(k for k in (set(before) & set(after)) if before[k] != after[k])}


def sha256_tree(root):
    """Digest of a whole tree, DIRECTORIES INCLUDED. An empty directory changes this value."""
    return inventory_digest(typed_inventory(root))


# ------------------------------------------------------------------ path safety
def unsafe_relpath_reason(rel):
    """Why a relative path may not be bound or listed, or None when it is safe."""
    if not isinstance(rel, str) or rel == "":
        return "empty path"
    if "\x00" in rel:
        return "NUL character in %r" % rel
    if "\\" in rel:
        return "backslash separator in %r" % rel
    if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
        return "absolute path %r" % rel
    parts = rel.split("/")
    if any(p == "" for p in parts):
        return "empty path segment in %r" % rel
    if any(p == ".." for p in parts):
        return "parent traversal in %r" % rel
    if any(p == "." for p in parts):
        return "current-directory segment in %r" % rel
    if any(p.casefold() in RESERVED_NAMES for p in parts):
        return "reserved envelope name in %r" % rel
    if any(p.casefold().endswith(RESERVED_SUFFIXES) for p in parts):
        return "reserved temporary suffix in %r" % rel
    return None


def case_collisions(relpaths):
    seen, bad = {}, []
    for r in relpaths:
        k = r.casefold()
        if k in seen and seen[k] != r:
            bad.append((seen[k], r))
        else:
            seen.setdefault(k, r)
    return bad


def _norm(p):
    return os.path.normcase(os.path.realpath(os.path.abspath(p)))


def contained_in(root, path):
    """True only if `path` really resolves inside `root` -- realpath, normcase, commonpath."""
    r, p = _norm(root), _norm(path)
    try:
        return os.path.commonpath([r, p]) == r
    except ValueError:                                # different drives
        return False


def escapes_root(root, path):
    return not contained_in(root, path)


def _is_hex64(s):
    """EXACTLY 64 LOWERCASE hex characters (R5-17): the messages say lowercase, so does this."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


# ------------------------------------------------------------------ required roles
def effective_required_roles(seal_roles=None, spec_roles=None, caller_extra=None,
                             authorized_run=False):
    """The UNION of every floor that applies. A caller may ADD and can never subtract.

    R3-3 reproduced the opposite: `require_roles or seal.required_roles or REQUIRED_ROLES` let the
    first non-empty list REPLACE the rest."""
    need = set(REQUIRED_ROLES)
    if authorized_run:
        need |= set(AUTHORIZED_REQUIRED_ROLES)
    for extra in (seal_roles, spec_roles, caller_extra):
        if extra:
            need |= {r for r in extra if isinstance(r, str)}
    return sorted(need)


# ------------------------------------------------------------------ inner seal
INNER_SEAL_SCHEMAS = ("meepcoin-inner-collection/1",)
INNER_SEAL_ALLOWED_KEYS = frozenset((
    "schema", "sealed", "final", "sums_file", "sha256sums_sha256", "inventory", "file_count",
    "directories", "directory_count", "note",
))


def parse_checksum_list(path):
    """(mapping, failures). Each line is `<64 hex><2 spaces>[kind<2 spaces>]<relpath>`.

    A checksum list nobody parses is a checksum list nobody checked. R4-12 reproduced an EMPTY
    inner list accepted for a collection full of files."""
    listed, fails = {}, []
    try:
        raw = open(path, encoding="utf-8").read()
    except Exception as e:
        return {}, ["the checksum list is unreadable: %s: %s" % (type(e).__name__, e)]
    for n, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            if line:
                fails.append("line %d is blank but not empty" % n)
            continue
        parts = line.split("  ")
        if len(parts) not in (2, 3):
            fails.append("malformed checksum line %d: %r" % (n, line[:70]))
            continue
        digest, rel = parts[0], parts[-1]
        if not _is_hex64(digest):
            fails.append("line %d does not start with 64 lowercase hex characters" % n)
            continue
        why = unsafe_relpath_reason(rel)
        if why:
            fails.append("line %d lists an unsafe path: %s" % (n, why))
            continue
        if rel in listed:
            fails.append("path %r is listed more than once" % rel)
            continue
        listed[rel] = digest
    coll = case_collisions(list(listed))
    if coll:
        fails.append("case-colliding listed paths: %s" % coll)
    return listed, fails


def inner_seal_failures(collection_root, inner_seal_relpath, expect_digest=None):
    """Locate, type-check, hash and FULLY VERIFY the inner collection. Returns (digest, failures).

    R4-12 reproduced two holes at once: an invented schema with an EMPTY checksum list was
    accepted, and `sums_file: "../outside_sums"` hashed a file outside the collection. The seal is
    now a contract -- exact schema, explicit finality, a safe contained checksum list that is
    PARSED, every listed member opened and hashed, no unlisted object, and exact file and
    directory inventories and counts."""
    fails = []
    why = unsafe_relpath_reason(inner_seal_relpath) if isinstance(inner_seal_relpath, str) \
        else "inner_seal_relpath is not a string"
    if why:
        return None, ["the inner seal path is unsafe: %s" % why]
    full = os.path.join(collection_root, inner_seal_relpath.replace("/", os.sep))
    if not contained_in(collection_root, full):
        return None, ["the inner seal %r resolves outside the collection it claims to seal"
                      % inner_seal_relpath]
    kind = file_kind(full)
    if kind != "regular":
        return None, ["the inner seal %r is %s, not a regular file inside the collection"
                      % (inner_seal_relpath, kind)]
    digest = sha256_file(full)
    try:
        doc = json.load(open(full, encoding="utf-8"))
    except Exception as e:
        return digest, ["the inner seal is unreadable: %s: %s" % (type(e).__name__, e)]
    if not isinstance(doc, dict):
        return digest, ["the inner seal is not a JSON object"]

    unknown = sorted(set(doc) - INNER_SEAL_ALLOWED_KEYS)
    if unknown:
        fails.append("the inner seal carries unknown field(s) %s" % unknown)
    if doc.get("schema") not in INNER_SEAL_SCHEMAS:
        fails.append("the inner seal declares schema %r, which is not one of the supported inner "
                     "collection schemas %s; an invented schema is not a contract"
                     % (doc.get("schema"), list(INNER_SEAL_SCHEMAS)))
    if doc.get("sealed") is not True and doc.get("final") is not True:
        fails.append("the inner seal declares no finality (sealed/final is not true)")

    # ---- the checksum list: safe, contained, regular, and PARSED ----
    sums_name = doc.get("sums_file") or INNER_SEAL_SUMS_DEFAULT
    swhy = unsafe_relpath_reason(sums_name) if isinstance(sums_name, str) \
        else "sums_file is not a string"
    if swhy:
        fails.append("the inner seal's sums_file is unsafe: %s" % swhy)
        return digest, fails
    sp = os.path.join(collection_root, sums_name.replace("/", os.sep))
    if not contained_in(collection_root, sp):
        fails.append("the inner seal's sums_file %r resolves OUTSIDE the collection" % sums_name)
        return digest, fails
    if file_kind(sp) != "regular":
        fails.append("the inner seal names checksum list %r, which is %s, not a regular file "
                     "inside the collection" % (sums_name, file_kind(sp)))
        return digest, fails
    declared = doc.get("sha256sums_sha256") or doc.get("sums_sha256")
    if declared is None:
        fails.append("the inner seal names no checksum-list digest, so it binds no inventory")
    elif sha256_file(sp) != declared:
        fails.append("the inner seal names checksum-list digest %s but %r hashes to %s"
                     % (str(declared)[:16], sums_name, sha256_file(sp)[:16]))

    listed, lf = parse_checksum_list(sp)
    for f in lf:
        fails.append("inner checksum list: %s" % f)

    graph = walk_typed(collection_root)
    unsafe = sorted((r, k) for r, k in graph.items() if k not in SAFE_KINDS)
    if unsafe:
        fails.append("unrepresentable object(s) inside the collection: %s" % unsafe[:4])
    self_files = {inner_seal_relpath, sums_name}
    present = sorted(r for r, k in graph.items() if k == "regular" and r not in self_files)
    dirs = sorted(r for r, k in graph.items() if k == "directory")

    extra = sorted(set(present) - set(listed))
    missing = sorted(set(listed) - set(present))
    if extra:
        fails.append("collection files present but NOT listed: %s" % extra[:6])
    if missing:
        fails.append("collection files listed but absent: %s" % missing[:6])
    for rel in sorted(set(present) & set(listed)):
        f = os.path.join(collection_root, rel.replace("/", os.sep))
        if sha256_file(f) != listed[rel]:
            fails.append("collection member %r does not match its listed digest" % rel)

    inv = doc.get("inventory")
    if not isinstance(inv, list):
        fails.append("the inner seal declares no inventory list")
    elif sorted(inv) != present:
        fails.append("the inner seal's inventory is not the collection's non-self files: "
                     "extra=%s missing=%s" % (sorted(set(inv) - set(present))[:6],
                                              sorted(set(present) - set(inv))[:6]))
    fc = doc.get("file_count")
    if not isinstance(fc, int) or isinstance(fc, bool):
        fails.append("the inner seal declares no integer file_count")
    elif fc != len(present) + len(self_files):
        fails.append("the inner seal declares %d files but the collection holds %d"
                     % (fc, len(present) + len(self_files)))
    dd = doc.get("directories")
    if not isinstance(dd, list):
        fails.append("the inner seal declares no directory inventory, so an empty directory "
                     "added or removed inside the collection would be invisible")
    elif sorted(dd) != dirs:
        fails.append("the inner seal's directory inventory is not the collection's directories: "
                     "extra=%s missing=%s" % (sorted(set(dd) - set(dirs))[:6],
                                              sorted(set(dirs) - set(dd))[:6]))
    dc = doc.get("directory_count")
    if not isinstance(dc, int) or isinstance(dc, bool) or dc != len(dirs):
        fails.append("the inner seal declares directory_count %r but the collection holds %d"
                     % (dc, len(dirs)))

    if expect_digest is not None and digest != expect_digest:
        fails.append("the ACTUAL inner seal hashes to %s, not the %s claimed for it"
                     % (digest[:16], str(expect_digest)[:16]))
    return digest, fails


def inner_seal_document(collection_root, sums_relpath=INNER_SEAL_SUMS_DEFAULT,
                        seal_relpath="FINAL_SEAL.json"):
    """Build a seal document satisfying the contract above, for a collection whose checksum list
    already exists. Provided so a caller need not reimplement the shape."""
    graph = walk_typed(collection_root)
    self_files = {seal_relpath, sums_relpath}
    present = sorted(r for r, k in graph.items() if k == "regular" and r not in self_files)
    dirs = sorted(r for r, k in graph.items() if k == "directory")
    return {"schema": INNER_SEAL_SCHEMAS[0], "sealed": True, "sums_file": sums_relpath,
            "sha256sums_sha256": sha256_file(os.path.join(
                collection_root, sums_relpath.replace("/", os.sep))),
            "inventory": present, "file_count": len(present) + len(self_files),
            "directories": dirs, "directory_count": len(dirs)}


# ------------------------------------------------------------------ builder
class EnvelopeBuilder:
    """Stages an envelope and seals it. The staging root is created ATOMICALLY and EXCLUSIVELY."""

    def __init__(self, staging_dir, envelope_id, clock=time.time, required_roles=REQUIRED_ROLES):
        self.dir = os.path.abspath(staging_dir)
        # Exclusive, atomic, no check-then-create window. An EXISTING path is refused whatever it
        # is -- including an empty directory, which R3-13 showed was accepted.
        try:
            os.mkdir(self.dir)
        except FileExistsError:
            raise EnvelopeError(
                "refusing to stage into the existing path %r. A staging root must be created by "
                "this builder and by nothing else; an existing directory -- empty or not -- may "
                "already be observed, may be a link or a junction, and cannot be proved to have "
                "been ours" % self.dir)
        except OSError as e:
            raise EnvelopeError("could not create the staging root %r: %s: %s"
                                % (self.dir, type(e).__name__, e))
        if file_kind(self.dir) != "directory":        # pragma: no cover - defensive
            raise EnvelopeError("the staging root %r is not a plain directory" % self.dir)
        self.envelope_id = envelope_id
        self.clock = clock
        # A caller may EXTEND the floor and can never shrink it.
        self.requested_roles = tuple(required_roles or ())
        self.required_roles = tuple(effective_required_roles(caller_extra=required_roles))
        self.state = STAGING
        self.published = False
        self.sealed = False
        self.entries = {}
        self.inner_seal_digest = None
        self.inner_seal_relpath = None
        self.trace_status = None
        self._write_state()

    # ---- state ----
    def _write_state(self, note=None):
        doc = {"schema": SCHEMA, "envelope_id": self.envelope_id, "state": self.state,
               # NEVER final. The seal is the only finality marker, and it cannot list itself.
               "final": False,
               "finality_marker": SEAL_FILE,
               "incomplete_unless_seal_present": True,
               "roles_bound": sorted(self.entries),
               "trace_status": self.trace_status,
               "note": note,
               "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock()))}
        self._atomic_json(os.path.join(self.dir, STATE_FILE), doc)

    def _advance(self, target, note=None):
        if ORDER.index(target) != ORDER.index(self.state) + 1:
            raise EnvelopeError("cannot go from %s to %s; the order is %s"
                                % (self.state, target, " -> ".join(ORDER)))
        self.state = target
        self._write_state(note)

    @staticmethod
    def _atomic_json(path, doc):
        tmp = path + ".partial"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:                          # pragma: no cover - platform dependent
                pass
        os.replace(tmp, path)

    # ---- binding ----
    def _stage(self, role, src, kind, relpath=None, extra=None, is_dir=False):
        if role not in ROLES:
            raise EnvelopeError("unknown role %r" % role)
        if role in self.entries:
            raise EnvelopeError("role %r is already bound to %r; a logical role may appear once"
                                % (role, self.entries[role]["relpath"]))
        rel = relpath if relpath is not None else os.path.basename(src.rstrip("/\\"))
        why = unsafe_relpath_reason(rel)
        if why:
            raise EnvelopeError("refusing to bind %s: %s" % (role, why))
        clash = [r for r, e in self.entries.items() if e["relpath"].casefold() == rel.casefold()]
        if clash:
            raise EnvelopeError("relpath %r collides (case-insensitively) with role %r"
                                % (rel, clash[0]))

        src_abs = os.path.abspath(src)
        src_kind = file_kind(src_abs)
        if src_kind not in SAFE_KINDS:
            raise EnvelopeError("refusing to bind %s: source %r is %s; only a regular file or a "
                                "plain directory can be represented in an envelope"
                                % (role, rel, src_kind))
        if is_dir:
            bad = unsafe_objects(src_abs)
            if bad:
                raise EnvelopeError("refusing to bind %s: source tree contains unrepresentable "
                                    "object(s) %s" % (role, bad[:4]))

        dst = os.path.join(self.dir, rel.replace("/", os.sep))
        if not contained_in(self.dir, os.path.dirname(dst) or self.dir):
            raise EnvelopeError("refusing to bind %s: destination escapes the envelope" % role)
        os.makedirs(os.path.dirname(dst) or self.dir, exist_ok=True)
        if os.path.lexists(dst):
            raise EnvelopeError("refusing to overwrite %r inside the envelope" % rel)

        if is_dir:
            shutil.copytree(src_abs, dst, symlinks=True)
            leftovers = unsafe_objects(dst)
            if leftovers:
                raise EnvelopeError("refusing %s: unrepresentable object(s) survived the copy: %s"
                                    % (role, leftovers[:4]))
            digest = sha256_tree(dst)
            size = sum(os.path.getsize(os.path.join(dst, r.replace("/", os.sep)))
                       for r in walk_relpaths(dst))
        else:
            shutil.copyfile(src_abs, dst, follow_symlinks=False)
            if file_kind(dst) != "regular":
                raise EnvelopeError("refusing %s: the copy is %s, not a regular file"
                                    % (role, file_kind(dst)))
            digest, size = sha256_file(dst), os.path.getsize(dst)

        if not contained_in(self.dir, dst):
            raise EnvelopeError("refusing %s: %r resolves outside the envelope" % (role, rel))

        self.entries[role] = {"role": role, "relpath": rel, "kind": kind, "size": size,
                              "sha256": digest, "is_dir": bool(is_dir), "extra": extra or {}}
        return self.entries[role]

    def bind_collection(self, inner_dir, inner_seal_relpath="FINAL_SEAL.json", relpath=None):
        """Bind the sealed inner collection.

        `inner_seal_relpath` must be a SAFE RELATIVE path contained beneath the collection: R3-12
        reproduced "../OUTSIDE_SEAL", which hashed a file outside the collection while the copy
        contained no seal at all."""
        if self.state != STAGING:
            raise EnvelopeError("collection must be bound first, from %s" % STAGING)
        why = unsafe_relpath_reason(inner_seal_relpath) \
            if isinstance(inner_seal_relpath, str) else "inner_seal_relpath is not a string"
        if why:
            raise EnvelopeError("refusing to bind the collection: the inner seal path is unsafe: "
                                "%s" % why)
        seal = os.path.join(inner_dir, inner_seal_relpath.replace("/", os.sep))
        if not contained_in(os.path.abspath(inner_dir), seal):
            raise EnvelopeError("refusing to bind the collection: the inner seal %r resolves "
                                "outside %r" % (inner_seal_relpath, inner_dir))
        if file_kind(seal) != "regular":
            raise EnvelopeError("inner bundle %r has no regular %s: an unsealed collection may "
                                "not be bound" % (inner_dir, inner_seal_relpath))
        e = self._stage("inner_collection", inner_dir, KIND_DIR,
                        relpath=relpath or "collection", is_dir=True,
                        extra={"inner_seal_relpath": inner_seal_relpath})
        # Hash and validate the seal IN THE COPY, which is the object the envelope carries.
        copied_root = os.path.join(self.dir, e["relpath"].replace("/", os.sep))
        digest, fails = inner_seal_failures(copied_root, inner_seal_relpath)
        if fails:
            raise EnvelopeError("refusing to bind the collection: %s" % fails)
        self.inner_seal_digest = digest
        self.inner_seal_relpath = inner_seal_relpath
        e["extra"]["inner_seal_sha256"] = digest
        self._advance(COLLECTION_BOUND, "inner seal %s" % digest[:16])
        return e

    def bind_trace(self, trace_path, trace_status, relpath="environment_trace.json"):
        if self.state != COLLECTION_BOUND:
            raise EnvelopeError("trace must be bound from %s, not %s"
                                % (COLLECTION_BOUND, self.state))
        if trace_status not in TRACE_STATUSES:
            raise EnvelopeError("trace_status %r is not one of %s"
                                % (trace_status, list(TRACE_STATUSES)))
        self.trace_status = trace_status
        e = self._stage("environment_trace", trace_path, KIND_FILE, relpath=relpath,
                        extra={"trace_status": trace_status})
        self._advance(TRACE_BOUND, "trace %s" % trace_status)
        return e

    def bind(self, role, src, kind=KIND_FILE, relpath=None, extra=None, is_dir=False):
        if self.state not in (TRACE_BOUND, CHECKED):
            raise EnvelopeError("artefacts are bound after the trace and before the seal, not in "
                                "state %s" % self.state)
        e = self._stage(role, src, kind, relpath=relpath, extra=extra, is_dir=is_dir)
        self._write_state("bound %s" % role)
        return e

    def mark_checked(self, gate_results_path, relpath="pre_seal_gate_results.json"):
        """Bind the PRE-SEAL gate results. Inputs to the seal, never claims about it."""
        if self.state != TRACE_BOUND:
            raise EnvelopeError("mark_checked runs from %s, not %s" % (TRACE_BOUND, self.state))
        e = self._stage("pre_seal_gate_results", gate_results_path, KIND_FILE, relpath=relpath)
        self._advance(CHECKED, "pre-seal gate results bound")
        return e

    # ---- sealing ----
    def seal(self):
        if self.state != CHECKED:
            raise EnvelopeError("seal runs from %s, not %s" % (CHECKED, self.state))
        missing = [r for r in self.required_roles if r not in self.entries]
        if missing:
            raise EnvelopeError("cannot seal: required roles not bound: %s" % missing)

        bad = unsafe_objects(self.dir)
        if bad:
            raise EnvelopeError("cannot seal: unrepresentable object(s) inside the envelope: %s"
                                % bad[:4])

        # SEALING is written FIRST and is not a claim of finality, so hashing it is honest.
        self._advance(SEALING, "computing the checksum inventory")

        graph = walk_typed(self.dir)
        present = [r for r, k in sorted(graph.items()) if k == "regular" and r not in SELF_FILES]
        directories = [r for r, k in sorted(graph.items()) if k == "directory"]
        for rel in present + directories:
            why = unsafe_relpath_reason(rel)
            if why and rel != STATE_FILE:
                raise EnvelopeError("cannot seal: %s" % why)
            if escapes_root(self.dir, os.path.join(self.dir, rel.replace("/", os.sep))):
                raise EnvelopeError("cannot seal: %r resolves outside the envelope" % rel)
        coll = case_collisions(present + directories)
        if coll:
            raise EnvelopeError("cannot seal: case-colliding paths %s" % coll)

        lines = []
        for r in present:
            full = os.path.join(self.dir, r.replace("/", os.sep))
            lines.append("%s  %d  %s" % (sha256_file(full), os.path.getsize(full), r))
        sums_path = os.path.join(self.dir, SUMS_FILE)
        with open(sums_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:                          # pragma: no cover
                pass

        # The typed inventory, self-files excluded, is what makes an empty directory a member.
        inv = {r: v for r, v in typed_inventory(self.dir).items() if r not in SELF_FILES}
        seal_doc = {
            "schema": SCHEMA, "envelope_id": self.envelope_id,
            "sealed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())),
            "state_file_state": SEALING,
            "final": True,
            "self_file_rule": ("%s and %s are the only files excluded from %s, because each would "
                               "have to contain its own digest. Every other file is listed exactly "
                               "once. BECAUSE THIS SEAL IS EXCLUDED IT CANNOT AUTHENTICATE "
                               "ITSELF: a decision-gate verification must pin this file's digest "
                               "from outside." % (SUMS_FILE, SEAL_FILE, SUMS_FILE)),
            "sums_file": SUMS_FILE,
            "sums_sha256": sha256_file(sums_path),
            "listed_file_count": len(present),
            "directories": directories,
            "directory_count": len(directories),
            "typed_inventory_sha256": inventory_digest(inv),
            "inventory_note": ("the typed inventory covers DIRECTORIES, empty ones included, and "
                               "records object TYPE. A checksum list of regular files cannot see "
                               "an empty directory added, deleted or renamed after sealing."),
            "inner_seal_relpath": self.inner_seal_relpath,
            "inner_seal_sha256": self.inner_seal_digest,
            "trace_status": self.trace_status,
            "required_roles": list(self.required_roles),
            "roles": {r: dict(e) for r, e in sorted(self.entries.items())},
            "attestation_note": ("post-seal verification is DETACHED. No result proving this seal "
                                 "is or can be inside the envelope this seal covers."),
        }
        self._atomic_json(os.path.join(self.dir, SEAL_FILE), seal_doc)
        self.sealed = True
        return seal_doc

    def publish(self, final_dir):
        """One-shot atomic same-device rename."""
        if not self.sealed:
            raise EnvelopeError("refusing to publish from state %s: only a sealed envelope may "
                                "take a final name" % self.state)
        if self.published:
            raise EnvelopeError("this envelope was already published to %r; publication is "
                                "one-shot" % self.dir)
        final_dir = os.path.abspath(final_dir)
        if os.path.lexists(final_dir):
            raise EnvelopeError("refusing to publish over an existing path %r" % final_dir)
        parent = os.path.dirname(final_dir) or "."
        if not os.path.isdir(parent):
            raise EnvelopeError("publication parent %r does not exist" % parent)
        # ACTUAL device identity, not drive-letter text.
        if os.stat(parent).st_dev != os.stat(self.dir).st_dev:
            raise EnvelopeError("refusing to publish across devices (%s -> %s): the rename would "
                                "not be atomic" % (os.stat(self.dir).st_dev,
                                                   os.stat(parent).st_dev))
        os.rename(self.dir, final_dir)
        self.dir = final_dir
        self.published = True
        return final_dir


# ------------------------------------------------------------------ verifier
def verify_envelope(path, expect_inner_seal=None, expect_spec_sha256=None,
                    expect_trace_status=None, expect_outer_seal_sha256=None,
                    require_roles=None, decision_gate=False, require_final_name=True,
                    authorized_run=False, spec_required_roles=None):
    """Structural verification of a sealed envelope. Returns a list of failures.

    `decision_gate=True` means the result will be used to decide something, and then
    `expect_outer_seal_sha256` is MANDATORY: the seal is excluded from the checksum list, so it
    cannot vouch for itself and an external pin is the only thing that can.

    `require_roles` ADDS to the floor. It can never replace or shrink it."""
    fails = []
    path = os.path.abspath(path)
    seal_path = os.path.join(path, SEAL_FILE)
    sums_path = os.path.join(path, SUMS_FILE)

    if file_kind(path) != "directory":
        return ["%r is %s, not a plain directory" % (path, file_kind(path))]
    if not os.path.exists(seal_path):
        return ["no %s: this directory carries a final-looking name but has no final seal"
                % SEAL_FILE]

    if decision_gate and not expect_outer_seal_sha256:
        fails.append("a decision-gate verification requires an externally supplied "
                     "expect_outer_seal_sha256; the excluded seal cannot authenticate itself")
    if expect_outer_seal_sha256:
        got = sha256_file(seal_path)
        if got != expect_outer_seal_sha256:
            fails.append("outer seal digest %s != externally pinned %s"
                         % (got[:16], expect_outer_seal_sha256[:16]))

    try:
        seal = json.load(open(seal_path, encoding="utf-8"))
    except Exception as e:
        return fails + ["%s is unreadable: %s: %s" % (SEAL_FILE, type(e).__name__, e)]

    if seal.get("schema") != SCHEMA:
        fails.append("seal schema %r != %r" % (seal.get("schema"), SCHEMA))
    if seal.get("final") is not True:
        fails.append("the seal does not declare finality")

    graph = walk_typed(path)
    unsafe = sorted((r, k) for r, k in graph.items() if k not in SAFE_KINDS)
    if unsafe:
        fails.append("unrepresentable object(s) inside the envelope: %s" % unsafe[:4])

    state_path = os.path.join(path, STATE_FILE)
    if not os.path.exists(state_path):
        fails.append("no %s" % STATE_FILE)
    else:
        try:
            st = json.load(open(state_path, encoding="utf-8"))
            if st.get("final") is not False:
                fails.append("%s claims finality; only %s may do that" % (STATE_FILE, SEAL_FILE))
            if st.get("state") != SEALING:
                fails.append("%s says state=%r; a sealed envelope's state file must read %r"
                             % (STATE_FILE, st.get("state"), SEALING))
            if st.get("envelope_id") != seal.get("envelope_id"):
                fails.append("envelope id disagrees between state (%r) and seal (%r)"
                             % (st.get("envelope_id"), seal.get("envelope_id")))
        except Exception as e:
            fails.append("%s unreadable: %s" % (STATE_FILE, e))

    if not os.path.exists(sums_path):
        return fails + ["no %s" % SUMS_FILE]
    if sha256_file(sums_path) != seal.get("sums_sha256"):
        fails.append("%s digest %s != the digest the seal names (%s)"
                     % (SUMS_FILE, sha256_file(sums_path)[:16], str(seal.get("sums_sha256"))[:16]))

    listed, dup = {}, []
    for ln in open(sums_path, encoding="utf-8"):
        ln = ln.rstrip("\n")
        if not ln:
            continue
        parts = ln.split("  ")
        if len(parts) != 3:
            fails.append("malformed %s line %r" % (SUMS_FILE, ln[:80]))
            continue
        digest, size, rel = parts[0], parts[1], parts[2]
        if not _is_hex64(digest):
            fails.append("malformed digest for %r" % rel)
            continue
        if not size.isdigit():
            fails.append("malformed size for %r" % rel)
            continue
        if rel in listed:
            dup.append(rel)
        listed[rel] = (digest, int(size))
    if dup:
        fails.append("%s lists these paths more than once: %s" % (SUMS_FILE, sorted(set(dup))))
    if seal.get("listed_file_count") != len(listed):
        fails.append("the seal declares %r listed files but %d are listed"
                     % (seal.get("listed_file_count"), len(listed)))

    present = [r for r, k in sorted(graph.items()) if k == "regular" and r not in SELF_FILES]
    extra = sorted(set(present) - set(listed))
    missing = sorted(set(listed) - set(present))
    if extra:
        fails.append("files present but not listed (post-seal insertion): %s" % extra)
    if missing:
        fails.append("files listed but absent: %s" % missing)

    # ---- DIRECTORIES, empty ones included. R3-4 was invisible to a file-only inventory. ----
    declared_dirs = seal.get("directories")
    actual_dirs = sorted(r for r, k in graph.items() if k == "directory")
    if not isinstance(declared_dirs, list):
        fails.append("the seal declares no directory inventory, so an empty directory added, "
                     "deleted or renamed after sealing would be invisible")
    else:
        added = sorted(set(actual_dirs) - set(declared_dirs))
        gone = sorted(set(declared_dirs) - set(actual_dirs))
        if added:
            fails.append("directories present but not sealed (post-seal insertion): %s" % added)
        if gone:
            fails.append("directories sealed but absent (deleted or renamed): %s" % gone)
        if seal.get("directory_count") != len(declared_dirs):
            fails.append("the seal declares %r directories but lists %d"
                         % (seal.get("directory_count"), len(declared_dirs)))

    for rel in sorted(set(present) & set(listed)):
        full = os.path.join(path, rel.replace("/", os.sep))
        why = unsafe_relpath_reason(rel)
        if why and rel != STATE_FILE:
            fails.append("unsafe listed path: %s" % why)
            continue
        if escapes_root(path, full):
            fails.append("%r resolves outside the envelope" % rel)
            continue
        k = file_kind(full)
        if k != "regular":
            fails.append("%r is a %s, not a regular file" % (rel, k))
            continue
        d, sz = listed[rel]
        if sha256_file(full) != d:
            fails.append("content of %r does not match its listed digest" % rel)
        elif os.path.getsize(full) != sz:
            fails.append("size of %r does not match its listed size" % rel)
    coll = case_collisions(present + actual_dirs)
    if coll:
        fails.append("case-colliding paths inside the envelope: %s" % coll)

    # ---- the whole typed inventory, against the digest the seal recorded ----
    inv = {r: v for r, v in typed_inventory(path).items() if r not in SELF_FILES}
    got_inv = inventory_digest(inv)
    if seal.get("typed_inventory_sha256") != got_inv:
        fails.append("the typed inventory hashes to %s but the seal recorded %s -- an object was "
                     "added, removed, renamed or changed TYPE"
                     % (got_inv[:16], str(seal.get("typed_inventory_sha256"))[:16]))

    # ---- roles cross-checked against the ACTUAL inventory, in both directions ----
    roles = seal.get("roles") or {}
    if not isinstance(roles, dict):
        fails.append("the seal carries no usable roles block")
        roles = {}
    seen_paths = {}
    for role, e in sorted(roles.items()):
        if role not in ROLES:
            fails.append("seal binds unknown role %r" % role)
            continue
        if not isinstance(e, dict):
            fails.append("role %r metadata is not an object" % role)
            continue
        rel = e.get("relpath")
        why = (unsafe_relpath_reason(rel) if isinstance(rel, str)
               else "role %r has no relpath" % role)
        if why:
            fails.append("role %r: %s" % (role, why))
            continue
        low = rel.casefold()
        if low in seen_paths:
            fails.append("roles %r and %r both bind %r" % (seen_paths[low], role, rel))
        seen_paths[low] = role

        full = os.path.join(path, rel.replace("/", os.sep))
        is_dir = bool(e.get("is_dir"))
        if is_dir:
            if file_kind(full) != "directory":
                fails.append("role %r names %r, which is %s in this envelope"
                             % (role, rel, file_kind(full)))
                continue
            members = walk_relpaths(full)
            if not members:
                fails.append("role %r names an empty directory %r" % (role, rel))
            unlisted = [rel + "/" + m for m in members if (rel + "/" + m) not in listed]
            if unlisted:
                fails.append("role %r has member(s) missing from the checksum list: %s"
                             % (role, unlisted[:4]))
            got_digest = sha256_tree(full)
            got_size = sum(os.path.getsize(os.path.join(full, m.replace("/", os.sep)))
                           for m in members)
        else:
            if rel not in listed:
                fails.append("role %r names %r, which is not in the checksum list" % (role, rel))
                continue
            if file_kind(full) != "regular":
                fails.append("role %r names %r, which is %s" % (role, rel, file_kind(full)))
                continue
            got_digest = sha256_file(full)
            got_size = os.path.getsize(full)
        if e.get("sha256") != got_digest:
            fails.append("role %r declares digest %s but %r hashes to %s -- role metadata lives "
                         "in the EXCLUDED seal and is never trusted on its own"
                         % (role, str(e.get("sha256"))[:16], rel, got_digest[:16]))
        if e.get("size") != got_size:
            fails.append("role %r declares size %r but %r is %d bytes"
                         % (role, e.get("size"), rel, got_size))

    # ---- required roles: the UNION of every floor. A caller may only ADD. ----
    need = effective_required_roles(seal_roles=seal.get("required_roles"),
                                    spec_roles=spec_required_roles,
                                    caller_extra=require_roles,
                                    authorized_run=authorized_run)
    for r in need:
        if r not in roles:
            fails.append("required role %r is not bound" % r)
    declared_floor = set(seal.get("required_roles") or ())
    short = sorted(set(REQUIRED_ROLES) - declared_floor)
    if short:
        fails.append("the seal declares a required-role floor that omits %s; the authoritative "
                     "minimum is %s and an envelope may not be sealed below it"
                     % (short, list(REQUIRED_ROLES)))

    # ---- the ACTUAL inner seal, opened and hashed inside the bound collection ----
    ic = roles.get("inner_collection") or {}
    ic_rel = ic.get("relpath")
    ic_extra = ic.get("extra") or {}
    isr = seal.get("inner_seal_relpath") or ic_extra.get("inner_seal_relpath")
    if not isinstance(ic_rel, str) or not isinstance(isr, str):
        fails.append("the envelope does not say where the inner seal lives, so no inner seal can "
                     "be located, opened or hashed")
    else:
        coll_root = os.path.join(path, ic_rel.replace("/", os.sep))
        listed_key = ic_rel + "/" + isr
        actual_inner, inner_fails = inner_seal_failures(coll_root, isr)
        for f in inner_fails:
            fails.append("inner seal: %s" % f)
        if listed_key not in listed:
            fails.append("the inner seal %r is not in the outer checksum list" % listed_key)
        if actual_inner is not None:
            if seal.get("inner_seal_sha256") != actual_inner:
                fails.append("the seal header claims inner seal %s but the ACTUAL file hashes to "
                             "%s" % (str(seal.get("inner_seal_sha256"))[:16], actual_inner[:16]))
            if ic_extra.get("inner_seal_sha256") != actual_inner:
                fails.append("the inner_collection role claims inner seal %s but the ACTUAL file "
                             "hashes to %s"
                             % (str(ic_extra.get("inner_seal_sha256"))[:16], actual_inner[:16]))
            if expect_inner_seal is not None and actual_inner != expect_inner_seal:
                fails.append("the ACTUAL inner seal %s != externally expected %s"
                             % (actual_inner[:16], expect_inner_seal[:16]))
        elif expect_inner_seal is not None:
            fails.append("expect_inner_seal was supplied but no inner seal could be opened")

    if seal.get("trace_status") not in TRACE_STATUSES:
        fails.append("trace_status %r is missing or not one of %s"
                     % (seal.get("trace_status"), list(TRACE_STATUSES)))
    else:
        tr = (roles.get("environment_trace") or {}).get("extra") or {}
        if tr.get("trace_status") != seal.get("trace_status"):
            fails.append("trace status disagrees between the role (%r) and the seal (%r)"
                         % (tr.get("trace_status"), seal.get("trace_status")))
        if expect_trace_status is not None and seal["trace_status"] != expect_trace_status:
            fails.append("trace_status %r != expected %r" % (seal["trace_status"],
                                                             expect_trace_status))

    if authorized_run and expect_spec_sha256 is None:
        fails.append("an authorized run must pin the bound specification's bytes from outside "
                     "before its declared role list means anything")
    if expect_spec_sha256 is not None:
        # Compare the ACTUAL bytes on disk, never the attacker-editable role metadata.
        srel = (roles.get("qualification_spec") or {}).get("relpath")
        actual = None
        if isinstance(srel, str) and not unsafe_relpath_reason(srel):
            sp = os.path.join(path, srel.replace("/", os.sep))
            if file_kind(sp) == "regular":
                actual = sha256_file(sp)
        if actual is None:
            fails.append("the bound qualification spec could not be read from the envelope, so "
                         "expect_spec_sha256 cannot be satisfied")
        elif actual != expect_spec_sha256:
            fails.append("the bound qualification spec hashes to %s, not the expected %s"
                         % (actual[:16], expect_spec_sha256[:16]))

    arch = roles.get("daemon_log_archive")
    side = roles.get("daemon_log_sidecar")
    if arch or side:
        if not (arch and side):
            fails.append("the daemon-log archive and its digest sidecar must be bound together")
        else:
            want = arch.get("relpath", "") + ".sha256"
            if side.get("relpath") != want:
                fails.append("sidecar %r is not %r" % (side.get("relpath"), want))
            else:
                try:
                    txt = open(os.path.join(path, side["relpath"].replace("/", os.sep)),
                               encoding="utf-8").read().split()
                    if not txt or txt[0].lower() != arch.get("sha256"):
                        fails.append("sidecar digest does not match the bound archive digest")
                except Exception as e:
                    fails.append("sidecar unreadable: %s" % e)

    if require_final_name:
        partials = [r for r in present if r.casefold().endswith(RESERVED_SUFFIXES)]
        if partials:
            fails.append("interrupted atomic writes remain: %s" % partials)
        base = os.path.basename(path).casefold()
        for marker in (".staging", ".partial", ".incomplete", ".tmp"):
            if marker in base:
                fails.append("final-looking check requested but the directory name %r still "
                             "carries the staging marker %r" % (os.path.basename(path), marker))
    return fails


# ------------------------------------------------------------------ detached attestation
# The canonical attestation is a PACKAGE DIRECTORY published by ONE rename. R4-9 reproduced an
# orphan final-name OUTER_ATTESTATION.json when the second of two renames failed: staging both
# files first is useful, but two final renames are not a pair-atomic publication.
CANONICAL_ATTESTATION_DIR = "OUTER_ATTESTATION"
CANONICAL_ATTESTATION_NAME = "OUTER_ATTESTATION.json"
CANONICAL_ATTESTATION_SIDECAR = CANONICAL_ATTESTATION_NAME + ".sha256"
RELOCATION_RESULT_SCHEMA = "meepcoin-relocated-verification/3"
CANONICAL_ATTESTATION_SCHEMA = "meepcoin-envelope-attestation/4"
CANONICAL_ATTESTATION_KEYS = frozenset((
    "schema", "non_evidence", "canonical", "canonical_package", "precedence",
    "covered_by_envelope", "boundary", "envelope_path_at_verification", "outer_seal_sha256",
    "outer_seal_sha256_source_at_attestation", "external_pins", "relocated_to", "verifier",
    "verifier_source_relpath", "verifier_source_sha256", "bootstrap_verified",
    "bootstrap_closure_sha256", "child_execution_proof", "expectations",
    "authorization_verified", "authorization_binding",
    "source_before_digest", "source_after_digest", "four_point_identity", "g17_pass",
    "verification_passed", "verification_failures", "utc",
))

# The external pin vocabulary is exact. In particular, the gate inventory and the typed
# ENVELOPE inventory are distinct objects and may never share one ambiguous `inventory_sha256`
# name. The first ten values describe the authorization/runtime bind; the last two describe the
# sealed evidence object G17 relocated and verified.
AUTHORIZATION_ATTESTATION_PIN_KEYS = frozenset((
    "authorized_spec_sha256", "gate_inventory_sha256", "gate_semantics_sha256",
    "full_binding_sha256", "authorization_record_sha256", "authorized_root",
    "interpreter_path", "interpreter_sha256", "bundled_verifier_sha256",
    "bootstrap_closure_sha256",
))
CANONICAL_EXTERNAL_PIN_KEYS = AUTHORIZATION_ATTESTATION_PIN_KEYS | frozenset((
    "outer_seal_sha256", "envelope_typed_inventory_sha256",
))
CANONICAL_DIGEST_PIN_KEYS = CANONICAL_EXTERNAL_PIN_KEYS - frozenset((
    "authorized_root", "interpreter_path",
))
ATTESTATION_AUTHENTICATION_LIMIT = (
    "Without an EXTERNALLY RETAINED attestation digest, a signature, or an independent rerun, a "
    "canonical attestation package is a SELF-CONSISTENT CLAIM about who verified what -- not "
    "proof of who produced it. A JSON document and a SHA-256 sidecar computed from that same "
    "document authenticate nothing: whoever wrote the document could write the sidecar. The "
    "trust anchor this module supports is expect_attestation_sha256, recorded when the package "
    "was published and kept somewhere the package cannot reach.")
ATTESTATION_PRECEDENCE = (
    "The project's canonical attestation is the directory named %s, published by a single atomic "
    "rename and containing exactly %s and %s. Third parties may publish their own attestations "
    "about the same outer seal; those are additional claims, are written by write_attestation as "
    "ordinary files, and are NEVER silently interchangeable with the canonical package. Where two "
    "attestations disagree, both are reported and neither is treated as authoritative without a "
    "human decision."
    % (CANONICAL_ATTESTATION_DIR, CANONICAL_ATTESTATION_NAME, CANONICAL_ATTESTATION_SIDECAR))

# API ENFORCEMENT, NOT A SANDBOX. Only the production G17 operation in qual_verify_v2 holds this
# token, so no caller can publish a canonical attestation from a dictionary it made up (R4-8).
# Arbitrary same-process Python can of course read this module global; the point is that the
# supported API has exactly one canonical publication path, inside the operation that did the work.
_CANONICAL_TOKEN = object()


def _canonical_external_pins(*, expect_authorized_spec_sha256=None,
                             expect_gate_inventory_sha256=None,
                             expect_gate_semantics_sha256=None,
                             expect_full_binding_sha256=None,
                             expect_authorization_record_sha256=None,
                             expect_authorized_root=None, expect_interpreter_path=None,
                             expect_interpreter_sha256=None, expect_outer_seal_sha256=None,
                             expect_verifier_sha256=None, expect_bootstrap_sha256=None,
                             expect_envelope_inventory_sha256=None):
    """The one unambiguous external-pin vocabulary used by publication and authentication."""
    return {
        "authorized_spec_sha256": expect_authorized_spec_sha256,
        "gate_inventory_sha256": expect_gate_inventory_sha256,
        "gate_semantics_sha256": expect_gate_semantics_sha256,
        "full_binding_sha256": expect_full_binding_sha256,
        "authorization_record_sha256": expect_authorization_record_sha256,
        "authorized_root": expect_authorized_root,
        "interpreter_path": expect_interpreter_path,
        "interpreter_sha256": expect_interpreter_sha256,
        "outer_seal_sha256": expect_outer_seal_sha256,
        "bundled_verifier_sha256": expect_verifier_sha256,
        "bootstrap_closure_sha256": expect_bootstrap_sha256,
        "envelope_typed_inventory_sha256": expect_envelope_inventory_sha256,
    }


def _canonical_pin_failures(pins, recheck_runtime=False):
    """Validate a complete pin set; optionally re-open the runtime objects it names."""
    fails = []
    if not isinstance(pins, dict):
        return ["external pins are not an object"]
    unknown = sorted(set(pins) - CANONICAL_EXTERNAL_PIN_KEYS)
    missing = sorted(CANONICAL_EXTERNAL_PIN_KEYS - set(pins))
    if unknown:
        fails.append("external pins carry unknown key(s) %s" % unknown)
    if missing:
        fails.append("external pins are missing %s" % missing)
    for name in sorted(CANONICAL_DIGEST_PIN_KEYS & set(pins)):
        if not _is_hex64(pins.get(name) or ""):
            fails.append("external pin %r must be 64 lowercase hex characters" % name)

    for name in ("authorized_root", "interpreter_path"):
        path = pins.get(name)
        if (not isinstance(path, str) or not path or "\x00" in path
                or not os.path.isabs(path)):
            fails.append("external pin %r must be a canonical absolute path" % name)
            continue
        try:
            absolute = os.path.abspath(path)
            normalized = os.path.normpath(path)
            real = os.path.realpath(path)
        except (OSError, TypeError, ValueError) as e:
            fails.append("external pin %r could not be resolved safely: %s: %s"
                         % (name, type(e).__name__, e))
            continue
        if os.path.normcase(normalized) != os.path.normcase(path):
            fails.append("external pin %r is not in canonical form: %r" % (name, path))
        if os.path.normcase(real) != os.path.normcase(absolute):
            fails.append("external pin %r is an alias for %r" % (name, real))

    if recheck_runtime and not fails:
        root = pins["authorized_root"]
        interp = pins["interpreter_path"]
        if file_kind(root) != "directory":
            fails.append("the externally pinned authorized root %r is %s, not a directory"
                         % (root, file_kind(root)))
        if file_kind(interp) != "regular":
            fails.append("the externally pinned interpreter %r is %s, not a regular file"
                         % (interp, file_kind(interp)))
        elif sha256_file(interp) != pins["interpreter_sha256"]:
            fails.append("the externally pinned interpreter now hashes to %s, not %s"
                         % (sha256_file(interp)[:16], pins["interpreter_sha256"][:16]))
    return fails


def _source_qualification_spec_sha256(envelope_path):
    """Re-derive the source envelope's qualification-spec role digest, or raise."""
    seal_path = os.path.join(envelope_path, SEAL_FILE)
    try:
        seal = json.load(open(seal_path, encoding="utf-8"))
    except Exception as e:
        raise EnvelopeError("the source envelope seal is unreadable: %s: %s"
                            % (type(e).__name__, e))
    roles = seal.get("roles") if isinstance(seal.get("roles"), dict) else {}
    role = roles.get("qualification_spec")
    if not isinstance(role, dict) or role.get("is_dir") is not False:
        raise EnvelopeError("the source envelope has no regular qualification_spec role")
    rel = role.get("relpath")
    why = unsafe_relpath_reason(rel) if isinstance(rel, str) else "no relpath"
    if why:
        raise EnvelopeError("the source qualification_spec role path is unsafe: %s" % why)
    full = os.path.join(envelope_path, rel.replace("/", os.sep))
    if not contained_in(envelope_path, full) or file_kind(full) != "regular":
        raise EnvelopeError("the source qualification_spec role is not a contained regular file")
    actual = sha256_file(full)
    if role.get("sha256") != actual:
        raise EnvelopeError("the source qualification_spec bytes disagree with their role digest")
    return actual


def _plain_json(value):
    """Detach mappingproxy/tuple based immutable records into JSON-compatible data."""
    return json.loads(json.dumps(
        value, default=lambda o: dict(o) if hasattr(o, "keys") else list(o)))


def _attestation_document(envelope_path, relocation_result, verifier_id, source_now, canonical,
                          pins, clock):
    return {
        "schema": CANONICAL_ATTESTATION_SCHEMA,
        "non_evidence": True,
        "canonical": bool(canonical),
        "canonical_package": CANONICAL_ATTESTATION_DIR,
        "precedence": ATTESTATION_PRECEDENCE,
        "covered_by_envelope": False,
        "boundary": ("pre-seal gates are inside the envelope; this attestation is outside it. A "
                     "seal cannot contain a result proving that same seal, so post-seal "
                     "verification is detached and names the seal digest of the copy verified."),
        "envelope_path_at_verification": os.path.abspath(envelope_path),
        "outer_seal_sha256": relocation_result.get("verified_copy_outer_seal_sha256"),
        "outer_seal_sha256_source_at_attestation": source_now,
        "external_pins": dict(pins),
        "relocated_to": relocation_result.get("relocated_to"),
        "verifier": verifier_id,
        "verifier_source_relpath": relocation_result.get("verified_with"),
        "verifier_source_sha256": relocation_result.get("verifier_source_sha256"),
        "bootstrap_verified": bool(relocation_result.get("bootstrap_verified")),
        "bootstrap_closure_sha256": relocation_result.get("bootstrap_closure_sha256"),
        "child_execution_proof": relocation_result.get("child_execution_proof"),
        "expectations": _plain_json(relocation_result.get("expectations") or {}),
        "authorization_verified": bool(relocation_result.get("authorization_verified")),
        "authorization_binding": _plain_json(
            relocation_result.get("authorization_binding") or {}),
        "source_before_digest": relocation_result.get("source_before_digest"),
        "source_after_digest": relocation_result.get("source_after_digest"),
        "four_point_identity": bool(relocation_result.get("four_point_identity")),
        "g17_pass": bool(relocation_result.get("g17_pass")),
        "verification_passed": bool(relocation_result.get("passed")),
        "verification_failures": list(relocation_result.get("failures") or []),
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock())),
    }


def _attestation_preconditions(envelope_path, out_path, relocation_result):
    """Shared, minimal checks. Returns the source seal digest now, or raises."""
    if not isinstance(relocation_result, dict) or \
            relocation_result.get("schema") != RELOCATION_RESULT_SCHEMA:
        raise EnvelopeError("an attestation must be bound to a structured relocation result, not "
                            "to a caller-supplied failure list")
    parent = os.path.dirname(out_path) or "."
    if not os.path.isdir(parent):
        raise EnvelopeError("attestation parent directory %r does not exist" % parent)
    for guard, label in ((envelope_path, "the source envelope"),
                         (relocation_result.get("relocated_to"), "the relocated copy")):
        if guard and (contained_in(guard, parent) or contained_in(guard, out_path)):
            raise EnvelopeError(
                "an attestation may not be written inside %s: that would change the bytes it is "
                "about (destination resolves to %r)" % (label, _norm(out_path)))
    verified_seal = relocation_result.get("verified_copy_outer_seal_sha256")
    if not _is_hex64(verified_seal or ""):
        raise EnvelopeError("the relocation result carries no verified-copy outer-seal digest")
    if not relocation_result.get("source_stable"):
        raise EnvelopeError("the relocation result does not prove the source envelope was "
                            "unchanged across verification")
    source_now = sha256_file(os.path.join(envelope_path, SEAL_FILE))
    if source_now != verified_seal:
        raise EnvelopeError(
            "TOCTOU: the source envelope's seal is now %s but the copy that was verified sealed "
            "to %s; refusing to attest a different object" % (source_now[:16], verified_seal[:16]))
    return source_now


def write_attestation(envelope_path, out_path, relocation_result, verifier_id, clock=time.time):
    """A DETACHED, NON-CANONICAL claim about a sealed envelope, written as one ordinary file.

    There is deliberately no `canonical` parameter. R4-8 published a canonical attestation from a
    dictionary that merely had the right shape -- g17_pass true, passed FALSE, a nonempty failures
    list and no relocation ever run. The canonical package is now produced only by
    publish_canonical_attestation, which the production G17 operation calls after its own checks."""
    envelope_path = os.path.abspath(envelope_path)
    out_path = os.path.abspath(out_path)
    source_now = _attestation_preconditions(envelope_path, out_path, relocation_result)
    doc = _attestation_document(envelope_path, relocation_result, verifier_id, source_now,
                                False, {}, clock)
    doc["third_party_note"] = ("NOT CANONICAL. This file is one party's claim; it was not produced "
                               "by the project's own G17 operation and nothing here re-derives it.")
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    return doc


def publish_canonical_attestation(envelope_path, package_dir, relocation_result, verifier_id,
                                  *, expect_authorized_spec_sha256=None,
                                  expect_gate_inventory_sha256=None,
                                  expect_gate_semantics_sha256=None,
                                  expect_full_binding_sha256=None,
                                  expect_authorization_record_sha256=None,
                                  expect_authorized_root=None, expect_interpreter_path=None,
                                  expect_interpreter_sha256=None,
                                  expect_outer_seal_sha256=None, expect_verifier_sha256=None,
                                  expect_bootstrap_sha256=None,
                                  expect_envelope_inventory_sha256=None,
                                  token=None, clock=time.time):
    """Publish the canonical attestation PACKAGE with ONE atomic rename.

    Requirements, all of them:

      * the caller holds the production token -- in practice this is only ever called from inside
        the G17 operation that produced the result;
      * every external pin is supplied and matches what the result was actually run against;
      * the result reports passed, g17_pass, bootstrap_verified, four_point_identity, an empty
        failures list and a relocated copy that really exists;
      * the source envelope's seal AND its complete current typed inventory still equal the pins.

    Publication stages both files inside a freshly created staging directory and renames THAT
    directory once. A failure at any point leaves only a staging directory, never a final name."""
    if token is not _CANONICAL_TOKEN:
        raise EnvelopeError(
            "a canonical attestation is published only by the production G17 operation that "
            "produced the result. A caller-supplied dictionary, however well shaped, is not a "
            "verification (see qual_verify_v2.relocate_and_verify(attestation_package=...))")
    envelope_path = os.path.abspath(envelope_path)
    package_dir = os.path.abspath(package_dir)
    if os.path.basename(package_dir) != CANONICAL_ATTESTATION_DIR:
        raise EnvelopeError("the canonical attestation package must be named %r, not %r"
                            % (CANONICAL_ATTESTATION_DIR, os.path.basename(package_dir)))
    source_now = _attestation_preconditions(envelope_path, package_dir, relocation_result)

    pins = _canonical_external_pins(
        expect_authorized_spec_sha256=expect_authorized_spec_sha256,
        expect_gate_inventory_sha256=expect_gate_inventory_sha256,
        expect_gate_semantics_sha256=expect_gate_semantics_sha256,
        expect_full_binding_sha256=expect_full_binding_sha256,
        expect_authorization_record_sha256=expect_authorization_record_sha256,
        expect_authorized_root=expect_authorized_root,
        expect_interpreter_path=expect_interpreter_path,
        expect_interpreter_sha256=expect_interpreter_sha256,
        expect_outer_seal_sha256=expect_outer_seal_sha256,
        expect_verifier_sha256=expect_verifier_sha256,
        expect_bootstrap_sha256=expect_bootstrap_sha256,
        expect_envelope_inventory_sha256=expect_envelope_inventory_sha256)
    pin_fails = _canonical_pin_failures(pins, recheck_runtime=True)
    if pin_fails:
        raise EnvelopeError("a canonical attestation requires a complete, valid external pin set: "
                            "%s" % pin_fails)
    for field in ("passed", "g17_pass", "bootstrap_verified", "four_point_identity",
                  "authorization_verified"):
        if relocation_result.get(field) is not True:
            raise EnvelopeError("a canonical attestation requires %s to be true; this result "
                                "reports %r" % (field, relocation_result.get(field)))
    if list(relocation_result.get("failures") or []):
        raise EnvelopeError("a canonical attestation requires an empty failure list; this result "
                            "carries %s" % (relocation_result.get("failures") or [])[:3])
    reloc = relocation_result.get("relocated_to")
    if not isinstance(reloc, str) or file_kind(reloc) != "directory":
        raise EnvelopeError("a canonical attestation requires a real relocated copy; this result "
                            "names %r" % (reloc,))
    exp = relocation_result.get("expectations") or {}
    if not isinstance(exp, dict):
        raise EnvelopeError("the relocation result carries no structured expectations")
    for key, want in sorted(pins.items()):
        if exp.get(key) != want:
            raise EnvelopeError("the relocation result was not run against the externally pinned "
                                "%s" % key)
    binding = relocation_result.get("authorization_binding")
    if not isinstance(binding, dict) or binding.get("bound_by_bind_authorized") is not True:
        raise EnvelopeError("the relocation result carries no authorization binding produced by "
                            "bind_authorized")
    for key in sorted(AUTHORIZATION_ATTESTATION_PIN_KEYS):
        if binding.get(key) != pins[key]:
            raise EnvelopeError("the verified authorization binding's %s is %r, not the external "
                                "pin %r" % (key, binding.get(key), pins[key]))
    if relocation_result.get("verifier_source_sha256") != expect_verifier_sha256:
        raise EnvelopeError("the bundled verifier that ran is not the externally pinned one")
    if source_now != expect_outer_seal_sha256:
        raise EnvelopeError("the source seal %s is not the externally pinned %s"
                            % (source_now[:16], expect_outer_seal_sha256[:16]))
    inv_now = {r: v for r, v in typed_inventory(envelope_path).items() if r not in SELF_FILES}
    got = inventory_digest(inv_now)
    if got != expect_envelope_inventory_sha256:
        raise EnvelopeError("the source envelope's typed inventory is now %s, not the externally "
                            "pinned %s"
                            % (got[:16], expect_envelope_inventory_sha256[:16]))
    spec_now = _source_qualification_spec_sha256(envelope_path)
    if spec_now != expect_authorized_spec_sha256:
        raise EnvelopeError("the source envelope's qualification specification is now %s, not "
                            "the authorized %s"
                            % (spec_now[:16], expect_authorized_spec_sha256[:16]))

    doc = _attestation_document(envelope_path, relocation_result, verifier_id, source_now, True,
                                pins, clock)
    if os.path.lexists(package_dir):
        raise EnvelopeError("refusing to publish over an existing %r" % package_dir)
    staging = "%s.staging-%d-%d" % (package_dir, os.getpid(), time.time_ns() % 1000000)
    os.mkdir(staging)                                 # exclusive; no check-then-create window
    try:
        inner = os.path.join(staging, CANONICAL_ATTESTATION_NAME)
        fd = os.open(inner, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        side = os.path.join(staging, CANONICAL_ATTESTATION_SIDECAR)
        fd = os.open(side, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("%s  %s\n" % (sha256_file(inner), CANONICAL_ATTESTATION_NAME))
        # ONE rename. Until it succeeds the final name does not exist; if it fails, nothing at
        # the final name was ever created.
        os.rename(staging, package_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return doc


def inspect_canonical_attestation_structure(package_dir):
    """STRUCTURE ONLY. NOT AUTHENTICATION. Returns a dict, never a bare pass.

    R5-13: a hand-made directory containing a JSON document with three true booleans and a
    self-computed checksum returned []. That is exactly what this function can tell you and no
    more, so it no longer answers in the vocabulary of verification."""
    fails = []
    package_dir = os.path.abspath(package_dir)
    result = {"checked": package_dir, "authenticated": False, "diagnostic_only": True,
              "not_authenticated_because": ATTESTATION_AUTHENTICATION_LIMIT,
              "structural_failures": fails}
    if file_kind(package_dir) != "directory":
        fails.append("%r is %s, not the canonical attestation package directory"
                     % (package_dir, file_kind(package_dir)))
        return result
    if os.path.basename(package_dir) != CANONICAL_ATTESTATION_DIR:
        fails.append("the package is named %r, not %r" % (os.path.basename(package_dir),
                                                          CANONICAL_ATTESTATION_DIR))
    got = sorted(walk_typed(package_dir))
    want = sorted((CANONICAL_ATTESTATION_NAME, CANONICAL_ATTESTATION_SIDECAR))
    if got != want:
        fails.append("the package contains %s, not exactly %s" % (got, want))
        return result
    inner = os.path.join(package_dir, CANONICAL_ATTESTATION_NAME)
    side = os.path.join(package_dir, CANONICAL_ATTESTATION_SIDECAR)
    digest = sha256_file(inner)
    result["attestation_sha256"] = digest
    try:
        with open(side, encoding="utf-8", errors="strict") as side_stream:
            side_text = side_stream.read()
    except (OSError, UnicodeError, ValueError) as e:
        fails.append("the attestation sidecar is unreadable: %s: %s"
                     % (type(e).__name__, e))
        return result
    if side_text != "%s  %s\n" % (digest, CANONICAL_ATTESTATION_NAME):
        fails.append("the sidecar does not name the attestation's digest exactly")
    try:
        doc = json.load(open(inner, encoding="utf-8"))
    except Exception as e:
        fails.append("the attestation is unreadable: %s" % e)
        return result
    if not isinstance(doc, dict):
        fails.append("the attestation is %s, not an object" % type(doc).__name__)
        return result
    result["declares_canonical_g17_pass"] = (doc.get("canonical") is True
                                             and doc.get("g17_pass") is True
                                             and doc.get("verification_passed") is True)
    return result


def authenticate_canonical_attestation(package_dir, envelope_path, *,
                                       expect_attestation_sha256=None,
                                       expect_authorized_spec_sha256=None,
                                       expect_gate_inventory_sha256=None,
                                       expect_gate_semantics_sha256=None,
                                       expect_full_binding_sha256=None,
                                       expect_authorization_record_sha256=None,
                                       expect_authorized_root=None,
                                       expect_interpreter_path=None,
                                       expect_interpreter_sha256=None,
                                       expect_outer_seal_sha256=None,
                                       expect_verifier_sha256=None,
                                       expect_bootstrap_sha256=None,
                                       expect_envelope_inventory_sha256=None):
    """AUTHENTICATED verification of a published canonical package. Returns failures.

    Every expectation is EXTERNAL. The load-bearing one is expect_attestation_sha256: the digest
    of the attestation document, retained when it was published, outside the package. Without it
    the package is only self-consistent, and this function refuses rather than pretending."""
    fails = []
    package_dir = os.path.abspath(package_dir)
    envelope_path = os.path.abspath(envelope_path)
    pins = _canonical_external_pins(
        expect_authorized_spec_sha256=expect_authorized_spec_sha256,
        expect_gate_inventory_sha256=expect_gate_inventory_sha256,
        expect_gate_semantics_sha256=expect_gate_semantics_sha256,
        expect_full_binding_sha256=expect_full_binding_sha256,
        expect_authorization_record_sha256=expect_authorization_record_sha256,
        expect_authorized_root=expect_authorized_root,
        expect_interpreter_path=expect_interpreter_path,
        expect_interpreter_sha256=expect_interpreter_sha256,
        expect_outer_seal_sha256=expect_outer_seal_sha256,
        expect_verifier_sha256=expect_verifier_sha256,
        expect_bootstrap_sha256=expect_bootstrap_sha256,
        expect_envelope_inventory_sha256=expect_envelope_inventory_sha256)
    if not _is_hex64(expect_attestation_sha256 or ""):
        fails.append("authentication requires the externally retained attestation_sha256 as 64 "
                     "lowercase hex characters")
    fails.extend(_canonical_pin_failures(pins, recheck_runtime=True))
    if fails:
        return fails

    structure = inspect_canonical_attestation_structure(package_dir)
    fails.extend(structure["structural_failures"])
    if fails:
        return fails

    # ---- THE TRUST ANCHOR: the externally retained digest of the attestation itself ----
    inner = os.path.join(package_dir, CANONICAL_ATTESTATION_NAME)
    got = sha256_file(inner)
    if got != expect_attestation_sha256:
        return fails + ["the attestation hashes to %s, not the externally retained %s; this is a "
                        "different document, whatever it says about itself"
                        % (got[:16], expect_attestation_sha256[:16])]
    try:
        with open(inner, encoding="utf-8", errors="strict") as inner_stream:
            doc = json.load(inner_stream)
    except (OSError, UnicodeError, ValueError) as e:
        return fails + ["the authenticated attestation became unreadable: %s: %s"
                        % (type(e).__name__, e)]
    if not isinstance(doc, dict):
        return fails + ["the authenticated attestation is %s, not an object"
                        % type(doc).__name__]

    if doc.get("schema") != CANONICAL_ATTESTATION_SCHEMA:
        fails.append("attestation schema %r != %r" % (doc.get("schema"),
                                                      CANONICAL_ATTESTATION_SCHEMA))
    unknown = sorted(set(doc) - CANONICAL_ATTESTATION_KEYS)
    missing = sorted(CANONICAL_ATTESTATION_KEYS - set(doc))
    if unknown:
        fails.append("the attestation carries unknown field(s) %s" % unknown)
    if missing:
        fails.append("the attestation is missing %s" % missing)
    for field in ("canonical", "g17_pass", "verification_passed", "four_point_identity",
                  "bootstrap_verified", "authorization_verified"):
        if doc.get(field) is not True:
            fails.append("the attestation reports %s=%r" % (field, doc.get(field)))
    if doc.get("covered_by_envelope") is not False:
        fails.append("an attestation is never covered by the envelope it attests")
    if list(doc.get("verification_failures") or []):
        fails.append("the attestation carries a non-empty failure list: %s"
                     % (doc.get("verification_failures") or [])[:3])

    # ---- the pins the document says it was run against must be the pins supplied here ----
    declared = doc.get("external_pins")
    if not isinstance(declared, dict):
        fails.append("the attestation carries no external_pins block")
    else:
        unknown_pins = sorted(set(declared) - CANONICAL_EXTERNAL_PIN_KEYS)
        missing_pins = sorted(CANONICAL_EXTERNAL_PIN_KEYS - set(declared))
        if unknown_pins:
            fails.append("the attestation's external_pins carries unknown key(s) %s"
                         % unknown_pins)
        if missing_pins:
            fails.append("the attestation's external_pins is missing %s" % missing_pins)
        for key in sorted(CANONICAL_EXTERNAL_PIN_KEYS):
            if declared.get(key) != pins[key]:
                fails.append("the attestation's external pin %s is %r, not the %r supplied here"
                             % (key, declared.get(key), pins[key]))
    exp = doc.get("expectations")
    if not isinstance(exp, dict):
        fails.append("the attestation carries no expectations block")
    else:
        for key, want in sorted(pins.items()):
            if exp.get(key) != want:
                fails.append("the attestation's relocation expectation %s is %r, not the %r "
                             "supplied here" % (key, exp.get(key), want))

    binding = doc.get("authorization_binding")
    if not isinstance(binding, dict) or binding.get("bound_by_bind_authorized") is not True:
        fails.append("the attestation carries no authorization binding produced by "
                     "bind_authorized")
    else:
        for key in sorted(AUTHORIZATION_ATTESTATION_PIN_KEYS):
            if binding.get(key) != pins[key]:
                fails.append("the attestation's verified authorization binding %s is %r, not "
                             "the external pin %r" % (key, binding.get(key), pins[key]))

    # ---- identities ----
    if doc.get("outer_seal_sha256") != expect_outer_seal_sha256:
        fails.append("the attestation names outer seal %s, not the pinned %s"
                     % (str(doc.get("outer_seal_sha256"))[:16], expect_outer_seal_sha256[:16]))
    if doc.get("verifier_source_sha256") != expect_verifier_sha256:
        fails.append("the attestation names bundled verifier %s, not the pinned %s"
                     % (str(doc.get("verifier_source_sha256"))[:16], expect_verifier_sha256[:16]))
    if doc.get("bootstrap_closure_sha256") != expect_bootstrap_sha256:
        fails.append("the attestation names bootstrap closure %s, not the pinned %s"
                     % (str(doc.get("bootstrap_closure_sha256"))[:16],
                        expect_bootstrap_sha256[:16]))
    proof = doc.get("child_execution_proof")
    if not isinstance(proof, dict) or proof.get("ok") is not True:
        fails.append("the attestation carries no successful child execution proof")

    # ---- the SOURCE ENVELOPE, re-derived here and now ----
    if file_kind(envelope_path) != "directory":
        fails.append("the source envelope %r is %s, not a directory"
                     % (envelope_path, file_kind(envelope_path)))
        return fails
    seal_path = os.path.join(envelope_path, SEAL_FILE)
    seal_kind = file_kind(seal_path)
    if seal_kind != "regular":
        fails.append("the source envelope seal %r is %s, not a regular file"
                     % (seal_path, seal_kind))
        return fails
    try:
        seal_now = sha256_file(seal_path)
    except OSError as e:
        fails.append("the source envelope seal is unreadable: %s: %s"
                     % (type(e).__name__, e))
        return fails
    if seal_now != expect_outer_seal_sha256:
        fails.append("the source envelope's seal is now %s, not the pinned %s"
                     % (str(seal_now)[:16], expect_outer_seal_sha256[:16]))
    try:
        inv_now = inventory_digest({r: v for r, v in typed_inventory(envelope_path).items()
                                    if r not in SELF_FILES})
    except (OSError, EnvelopeError, TypeError, ValueError) as e:
        fails.append("the source envelope typed inventory is unreadable: %s: %s"
                     % (type(e).__name__, e))
        return fails
    if inv_now != expect_envelope_inventory_sha256:
        fails.append("the source envelope's typed inventory is now %s, not the pinned %s"
                     % (inv_now[:16], expect_envelope_inventory_sha256[:16]))
    try:
        spec_now = _source_qualification_spec_sha256(envelope_path)
        if spec_now != expect_authorized_spec_sha256:
            fails.append("the source envelope's qualification specification is now %s, not the "
                         "authorized %s"
                         % (spec_now[:16], expect_authorized_spec_sha256[:16]))
    except (OSError, EnvelopeError, TypeError, ValueError) as e:
        fails.append("the source qualification specification could not be re-derived: %s: %s"
                     % (type(e).__name__, e))
    if doc.get("source_before_digest") != doc.get("source_after_digest"):
        fails.append("the attestation itself records the source changing during verification")
    return fails


def verify_canonical_attestation(package_dir, envelope_path, *,
                                 expect_attestation_sha256=None,
                                 expect_authorized_spec_sha256=None,
                                 expect_gate_inventory_sha256=None,
                                 expect_gate_semantics_sha256=None,
                                 expect_full_binding_sha256=None,
                                 expect_authorization_record_sha256=None,
                                 expect_authorized_root=None,
                                 expect_interpreter_path=None,
                                 expect_interpreter_sha256=None,
                                 expect_outer_seal_sha256=None,
                                 expect_verifier_sha256=None,
                                 expect_bootstrap_sha256=None,
                                 expect_envelope_inventory_sha256=None):
    """The name means what it says: see authenticate_canonical_attestation.

    R5-13 reproduced the previous single-argument version returning [] for a package a caller
    made by hand. A function whose name claims verification must require independent
    expectations; the structure-only view is inspect_canonical_attestation_structure, which can
    never report itself authenticated."""
    return authenticate_canonical_attestation(
        package_dir, envelope_path,
        expect_attestation_sha256=expect_attestation_sha256,
        expect_authorized_spec_sha256=expect_authorized_spec_sha256,
        expect_gate_inventory_sha256=expect_gate_inventory_sha256,
        expect_gate_semantics_sha256=expect_gate_semantics_sha256,
        expect_full_binding_sha256=expect_full_binding_sha256,
        expect_authorization_record_sha256=expect_authorization_record_sha256,
        expect_authorized_root=expect_authorized_root,
        expect_interpreter_path=expect_interpreter_path,
        expect_interpreter_sha256=expect_interpreter_sha256,
        expect_outer_seal_sha256=expect_outer_seal_sha256,
        expect_verifier_sha256=expect_verifier_sha256,
        expect_bootstrap_sha256=expect_bootstrap_sha256,
        expect_envelope_inventory_sha256=expect_envelope_inventory_sha256)
