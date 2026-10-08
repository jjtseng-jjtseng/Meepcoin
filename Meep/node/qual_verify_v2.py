#!/usr/bin/env python3
"""Prospective qualification verifier v2: sterile relocated verification (the authorised G17).

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE. A checker: it launches nothing scientific and renders no
verdict. This is NOT node/cadence_qualify.py, which stays as CADENCEQ v1 history.

THREAT MODEL AND ROOT OF TRUST -- see node/qual_runner_v2.py for the project-wide statement. In
brief: the local orchestrator that calls this module, the pinned Python interpreter and the
EXTERNALLY SUPPLIED bootstrap digest are the root of trust. The envelope, its seal, its role
metadata, its bundled verifier, that verifier's output and any sidecar are untrusted until checked.

WHAT THE FIRST AND THIRD CORRECTIVE AUDITS REPRODUCED

  no bundled source / verifier traversal / copy laundering; then a missing outer-seal pin that
  fell back to the object under verification, and a self-declared bundled verifier that was
  imported and trusted. See the git history of this file.

WHAT THE FOURTH CORRECTIVE AUDIT REPRODUCED (R4-5, R4-6, R4-7, R4-8)

  R4-5  `runner=` is a PRODUCTION parameter. A stub that never started a child and returned exit 0
        with stdout "[]" produced passed=true and g17_pass=true, with child_provenance null. The
        bootstrap authenticated BYTES; nothing proved those bytes ever executed.
  R4-6  `child_prelude=` is a PRODUCTION parameter, and it is executable code AHEAD of the
        verifier. A prelude of `print("[]"); sys.exit(0)` produced g17_pass=true from a real child
        that never imported the bundled verifier at all.
  R4-7  `bootstrap_identity()` hashed the CURRENT qual_verify_v2.py and evidence_envelope.py and
        merely reported those hashes. relocate_and_verify accepted no bootstrap expectation and
        compared nothing. Self-reporting is not authentication.
  R4-8  a canonical attestation could be published from a caller dictionary that never came from
        a relocation at all.

WHAT NOW HOLDS

  THREE MANDATORY EXTERNAL PINS   the outer seal, the bundled verifier and the BOOTSTRAP CLOSURE
      (this file plus evidence_envelope.py, as one digest over an enumerated list). The bootstrap
      is compared against the external expectation BEFORE it is trusted to authenticate anything.
  NO INJECTION IN THE DECISION PATH   `runner=` and `child_prelude=` are gone from
      relocate_and_verify. Exactly one runner-owned subprocess is created, from code this module
      composes, and its argv, interpreter digest, exit status and stdout/stderr digests are
      recorded.
  PROOF OF EXECUTION   the parent generates an unpredictable nonce. The child must echo that nonce
      AND the digest of the file it actually exec'd AND that module's __file__. A child that did
      not run the externally pinned bundled verifier cannot pass, whatever it prints.
  ONE CANONICAL PUBLICATION   the canonical attestation package is written by THIS operation,
      after every check, through evidence_envelope.publish_canonical_attestation.

DIAGNOSTICS ARE A DIFFERENT FUNCTION. `diagnostic_relocate` accepts a runner and a prelude for
tests; it sets diagnostic_only=True, can never set g17_pass and can never publish an attestation.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import evidence_envelope as ENV
import qual_spec as QS
import run_provenance as RP

__all__ = ["VERIFIER_ID", "BOOTSTRAP_ID", "RESULT_SCHEMA", "BOOTSTRAP_FILES",
           "AUTHORIZED_G17_ROLE", "bootstrap_identity", "bootstrap_closure_digest",
           "bootstrap_authenticate", "inventory", "inventory_diff", "relocate_and_verify",
           "diagnostic_relocate", "CLIRefusal", "parse_cli_args", "main"]

VERIFIER_ID = "meepcoin-qualification-verifier/2"
BOOTSTRAP_ID = "meepcoin-bootstrap-verifier/2"
RESULT_SCHEMA = ENV.RELOCATION_RESULT_SCHEMA
CHILD_PROOF_SCHEMA = "meepcoin-g17-child-proof/1"
# R5-14: g17_pass and canonical publication were reachable with authorized_run=False, no
# specification pin and only the non-authorized role floor. The qualification-gate name and the
# canonical attestation are now reserved for a genuinely authorized context.
AUTHORIZED_G17_ROLE = "outer_verifier"
AUTHORIZED_G17_REQUIREMENTS = (
    "a complete AUTHORIZED specification reopened by qual_spec.bind_authorized",
    "an independently pinned authorization record at the safe path named by that specification",
    "distinct gate-inventory, gate-semantics and full-binding pins",
    "the authorized root, interpreter path/bytes, outer seal, bundled verifier, bootstrap closure "
    "and typed envelope inventory pinned independently",
    "the envelope's qualification_spec role matching the authorized specification bytes",
)

# The bootstrap closure, enumerated explicitly. There is no discovery step: if this list is wrong,
# it is wrong visibly, and the external digest that pins it will not match.
#
# R5-11: run_provenance.CHILD_SHIM_SOURCE is PREPENDED to the child's program, so it executes
# before the bundled verifier is even imported -- and it was not in the pinned closure. A
# mutation of it (including one that answers the proof challenge and exits) left the externally
# pinned digest unchanged. Every project-local byte that runs before or as part of the decision
# is now enumerated here.
BOOTSTRAP_FILES = ("qual_verify_v2.py", "evidence_envelope.py", "qual_spec.py",
                   "run_provenance.py")


def inventory(root):
    """The typed inventory: {relpath: (kind, size, sha256)}, directories included."""
    return ENV.typed_inventory(root)


def inventory_diff(before, after):
    return ENV.inventory_diff(before, after)


def _same(a, b):
    return inventory_diff(a, b) == {"added": [], "removed": [], "changed": []}


def _sha256_text(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def bootstrap_identity():
    """{filename: sha256} for the enumerated bootstrap closure.

    SELF-REPORTED. It is an inventory, not an authentication: R4-7 reproduced exactly that
    confusion. The value only means something once a caller compares
    bootstrap_closure_digest() against a digest reviewed OUTSIDE this repository."""
    return {name: ENV.sha256_file(os.path.join(_HERE, name)) for name in BOOTSTRAP_FILES}


def bootstrap_closure_digest():
    """One digest over the enumerated bootstrap closure, for external pinning."""
    ident = bootstrap_identity()
    payload = "\x1e".join("%s\x1f%s" % (n, ident[n]) for n in sorted(ident))
    return _sha256_text(payload)


def _bootstrap_authenticate_inner(copy_root, expect_outer_seal_sha256,
                                  expect_bundled_verifier_sha256,
                                  expect_inventory_sha256=None, expect_spec_sha256=None,
                                  spec_required_roles=None, authorized_run=False,
                                  bundled_verifier_role="outer_verifier"):
    """The TRUSTED BOOTSTRAP. Returns (verifier_abspath_or_None, failures).

    It reads the copy with json, os and the envelope module's own hashing and typing helpers --
    all of them inside the enumerated bootstrap closure, so the caller pins them. It never imports,
    executes or otherwise trusts anything INSIDE the envelope. Only if it returns no failures may
    the exact bundled verifier it authenticated be executed."""
    fails = []
    seal_p = os.path.join(copy_root, ENV.SEAL_FILE)
    sums_p = os.path.join(copy_root, ENV.SUMS_FILE)

    if not ENV._is_hex64(expect_outer_seal_sha256 or ""):
        return None, ["the bootstrap requires an external expect_outer_seal_sha256; the excluded "
                      "seal cannot authenticate itself and no value may be derived from the "
                      "object under verification"]
    if not ENV._is_hex64(expect_bundled_verifier_sha256 or ""):
        return None, ["the bootstrap requires an external expect_bundled_verifier_sha256; a "
                      "self-declared role digest is not a trust root"]
    if ENV.file_kind(seal_p) != "regular":
        return None, ["the relocated copy has no regular %s" % ENV.SEAL_FILE]
    got_seal = ENV.sha256_file(seal_p)
    if got_seal != expect_outer_seal_sha256:
        return None, ["the copy's outer seal %s != the externally pinned %s"
                      % (got_seal[:16], expect_outer_seal_sha256[:16])]
    try:
        seal = json.load(open(seal_p, encoding="utf-8"))
    except Exception as e:
        return None, ["the relocated seal is unreadable: %s: %s" % (type(e).__name__, e)]
    if not isinstance(seal, dict):
        return None, ["the relocated seal is %s, not an object" % type(seal).__name__]
    if seal.get("schema") != ENV.SCHEMA or seal.get("final") is not True:
        fails.append("the seal does not declare the expected schema and finality")

    # ---- the checksum chain, recomputed ----
    if ENV.file_kind(sums_p) != "regular":
        return None, fails + ["the relocated copy has no regular %s" % ENV.SUMS_FILE]
    if ENV.sha256_file(sums_p) != seal.get("sums_sha256"):
        fails.append("%s does not hash to the digest the seal names" % ENV.SUMS_FILE)
    try:
        with open(sums_p, encoding="utf-8", errors="strict") as sums_stream:
            sum_lines = list(sums_stream)
    except (OSError, UnicodeError, ValueError) as e:
        return None, fails + ["the relocated checksum list is unreadable: %s: %s"
                              % (type(e).__name__, e)]
    listed = {}
    for ln in sum_lines:
        ln = ln.rstrip("\n")
        if not ln:
            continue
        parts = ln.split("  ")
        if len(parts) != 3 or not ENV._is_hex64(parts[0]) or not parts[1].isdigit():
            fails.append("malformed checksum line %r" % ln[:60])
            continue
        if parts[2] in listed:
            fails.append("duplicate checksum entry %r" % parts[2])
        try:
            size = int(parts[1])
        except (ValueError, OverflowError) as e:
            fails.append("checksum size for %r is not a bounded integer: %s: %s"
                         % (parts[2], type(e).__name__, e))
            continue
        listed[parts[2]] = (parts[0], size)

    graph = ENV.walk_typed(copy_root)
    unsafe = sorted((r, k) for r, k in graph.items() if k not in ENV.SAFE_KINDS)
    if unsafe:
        fails.append("unrepresentable object(s) in the copy: %s" % unsafe[:4])
    present = [r for r, k in sorted(graph.items())
               if k == "regular" and r not in ENV.SELF_FILES]
    if sorted(present) != sorted(listed):
        fails.append("the copy's regular files do not equal the checksum list: extra=%s missing=%s"
                     % (sorted(set(present) - set(listed))[:4],
                        sorted(set(listed) - set(present))[:4]))
    for rel in sorted(set(present) & set(listed)):
        full = os.path.join(copy_root, rel.replace("/", os.sep))
        if ENV.sha256_file(full) != listed[rel][0]:
            fails.append("listed member %r does not match its digest" % rel)

    # ---- the typed inventory, directories included ----
    inv = {r: v for r, v in ENV.typed_inventory(copy_root).items() if r not in ENV.SELF_FILES}
    got_inv = ENV.inventory_digest(inv)
    if seal.get("typed_inventory_sha256") != got_inv:
        fails.append("the copy's typed inventory %s != the digest the seal recorded (%s)"
                     % (got_inv[:16], str(seal.get("typed_inventory_sha256"))[:16]))
    if expect_inventory_sha256 is not None and got_inv != expect_inventory_sha256:
        fails.append("the copy's typed inventory %s != the externally pinned %s"
                     % (got_inv[:16], expect_inventory_sha256[:16]))

    # ---- COMPLETE role metadata, against the union floor ----
    roles = seal.get("roles") if isinstance(seal.get("roles"), dict) else {}
    seal_required_roles = seal.get("required_roles")
    if (not isinstance(seal_required_roles, list)
            or any(not isinstance(role, str) for role in seal_required_roles)):
        fails.append("the seal's required_roles must be a list of role-name strings")
        seal_required_roles = []
    elif len(seal_required_roles) != len(set(seal_required_roles)):
        fails.append("the seal's required_roles contains duplicate role names")
    unknown_required = sorted(set(seal_required_roles) - set(ENV.ROLES))
    if unknown_required:
        fails.append("the seal's required_roles contains unknown roles: %s"
                     % unknown_required)
    need = ENV.effective_required_roles(seal_roles=seal_required_roles,
                                        spec_roles=spec_required_roles,
                                        authorized_run=authorized_run)
    for r in need:
        if r not in roles:
            fails.append("required role %r is not bound" % r)
    for role, e in sorted(roles.items()):
        if role not in ENV.ROLES or not isinstance(e, dict):
            fails.append("role %r is unknown or malformed" % role)
            continue
        rel = e.get("relpath")
        why = ENV.unsafe_relpath_reason(rel) if isinstance(rel, str) else "no relpath"
        if why:
            fails.append("role %r: %s" % (role, why))
            continue
        full = os.path.join(copy_root, rel.replace("/", os.sep))
        if not ENV.contained_in(copy_root, full):
            fails.append("role %r resolves outside the copy" % role)
            continue
        if e.get("is_dir"):
            if ENV.file_kind(full) != "directory":
                fails.append("role %r is not a directory in the copy" % role)
            elif ENV.sha256_tree(full) != e.get("sha256"):
                fails.append("role %r tree digest disagrees with its metadata" % role)
        else:
            if ENV.file_kind(full) != "regular":
                fails.append("role %r is %s, not a regular file" % (role, ENV.file_kind(full)))
            elif ENV.sha256_file(full) != e.get("sha256"):
                fails.append("role %r digest disagrees with its metadata" % role)

    # ---- the bound specification's bytes, BEFORE its role list means anything ----
    if expect_spec_sha256 is not None:
        srel = (roles.get("qualification_spec") or {}).get("relpath")
        sp = os.path.join(copy_root, srel.replace("/", os.sep)) if isinstance(srel, str) else None
        if not sp or ENV.file_kind(sp) != "regular":
            fails.append("the bound qualification spec could not be read from the copy")
        elif ENV.sha256_file(sp) != expect_spec_sha256:
            fails.append("the bound qualification spec %s != the externally pinned %s"
                         % (ENV.sha256_file(sp)[:16], expect_spec_sha256[:16]))
    elif authorized_run:
        fails.append("an authorized run must pin the bound specification's bytes externally")

    # ---- the bundled verifier: path safety, containment, TYPE, and EXTERNALLY pinned bytes ----
    role = roles.get(bundled_verifier_role)
    if not isinstance(role, dict):
        return None, fails + ["G17 requires a bundled verifier: role %r is not bound"
                              % bundled_verifier_role]
    rel = role.get("relpath")
    why = ENV.unsafe_relpath_reason(rel) if isinstance(rel, str) else "no relpath"
    if why:
        return None, fails + ["bundled verifier path is unsafe: %s" % why]
    verifier_abs = os.path.join(copy_root, rel.replace("/", os.sep))
    if not ENV.contained_in(copy_root, verifier_abs):
        return None, fails + ["the bundled verifier resolves outside the relocated copy"]
    if ENV.file_kind(verifier_abs) != "regular":
        return None, fails + ["the bundled verifier is %s, not a regular file"
                              % ENV.file_kind(verifier_abs)]
    if rel not in listed:
        fails.append("the bundled verifier %r is not in the checksum list" % rel)
    got = ENV.sha256_file(verifier_abs)
    if got != role.get("sha256"):
        fails.append("the bundled verifier hashes to %s but its role declares %s"
                     % (got[:16], str(role.get("sha256"))[:16]))
    if got != expect_bundled_verifier_sha256:
        return None, fails + [
            "the bundled verifier hashes to %s but the EXTERNAL pin is %s; a self-declared role "
            "digest is not a trust root, and this file will not be executed"
            % (got[:16], expect_bundled_verifier_sha256[:16])]
    if fails:
        return None, fails
    return verifier_abs, []


def bootstrap_authenticate(copy_root, expect_outer_seal_sha256,
                           expect_bundled_verifier_sha256,
                           expect_inventory_sha256=None, expect_spec_sha256=None,
                           spec_required_roles=None, authorized_run=False,
                           bundled_verifier_role="outer_verifier"):
    """Total fail-closed boundary over every untrusted byte in a relocated envelope.

    External hashes authenticate byte identity, not JSON/schema validity.  A pinned malformed
    seal, checksum list, role object, or oversized number therefore becomes a deterministic
    bootstrap failure and never a Python traceback or child launch.
    """
    try:
        return _bootstrap_authenticate_inner(
            copy_root, expect_outer_seal_sha256, expect_bundled_verifier_sha256,
            expect_inventory_sha256=expect_inventory_sha256,
            expect_spec_sha256=expect_spec_sha256,
            spec_required_roles=spec_required_roles, authorized_run=authorized_run,
            bundled_verifier_role=bundled_verifier_role)
    except Exception as e:
        return None, ["the relocated bootstrap input is malformed: %s: %s"
                      % (type(e).__name__, e)]


def sterile_env(pycache_dir, home_dir, extra=None):
    keep = ("PATH", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "WSLENV")
    e = {k: v for k, v in os.environ.items() if k in keep}
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    e["PYTHONPYCACHEPREFIX"] = pycache_dir
    e["PYTHONNOUSERSITE"] = "1"
    e["PYTHONHASHSEED"] = "0"
    e["HOME"] = home_dir
    e["USERPROFILE"] = home_dir
    e["PYTHONPATH"] = ""
    if extra:
        e.update(extra)
    return e


def _fail(res, msg):
    res["failures"].append(msg)
    return res


def _child_program(verifier_abs, reloc, expect_inner_seal, expect_spec_sha256,
                   expect_trace_status, expect_outer_seal_sha256, spec_required_roles):
    """The exact program the child runs. Composed here; nothing is injected in front of it.

    The child must prove it executed THE FILE WE AUTHENTICATED: it echoes the parent's nonce, the
    digest of the file it exec'd and that module's own __file__."""
    return (
        "import hashlib, json, os, sys\n"
        "sys.dont_write_bytecode = True\n"
        "import importlib.util as _u\n"
        "_p = %r\n"
        "_s = _u.spec_from_file_location('bundled_envelope', _p)\n"
        "_m = _u.module_from_spec(_s); _s.loader.exec_module(_m)\n"
        "_d = hashlib.sha256(open(_p, 'rb').read()).hexdigest()\n"
        "_f = _m.verify_envelope(%r, expect_inner_seal=%r, expect_spec_sha256=%r,"
        " expect_trace_status=%r, expect_outer_seal_sha256=%r, spec_required_roles=%r,"
        " authorized_run=True, decision_gate=True)\n"
        "print(json.dumps({'schema': %r, 'nonce': os.environ.get('MEEPCOIN_CHILD_NONCE'), "
        "'verifier_sha256': _d,"
        " 'module_file': getattr(_m, '__file__', None), 'failures': _f}))\n"
        % (verifier_abs, reloc, expect_inner_seal,
           expect_spec_sha256, expect_trace_status, expect_outer_seal_sha256,
           list(spec_required_roles or []), CHILD_PROOF_SCHEMA))


def _new_result(envelope_path, workspace, expectations, diagnostic):
    return {
        "schema": RESULT_SCHEMA, "verifier": VERIFIER_ID, "bootstrap": BOOTSTRAP_ID,
        "non_evidence": True,
        "source_envelope": envelope_path, "relocated_to": None, "verified_with": None,
        "verifier_source_sha256": None, "cwd_during_verification": None,
        "bootstrap_identity": bootstrap_identity(),
        "bootstrap_closure_sha256": bootstrap_closure_digest(),
        "bootstrap_pin_checked": False, "bootstrap_verified": False, "bootstrap_failures": [],
        "expectations": dict(expectations),
        "external_outer_seal_sha256": expectations.get("outer_seal_sha256"),
        "source_observed_outer_seal_sha256": None,
        "verified_copy_outer_seal_sha256": None,
        "source_before_digest": None, "source_after_digest": None, "source_stable": False,
        "byte_identical_before_and_after": False, "four_point_identity": False,
        "inventory_diff": None, "file_count": None, "object_count": None,
        "child_record": None, "child_execution_proof": None,
        "child_sidecar_failures": [], "child_sidecar_validated": False,
        "interpreter_path": None, "interpreter_pin_checked": False,
        "interpreter_failures": [],
        "authorization_verified": False, "authorization_failures": [],
        "authorization_binding": None, "authorized_context": False,
        "authorized_context_requirements": list(AUTHORIZED_G17_REQUIREMENTS),
        "g17_pass": False, "diagnostic_only": bool(diagnostic),
        "attestation_package": None, "attestation_sha256": None,
        "attestation_publication_error": None,
        "passed": False, "failures": [], "seconds": None,
        "limitation": ("-B and PYTHONDONTWRITEBYTECODE prevent bytecode from being WRITTEN; "
                       "neither proves a pre-existing valid cache was not READ. The four-point "
                       "TYPED inventory, directories and file type included, is what proves this "
                       "run created nothing and changed nothing."),
    }


def _pinned_interpreter(expect_path, expect_sha256):
    """(abspath, failures). The runtime that executes the authenticated verifier is itself an
    externally pinned, type-checked, re-hashed input (R5-12)."""
    f = []
    if not isinstance(expect_path, str) or not expect_path or "\x00" in expect_path:
        return None, ["expect_interpreter_path is mandatory: the runtime that executes the "
                      "bundled verifier must be a NUL-free canonical path and cannot be "
                      "self-reported"]
    if not os.path.isabs(expect_path):
        return None, ["the pinned interpreter path %r is relative" % expect_path]
    try:
        normalized = os.path.normpath(expect_path)
    except (OSError, TypeError, ValueError) as e:
        return None, ["the pinned interpreter path cannot be resolved safely: %s: %s"
                      % (type(e).__name__, e)]
    if os.path.normcase(expect_path) != os.path.normcase(normalized):
        return None, ["the pinned interpreter path %r is not in canonical lexical form; use %r"
                      % (expect_path, normalized)]
    kind = ENV.file_kind(expect_path)
    if kind != "regular":
        return None, ["the pinned interpreter %r is %s, not a regular file" % (expect_path, kind)]
    real = os.path.realpath(expect_path)
    if os.path.normcase(real) != os.path.normcase(os.path.abspath(expect_path)):
        return None, ["the pinned interpreter %r is an alias for %r" % (expect_path, real)]
    if not ENV._is_hex64(expect_sha256 or ""):
        return None, ["expect_interpreter_sha256 must be 64 lowercase hex characters"]
    got = ENV.sha256_file(expect_path)
    if got != expect_sha256:
        f.append("the pinned interpreter %r hashes to %s, not the externally pinned %s"
                 % (expect_path, got[:16], str(expect_sha256)[:16]))
    return (None if f else os.path.abspath(expect_path)), f


def _relocate(envelope_path, workspace, *, spec_path, expect_spec_sha256,
              expect_gate_inventory_sha256, expect_gate_semantics_sha256,
              expect_full_binding_sha256, authorization_path,
              expect_authorization_record_sha256, authorized_root,
              expect_interpreter_path, expect_interpreter_sha256,
              expect_outer_seal_sha256, expect_bundled_verifier_sha256,
              expect_bootstrap_sha256, expect_envelope_inventory_sha256,
              expect_inner_seal, expect_trace_status, require_same_device, timeout,
              runner, child_prelude, diagnostic, attestation_package,
              diagnostic_spec_required_roles=None,
              diagnostic_bundled_verifier_role=AUTHORIZED_G17_ROLE):
    for path_name, path_value in (("envelope_path", envelope_path),
                                  ("workspace", workspace)):
        invalid = (not isinstance(path_value, str) or not path_value
                   or "\x00" in path_value or not os.path.isabs(path_value))
        if not invalid:
            try:
                invalid = (os.path.normcase(os.path.normpath(path_value)) !=
                           os.path.normcase(path_value))
            except (OSError, TypeError, ValueError):
                invalid = True
        if invalid:
            result = _new_result(
                envelope_path if isinstance(envelope_path, str) else None,
                workspace if isinstance(workspace, str) else None,
                {}, diagnostic)
            return _fail(result, "%s must be a NUL-free canonical absolute path"
                         % path_name)
    envelope_path = os.path.abspath(envelope_path)
    workspace = os.path.abspath(workspace)
    expectations = {"inner_seal": expect_inner_seal, "trace_status": expect_trace_status,
                    "authorized_spec_sha256": expect_spec_sha256,
                    "gate_inventory_sha256": expect_gate_inventory_sha256,
                    "gate_semantics_sha256": expect_gate_semantics_sha256,
                    "full_binding_sha256": expect_full_binding_sha256,
                    "authorization_record_sha256": expect_authorization_record_sha256,
                    "authorized_root": (os.path.abspath(authorized_root)
                                        if isinstance(authorized_root, str) else authorized_root),
                    "interpreter_path": expect_interpreter_path,
                    "interpreter_sha256": expect_interpreter_sha256,
                    "outer_seal_sha256": expect_outer_seal_sha256,
                    "bundled_verifier_sha256": expect_bundled_verifier_sha256,
                    "bootstrap_closure_sha256": expect_bootstrap_sha256,
                    "envelope_typed_inventory_sha256": expect_envelope_inventory_sha256}
    res = _new_result(envelope_path, workspace, expectations, diagnostic)
    started = time.time()

    bound_spec = None
    if not diagnostic:
        if (not isinstance(attestation_package, str) or not attestation_package
                or "\x00" in attestation_package or not os.path.isabs(attestation_package)):
            return _fail(
                res, "attestation_package is mandatory for production G17 and must be a "
                "NUL-free canonical absolute path supplied independently")
        try:
            if os.path.normcase(os.path.normpath(attestation_package)) != \
                    os.path.normcase(attestation_package):
                return _fail(res, "attestation_package is not in canonical lexical form: %r"
                                  % attestation_package)
        except (OSError, TypeError, ValueError) as e:
            return _fail(res, "attestation_package cannot be resolved safely: %s: %s"
                              % (type(e).__name__, e))
        if os.path.basename(attestation_package) != ENV.CANONICAL_ATTESTATION_DIR:
            return _fail(res, "attestation_package must use the canonical basename %r"
                              % ENV.CANONICAL_ATTESTATION_DIR)
        for name, val in (("expect_spec_sha256", expect_spec_sha256),
                          ("expect_gate_inventory_sha256", expect_gate_inventory_sha256),
                          ("expect_gate_semantics_sha256", expect_gate_semantics_sha256),
                          ("expect_full_binding_sha256", expect_full_binding_sha256),
                          ("expect_authorization_record_sha256",
                           expect_authorization_record_sha256),
                          ("expect_interpreter_sha256", expect_interpreter_sha256),
                          ("expect_outer_seal_sha256", expect_outer_seal_sha256),
                          ("expect_bundled_verifier_sha256", expect_bundled_verifier_sha256),
                          ("expect_bootstrap_sha256", expect_bootstrap_sha256),
                          ("expect_envelope_inventory_sha256",
                           expect_envelope_inventory_sha256)):
            if not ENV._is_hex64(val or ""):
                return _fail(res, "%s is mandatory and must be 64 lowercase hex characters "
                                  "supplied from outside the envelope; there is no fallback"
                                  % name)
        for name, val in (("spec_path", spec_path), ("authorization_path", authorization_path),
                          ("authorized_root", authorized_root),
                          ("expect_interpreter_path", expect_interpreter_path)):
            if (not isinstance(val, str) or not val or "\x00" in val
                    or not os.path.isabs(val)):
                return _fail(res, "%s is mandatory and must be a canonical absolute path "
                                  "supplied independently" % name)
            try:
                if os.path.normcase(os.path.normpath(val)) != os.path.normcase(val):
                    return _fail(res, "%s is not in canonical lexical form: %r" % (name, val))
                if name == "authorized_root" and os.path.normcase(os.path.realpath(val)) != \
                        os.path.normcase(os.path.abspath(val)):
                    return _fail(res, "authorized_root is an alias rather than the canonical "
                                      "directory: %r" % val)
            except (OSError, TypeError, ValueError) as e:
                return _fail(res, "%s cannot be resolved as a canonical path: %s: %s"
                                  % (name, type(e).__name__, e))
        # ---- (0) the BOOTSTRAP itself, against an expectation reviewed outside this repo ----
        actual_boot = res["bootstrap_closure_sha256"]
        res["bootstrap_pin_checked"] = True
        if actual_boot != expect_bootstrap_sha256:
            return _fail(res, "the bootstrap closure %s (%s) != the externally pinned %s; the "
                              "code that would authenticate this envelope is not the code that "
                              "was reviewed" % (actual_boot[:16], list(BOOTSTRAP_FILES),
                                                 expect_bootstrap_sha256[:16]))

        # ---- (0a) the REAL authorization contract, before copy or child creation ----
        try:
            bound_spec = QS.bind_authorized(
                spec_path, expect_spec_sha256, expect_gate_inventory_sha256,
                expect_full_binding_sha256, authorization_path,
                expect_authorization_record_sha256, authorized_root)
        except QS.SpecError as e:
            msg = "authorization bind refused: %s: %s" % (type(e).__name__, e)
            res["authorization_failures"].append(msg)
            return _fail(res, msg)
        auth_fails = []
        if bound_spec.semantics_sha256 != expect_gate_semantics_sha256:
            auth_fails.append("the bound gate semantics %s != the external %s"
                              % (bound_spec.semantics_sha256[:16],
                                 expect_gate_semantics_sha256[:16]))
        auth_fails.extend(QS.authorization_runtime_pin_failures(
            bound_spec, expect_bundled_verifier_sha256=expect_bundled_verifier_sha256,
            expect_bootstrap_sha256=expect_bootstrap_sha256))
        binding = bound_spec.authorization_binding_plain()
        if os.path.normcase(os.path.realpath(binding.get("interpreter_path") or "")) != \
                os.path.normcase(os.path.realpath(expect_interpreter_path)):
            auth_fails.append("the authorization record's interpreter path does not equal the "
                              "externally pinned interpreter path")
        if binding.get("interpreter_sha256") != expect_interpreter_sha256:
            auth_fails.append("the authorization record's interpreter digest does not equal the "
                              "externally pinned interpreter digest")
        if binding.get("authorized_root") != os.path.abspath(authorized_root):
            auth_fails.append("the authorization binding names a different authorized root")
        res["authorization_binding"] = binding
        res["authorization_failures"] = list(auth_fails)
        if auth_fails:
            for f in auth_fails:
                _fail(res, "authorization: %s" % f)
            return res
        res["authorization_verified"] = True
        res["authorized_context"] = True
    else:
        # A diagnostic may omit authorization, but it may not claim to have used this bootstrap
        # unless the bootstrap itself is pinned from outside and matches now.
        if not ENV._is_hex64(expect_bootstrap_sha256 or ""):
            return _fail(res, "expect_bootstrap_sha256 is mandatory even for a diagnostic; the "
                              "code authenticating the envelope cannot authenticate itself")
        res["bootstrap_pin_checked"] = True
        if res["bootstrap_closure_sha256"] != expect_bootstrap_sha256:
            return _fail(res, "the bootstrap closure does not match the external diagnostic pin")

    # These values are DERIVED from a completed bind in production. Diagnostic callers may
    # supply labels so they can exercise structural checks, but those labels can never make an
    # authorization, a G17 pass or a canonical publication.
    spec_required_roles = (list(bound_spec.get("required_envelope_roles") or [])
                           if bound_spec is not None
                           else list(diagnostic_spec_required_roles or []))
    authorized_run = bound_spec is not None
    bundled_verifier_role = (AUTHORIZED_G17_ROLE if bound_spec is not None
                             else diagnostic_bundled_verifier_role)

    if ENV.contained_in(envelope_path, workspace) or workspace == envelope_path:
        return _fail(res, "the relocation workspace must not be inside the envelope")
    bad = ENV.unsafe_objects(envelope_path)
    if bad:
        return _fail(res, "the source envelope contains unrepresentable object(s) %s" % bad[:4])

    # ---- (1) source, BEFORE the copy, against the external pin ----
    src_seal_p = os.path.join(envelope_path, ENV.SEAL_FILE)
    if ENV.file_kind(src_seal_p) != "regular":
        return _fail(res, "the source envelope has no regular %s" % ENV.SEAL_FILE)
    res["source_observed_outer_seal_sha256"] = ENV.sha256_file(src_seal_p)
    if expect_outer_seal_sha256 and \
            res["source_observed_outer_seal_sha256"] != expect_outer_seal_sha256:
        return _fail(res, "the SOURCE seal %s != the externally pinned %s"
                          % (res["source_observed_outer_seal_sha256"][:16],
                             expect_outer_seal_sha256[:16]))
    src_before = inventory(envelope_path)
    res["source_before_digest"] = ENV.inventory_digest(src_before)
    res["file_count"] = sum(1 for v in src_before.values() if v[0] == "regular")
    res["object_count"] = len(src_before)
    if expect_envelope_inventory_sha256 is not None:
        got = ENV.inventory_digest({r: v for r, v in src_before.items()
                                    if r not in ENV.SELF_FILES})
        if got != expect_envelope_inventory_sha256:
            return _fail(res, "the SOURCE typed inventory %s != the externally pinned %s"
                              % (got[:16], expect_envelope_inventory_sha256[:16]))

    reloc = os.path.join(workspace, "relocated_envelope")
    pyc = os.path.join(workspace, "pycache")
    home = os.path.join(workspace, "sterile_home")
    cwd = os.path.join(workspace, "unrelated_cwd")
    for d in (pyc, home, cwd):
        os.makedirs(d, exist_ok=True)
    if os.path.lexists(reloc):
        return _fail(res, "refusing to overwrite an existing relocation target %r" % reloc)
    if require_same_device and os.stat(workspace).st_dev != os.stat(envelope_path).st_dev:
        return _fail(res, "the workspace is on a different device from the envelope")
    shutil.copytree(envelope_path, reloc, symlinks=True)
    res["relocated_to"] = reloc
    res["cwd_during_verification"] = cwd
    leftovers = ENV.unsafe_objects(reloc)
    if leftovers:
        return _fail(res, "unrepresentable object(s) survived into the relocated copy: %s"
                          % leftovers[:4])

    # ---- (2) copy, BEFORE any bundled code runs, against the external pin ----
    copy_before = inventory(reloc)
    copy_seal_p = os.path.join(reloc, ENV.SEAL_FILE)
    res["verified_copy_outer_seal_sha256"] = (
        ENV.sha256_file(copy_seal_p) if ENV.file_kind(copy_seal_p) == "regular" else None)
    if expect_outer_seal_sha256 and \
            res["verified_copy_outer_seal_sha256"] != expect_outer_seal_sha256:
        return _fail(res, "the COPY's seal %s != the externally pinned %s"
                          % (str(res["verified_copy_outer_seal_sha256"])[:16],
                             expect_outer_seal_sha256[:16]))

    # ---- (3) the TRUSTED BOOTSTRAP, before a line of bundled code is executed ----
    verifier_abs, boot_fails = bootstrap_authenticate(
        reloc, expect_outer_seal_sha256, expect_bundled_verifier_sha256,
        expect_inventory_sha256=expect_envelope_inventory_sha256,
        expect_spec_sha256=expect_spec_sha256, spec_required_roles=spec_required_roles,
        authorized_run=authorized_run, bundled_verifier_role=bundled_verifier_role)
    res["bootstrap_failures"] = list(boot_fails)
    res["bootstrap_verified"] = not boot_fails and verifier_abs is not None
    if not res["bootstrap_verified"]:
        for f in boot_fails:
            _fail(res, "bootstrap: %s" % f)
        res["seconds"] = round(time.time() - started, 3)
        return res
    res["verified_with"] = os.path.relpath(verifier_abs, reloc).replace(os.sep, "/")
    res["verifier_source_sha256"] = ENV.sha256_file(verifier_abs)

    # ---- (4) the pinned interpreter, re-read and re-hashed IMMEDIATELY before the child ----
    interp_abs, interp_fails = (None, [])
    diagnostic_interpreter_fallback = bool(diagnostic and not expect_interpreter_path)
    if diagnostic_interpreter_fallback:
        interp_abs = os.path.realpath(sys.executable)   # DIAGNOSTIC ONLY; never a G17 pass
    else:
        interp_abs, interp_fails = _pinned_interpreter(expect_interpreter_path,
                                                       expect_interpreter_sha256)
    res["interpreter_path"] = interp_abs
    res["interpreter_pin_checked"] = bool(not diagnostic_interpreter_fallback
                                           and not interp_fails and interp_abs is not None)
    res["interpreter_failures"] = list(interp_fails)
    if interp_fails:
        for f in interp_fails:
            _fail(res, "interpreter: %s" % f)
        res["seconds"] = round(time.time() - started, 3)
        return res

    # ---- (5) ONE process-owning call, from Popen creation through return and sidecar freeze ----
    sidecar = os.path.join(workspace, "child_provenance.json")
    # The child-side provenance shim is prepended by THIS operation, from this project's own
    # source constant -- it is not a caller seam, and run_provenance.py is inside the externally
    # pinned bootstrap closure, so a mutation of it changes the pin (R5-11).
    child_failures, child_error, proof, record = None, None, None, None
    code = ((child_prelude or "") if diagnostic else RP.CHILD_SHIM_SOURCE) + _child_program(
        verifier_abs, reloc, expect_inner_seal, expect_spec_sha256, expect_trace_status,
        expect_outer_seal_sha256, spec_required_roles)
    argv = [interp_abs, "-I", "-B", "-c", code]
    if diagnostic:
        # Deliberately outside the production observation boundary. An injected diagnostic runner
        # may help test parsing, but it can never mint a child capability or a G17 result.
        try:
            if runner is None:
                raise RuntimeError("diagnostic path stops before process creation unless an "
                                   "explicit diagnostic runner is supplied")
            r = runner(argv, cwd=cwd, env=sterile_env(pyc, home, {}),
                       capture_output=True, timeout=timeout)
            out = r.stdout if isinstance(r.stdout, (bytes, bytearray)) else \
                (r.stdout or "").encode("utf-8", "replace")
            err = r.stderr if isinstance(r.stderr, (bytes, bytearray)) else \
                (r.stderr or "").encode("utf-8", "replace")
            if r.returncode == 0:
                try:
                    proof = json.loads(bytes(out).decode("utf-8").strip().splitlines()[-1])
                except Exception as e:
                    child_error = "diagnostic output was not parseable: %s: %s" % (
                        type(e).__name__, e)
            else:
                child_error = "diagnostic verifier exited %s" % r.returncode
        except Exception as e:
            child_error = "diagnostic %s: %s" % (type(e).__name__, e)
        nonce = None
        sidecar_fails = ["diagnostic execution is permanently non-adoptable"]
    else:
        launch_inputs = {
            os.path.abspath(spec_path): expect_spec_sha256,
            os.path.abspath(authorization_path): expect_authorization_record_sha256,
            os.path.abspath(src_seal_p): expect_outer_seal_sha256,
            os.path.abspath(copy_seal_p): expect_outer_seal_sha256,
            os.path.abspath(verifier_abs): expect_bundled_verifier_sha256,
        }
        # The envelope-bound spec is the same authorized byte string, at a different, relocated
        # path. Bind that exact launch-bearing copy too.
        seal_doc = json.load(open(copy_seal_p, encoding="utf-8"))
        spec_rel = ((seal_doc.get("roles") or {}).get("qualification_spec") or {}).get("relpath")
        if isinstance(spec_rel, str):
            launch_inputs[os.path.abspath(os.path.join(
                reloc, spec_rel.replace("/", os.sep)))] = expect_spec_sha256
        cb = bound_spec.get("collector_binding") or {}
        for rel, digest in [(cb.get("path"), cb.get("sha256"))] + list(
                (cb.get("dependencies") or {}).items()):
            if isinstance(rel, str) and ENV._is_hex64(digest or ""):
                launch_inputs[os.path.abspath(os.path.join(
                    bound_spec.authorized_root, rel.replace("/", os.sep)))] = digest
        for item in (bound_spec.get("evaluators") or {}).values():
            if hasattr(item, "get") and isinstance(item.get("module"), str):
                launch_inputs[os.path.abspath(os.path.join(
                    bound_spec.authorized_root,
                    item["module"].replace("/", os.sep)))] = item.get("sha256")
        try:
            r = RP.run_observed(
                argv, executable=interp_abs, expect_executable_sha256=expect_interpreter_sha256,
                cwd=cwd, root=reloc, expected_inputs=launch_inputs, sidecar_path=sidecar,
                env=sterile_env(pyc, home, {}), timeout=timeout)
            record = r.record
            out, err = r.stdout, r.stderr
            nonce = record.get("nonce")
            sidecar_fails = list(r.sidecar_failures)
            if r.returncode != 0:
                child_error = "bundled verifier exited %s: %s" % (
                    r.returncode, err[:400].decode("utf-8", "replace"))
            else:
                try:
                    proof = json.loads(out.decode("utf-8").strip().splitlines()[-1])
                except Exception as e:
                    child_error = "the child produced no parseable proof line: %s: %s" % (
                        type(e).__name__, e)
        except Exception as e:
            nonce = None
            sidecar_fails = ["process observation refused: %s: %s" % (type(e).__name__, e)]
            child_error = sidecar_fails[0]

    # ---- (5) the proof of execution: did the pinned bytes actually run? ----
    proof_fails = []
    if isinstance(proof, dict):
        if proof.get("schema") != CHILD_PROOF_SCHEMA:
            proof_fails.append("the child's proof carries schema %r, not %r"
                               % (proof.get("schema"), CHILD_PROOF_SCHEMA))
        if proof.get("nonce") != nonce:
            proof_fails.append("the child did not echo this run's nonce")
        if proof.get("verifier_sha256") != expect_bundled_verifier_sha256:
            proof_fails.append("the child reports it executed %s, not the externally pinned %s"
                               % (str(proof.get("verifier_sha256"))[:16],
                                  str(expect_bundled_verifier_sha256)[:16]))
        mf = proof.get("module_file")
        if not isinstance(mf, str) or ENV._norm(mf) != ENV._norm(verifier_abs):
            proof_fails.append("the module the child loaded was %r, not the authenticated "
                               "bundled verifier" % (mf,))
        if not isinstance(proof.get("failures"), list):
            proof_fails.append("the child's failure list is not a list")
        else:
            child_failures = proof["failures"]
    elif not child_error:
        proof_fails.append("the child returned no proof object at all")
    semantic_execution_ok = bool(record and record.get("execution_proof_ok")
                                 and not proof_fails and child_error is None)
    proof_doc = proof if isinstance(proof, dict) else {}
    # The generic record is immutable after run_observed. The semantic verifier proof is a
    # separate conjunct; callers may not rewrite execution_proof_ok after completion.
    res["child_sidecar_failures"] = list(sidecar_fails)
    res["child_sidecar_validated"] = bool(record and not sidecar_fails)
    for f in sidecar_fails:
        _fail(res, "child provenance: %s" % f)
    res["child_record"] = record
    res["child_execution_proof"] = {"nonce_echoed": bool(proof_doc)
                                    and proof_doc.get("nonce") == nonce,
                                    "verifier_sha256_reported": proof_doc.get(
                                        "verifier_sha256"),
                                    "module_file_reported": proof_doc.get("module_file"),
                                    "ok": semantic_execution_ok,
                                    "failures": proof_fails}

    # ---- (6) copy after, and (7) source after ----
    copy_after = inventory(reloc)
    src_after = inventory(envelope_path)
    res["source_after_digest"] = ENV.inventory_digest(src_after)
    res["inventory_diff"] = {
        "copy_before_vs_after": inventory_diff(copy_before, copy_after),
        "source_before_vs_after": inventory_diff(src_before, src_after),
        "source_before_vs_copy_before": inventory_diff(src_before, copy_before),
        "copy_after_vs_source_after": inventory_diff(copy_after, src_after),
    }
    four = (_same(src_before, copy_before) and _same(copy_before, copy_after)
            and _same(copy_after, src_after))
    res["four_point_identity"] = four
    res["byte_identical_before_and_after"] = _same(copy_before, copy_after)
    res["source_stable"] = (_same(src_before, src_after)
                            and res["source_before_digest"] == res["source_after_digest"])
    if expect_outer_seal_sha256:
        for label, p in (("source", src_seal_p), ("copy", copy_seal_p)):
            now = ENV.sha256_file(p) if ENV.file_kind(p) == "regular" else None
            if now != expect_outer_seal_sha256:
                _fail(res, "after verification the %s seal is %s, not the externally pinned %s"
                           % (label, str(now)[:16], expect_outer_seal_sha256[:16]))

    if child_error:
        _fail(res, "relocated verification could not run: %s" % child_error)
    for f in proof_fails:
        _fail(res, "proof of execution: %s" % f)
    for f in (child_failures or []):
        res["failures"].append("envelope: %s" % f)
    if not four:
        _fail(res, "four-point typed identity failed: %s" % res["inventory_diff"])
    if not res["source_stable"]:
        _fail(res, "the SOURCE envelope changed across verification")
    stray = [r for r in copy_after if r.endswith(".pyc") or "__pycache__" in r]
    if stray:
        _fail(res, "bytecode was created inside the relocated envelope: %s" % stray)

    authorized_context = bool(res.get("authorization_verified") and bound_spec is not None
                              and not diagnostic)
    res["authorized_context"] = authorized_context
    res["authorized_context_requirements"] = list(AUTHORIZED_G17_REQUIREMENTS)
    res["passed"] = not res["failures"]
    res["g17_pass"] = bool(res["passed"] and res["bootstrap_verified"]
                           and res["bootstrap_pin_checked"]
                           and res.get("interpreter_pin_checked")
                           and res.get("child_sidecar_validated")
                           and semantic_execution_ok
                           and authorized_context and not diagnostic)
    if res["passed"] and not authorized_context and not diagnostic:
        res["g17_note"] = ("INTEGRITY RESULT, NOT A QUALIFICATION GATE. Every integrity check "
                           "passed, but this call did not supply an authorized context (%s), so "
                           "it cannot be named G17 and cannot publish a canonical attestation."
                           % ", ".join(AUTHORIZED_G17_REQUIREMENTS))
    if diagnostic:
        res["g17_note"] = ("DIAGNOSTIC. This call accepted an injected runner and/or an injected "
                           "prelude, so nothing here can satisfy G17 or publish an attestation.")
    res["seconds"] = round(time.time() - started, 3)

    # ---- (8) the canonical attestation, published by THIS operation ----
    if attestation_package and res["g17_pass"]:
        res["attestation_package"] = attestation_package
        # The digest published here is the TRUST ANCHOR a later authentication needs. Retain it
        # outside the package: the package cannot authenticate itself (R5-13).
        #
        # A failure anywhere in publication is reported as a failure of THIS result rather than
        # thrown at the caller: the run happened, the child was observed, and the operator needs
        # a document that says publication did not complete -- not a traceback that loses both.
        try:
            ENV.publish_canonical_attestation(
                envelope_path, attestation_package, res, VERIFIER_ID,
                expect_authorized_spec_sha256=expect_spec_sha256,
                expect_gate_inventory_sha256=expect_gate_inventory_sha256,
                expect_gate_semantics_sha256=expect_gate_semantics_sha256,
                expect_full_binding_sha256=expect_full_binding_sha256,
                expect_authorization_record_sha256=expect_authorization_record_sha256,
                expect_authorized_root=os.path.abspath(authorized_root),
                expect_interpreter_path=expect_interpreter_path,
                expect_interpreter_sha256=expect_interpreter_sha256,
                expect_outer_seal_sha256=expect_outer_seal_sha256,
                expect_verifier_sha256=expect_bundled_verifier_sha256,
                expect_bootstrap_sha256=expect_bootstrap_sha256,
                expect_envelope_inventory_sha256=expect_envelope_inventory_sha256,
                token=ENV._CANONICAL_TOKEN)
            res["attestation_sha256"] = ENV.sha256_file(
                os.path.join(res["attestation_package"], ENV.CANONICAL_ATTESTATION_NAME))
            res["attestation_anchor_note"] = ENV.ATTESTATION_AUTHENTICATION_LIMIT
        except BaseException as e:
            res["attestation_package"] = None
            res["attestation_publication_error"] = "%s: %s" % (type(e).__name__, e)
            _fail(res, "the canonical attestation was NOT published: %s: %s"
                       % (type(e).__name__, e))
            res["g17_pass"] = False
    elif attestation_package:
        _fail(res, "no canonical attestation was published: this run did not pass G17 in an "
                   "authorized context")
    # Publication is part of the requested operation.  A publication refusal is therefore a
    # failure of the returned operation even when every preceding relocation check passed.  Keep
    # this derived field synchronized with the final failure list instead of leaving the pre-
    # publication value from line 770 in place (R6 reviewer finding).
    res["passed"] = not res["failures"]
    return res


def relocate_and_verify(envelope_path, workspace, *, spec_path=None, expect_spec_sha256=None,
                        expect_gate_inventory_sha256=None,
                        expect_gate_semantics_sha256=None,
                        expect_full_binding_sha256=None, authorization_path=None,
                        expect_authorization_record_sha256=None, authorized_root=None,
                        expect_interpreter_path=None, expect_interpreter_sha256=None,
                        expect_outer_seal_sha256=None,
                        expect_bundled_verifier_sha256=None,
                        expect_bootstrap_sha256=None,
                        expect_envelope_inventory_sha256=None,
                        expect_inner_seal=None, expect_trace_status=None,
                        require_same_device=True, timeout=600, attestation_package=None):
    """THE PRODUCTION G17 VERIFIER: paths plus complete independent authorization/runtime pins.

    This function reopens the specification and separate authorization record through
    qual_spec.bind_authorized before copying an envelope or creating a child. It accepts no
    authorization Boolean, role label, runner, prelude, clock, Popen or process result. Ordinary
    missing pins return a structured refusal rather than falling through to a traceback.
    """
    return _relocate(
        envelope_path, workspace, spec_path=spec_path, expect_spec_sha256=expect_spec_sha256,
        expect_gate_inventory_sha256=expect_gate_inventory_sha256,
        expect_gate_semantics_sha256=expect_gate_semantics_sha256,
        expect_full_binding_sha256=expect_full_binding_sha256,
        authorization_path=authorization_path,
        expect_authorization_record_sha256=expect_authorization_record_sha256,
        authorized_root=authorized_root, expect_interpreter_path=expect_interpreter_path,
        expect_interpreter_sha256=expect_interpreter_sha256,
        expect_outer_seal_sha256=expect_outer_seal_sha256,
        expect_bundled_verifier_sha256=expect_bundled_verifier_sha256,
        expect_bootstrap_sha256=expect_bootstrap_sha256,
        expect_envelope_inventory_sha256=expect_envelope_inventory_sha256,
        expect_inner_seal=expect_inner_seal, expect_trace_status=expect_trace_status,
        require_same_device=require_same_device, timeout=timeout, runner=None, child_prelude="",
        diagnostic=False, attestation_package=attestation_package)


def diagnostic_relocate(envelope_path, workspace, expect_outer_seal_sha256=None,
                        expect_bundled_verifier_sha256=None, expect_bootstrap_sha256=None,
                        runner=None, child_prelude="", **kw):
    """DIAGNOSTIC ONLY. Accepts an injected runner and an injected prelude for tests.

    It sets diagnostic_only=True, can never set g17_pass, and refuses to publish an attestation.
    R4-5 and R4-6 exist because these two seams were in the production signature."""
    kw.pop("attestation_package", None)
    # Old diagnostic spellings are accepted only here. They are annotations, never authority.
    inv = kw.pop("expect_envelope_inventory_sha256",
                 kw.pop("expect_inventory_sha256", None))
    roles = kw.pop("spec_required_roles", None)
    kw.pop("authorized_run", None)
    role = kw.pop("bundled_verifier_role", AUTHORIZED_G17_ROLE)
    return _relocate(
        envelope_path, workspace, spec_path=None,
        expect_spec_sha256=kw.pop("expect_spec_sha256", None),
        expect_gate_inventory_sha256=None, expect_gate_semantics_sha256=None,
        expect_full_binding_sha256=None, authorization_path=None,
        expect_authorization_record_sha256=None, authorized_root=None,
        expect_interpreter_path=kw.pop("expect_interpreter_path", None),
        expect_interpreter_sha256=kw.pop("expect_interpreter_sha256", None),
        expect_outer_seal_sha256=expect_outer_seal_sha256,
        expect_bundled_verifier_sha256=expect_bundled_verifier_sha256,
        expect_bootstrap_sha256=expect_bootstrap_sha256,
        expect_envelope_inventory_sha256=inv,
        expect_inner_seal=kw.pop("expect_inner_seal", None),
        expect_trace_status=kw.pop("expect_trace_status", None),
        require_same_device=kw.pop("require_same_device", True),
        timeout=kw.pop("timeout", 600), runner=runner, child_prelude=child_prelude,
        diagnostic=True, attestation_package=None,
        diagnostic_spec_required_roles=roles, diagnostic_bundled_verifier_role=role)


class CLIRefusal(ValueError):
    """An ordinary command-line refusal. main() renders it without a traceback."""


_CLI_REQUIRED = {
    "--spec": "spec_path",
    "--spec-sha256": "expect_spec_sha256",
    "--gate-inventory-sha256": "expect_gate_inventory_sha256",
    "--gate-semantics-sha256": "expect_gate_semantics_sha256",
    "--full-binding-sha256": "expect_full_binding_sha256",
    "--authorization": "authorization_path",
    "--authorization-sha256": "expect_authorization_record_sha256",
    "--authorized-root": "authorized_root",
    "--interpreter": "expect_interpreter_path",
    "--interpreter-sha256": "expect_interpreter_sha256",
    "--outer-seal-sha256": "expect_outer_seal_sha256",
    "--verifier-sha256": "expect_bundled_verifier_sha256",
    "--bootstrap-sha256": "expect_bootstrap_sha256",
    "--envelope-inventory-sha256": "expect_envelope_inventory_sha256",
    "--attestation-package": "attestation_package",
}
_CLI_OPTIONAL = {
    "--inner-seal": "expect_inner_seal",
    "--trace-status": "expect_trace_status",
}


def parse_cli_args(argv):
    """Parse the production CLI exactly once; reject omission, duplicates and unknown options."""
    vals, pos = {}, []
    allowed = dict(_CLI_REQUIRED, **_CLI_OPTIONAL)
    for raw in argv:
        if raw.startswith("--"):
            if "=" not in raw:
                raise CLIRefusal("option %r must use --name=value" % raw)
            key, value = raw.split("=", 1)
            if key not in allowed:
                raise CLIRefusal("unknown option %r" % key)
            if key in vals:
                raise CLIRefusal("duplicate option %r" % key)
            if not value:
                raise CLIRefusal("option %r has an empty value" % key)
            vals[key] = value
        else:
            pos.append(raw)
    if len(pos) != 1:
        raise CLIRefusal("exactly one envelope path is required; got %d" % len(pos))
    envelope_path = pos[0]
    if "\x00" in envelope_path or not os.path.isabs(envelope_path):
        raise CLIRefusal("the envelope path must be a NUL-free canonical absolute path")
    try:
        normalized_envelope = os.path.normpath(envelope_path)
    except (OSError, TypeError, ValueError) as e:
        raise CLIRefusal("the envelope path cannot be resolved safely: %s: %s"
                         % (type(e).__name__, e))
    if os.path.normcase(normalized_envelope) != os.path.normcase(envelope_path):
        raise CLIRefusal("the envelope path is not in canonical lexical form")
    missing = sorted(set(_CLI_REQUIRED) - set(vals))
    if missing:
        raise CLIRefusal("mandatory production pins are missing: %s" % missing)
    digest_flags = [k for k in _CLI_REQUIRED if k.endswith("sha256")]
    malformed = [k for k in digest_flags if not ENV._is_hex64(vals.get(k, ""))]
    if malformed:
        raise CLIRefusal("digest option(s) must be 64 lowercase hex characters: %s" % malformed)
    for key in ("--spec", "--authorization", "--authorized-root", "--interpreter"):
        value = vals[key]
        if "\x00" in value or not os.path.isabs(value):
            raise CLIRefusal("path option %r must be a NUL-free canonical absolute path" % key)
        try:
            normalized = os.path.normpath(value)
        except (OSError, TypeError, ValueError) as e:
            raise CLIRefusal("path option %r cannot be resolved safely: %s: %s"
                             % (key, type(e).__name__, e))
        if os.path.normcase(normalized) != os.path.normcase(value):
            raise CLIRefusal("path option %r is not in canonical lexical form" % key)
    if vals.get("--attestation-package") and not os.path.isabs(vals["--attestation-package"]):
        raise CLIRefusal("path option '--attestation-package' must be absolute")
    kwargs = {target: vals[flag] for flag, target in allowed.items() if flag in vals}
    return {"envelope_path": pos[0], "kwargs": kwargs}


def main(argv):
    if not argv:
        print(__doc__)
        print("bootstrap identity:", json.dumps(bootstrap_identity(), indent=1))
        print("bootstrap closure digest:", bootstrap_closure_digest())
        return 2
    try:
        parsed = parse_cli_args(argv)
    except CLIRefusal as e:
        print("REFUSED: %s" % e)
        return 3
    with tempfile.TemporaryDirectory(prefix="qualverify_") as ws:
        res = relocate_and_verify(parsed["envelope_path"], ws, **parsed["kwargs"])
        print(json.dumps({k: v for k, v in res.items() if k != "failures"}, indent=1))
        for f in res["failures"]:
            print("  !", f)
        print("RELOCATED VERIFICATION:", "PASS" if res["passed"] else "FAIL",
              "| G17:", "PASS" if res["g17_pass"] else "NOT SATISFIED")
        return 0 if res["g17_pass"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
