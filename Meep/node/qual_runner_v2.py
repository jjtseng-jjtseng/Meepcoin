#!/usr/bin/env python3
"""Qualification runner v2 -- a dedicated engineering runner with an explicit launch boundary.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE. In this revision the only committed specification is
DRAFT_NO_LAUNCH and no authorization record exists, so every real invocation refuses.

node/cadence_qualify.py is NOT converted into this and stays as identifiable CADENCEQ v1 history.

DEFECTS THE FIRST CORRECTIVE AUDIT REPRODUCED

1.  The order was lead-in preflight -> collect -> pre-launch preflight: the immediately-before-
    launch check ran AFTER the launch.
2.  A collector could be reached by editing `status` on an in-memory draft whose 17 thresholds
    were all still null.

THE DEFECT THE THIRD CORRECTIVE AUDIT REPRODUCED (R3-1)

    a caller constructed qual_spec.FrozenSpec DIRECTLY -- no file, no bind_authorized(), no
    authorization record -- around a document with EMPTY gates and nonsense operational values,
    and handed it to QualificationRunner together with a collector object whose
    `binding_sha256` attribute merely CLAIMED the pinned digest. Both checks were satisfied
    (`isinstance(FrozenSpec)` and an attribute comparison), the event sequence ran in the right
    order, and `launch_and_collect` executed.

The lesson is not "add another check to the object". It is that AN OBJECT IS NOT AN AUTHORIZATION.
Constructor privacy, a leading underscore, a frozen dataclass and `isinstance` are all readable and
constructible by any code in the same process.

SO THERE ARE NOW TWO CLASSES OF ENTRY POINT

  RefusalOnlyRunner (exported as QualificationRunner) -- can produce refusal documents and
      nothing else. It has NO collector, NO launch callback and NO code path that starts a
      process. Handing it a forged FrozenSpec produces a refusal, which is all it can produce.

  run_authorized(...) -- the ONLY executable entry point. It takes PATHS and EXTERNAL HASHES,
      never an object. Immediately before any side effect it re-opens both files, hashes the exact
      bytes, parses them, deeply validates the schemas against the filesystem, checks every
      cross-pin, and only then constructs its own internal binding. It then:

        authorization_check
          -> preflight:lead_in
          -> prepare               (RUNNER-OWNED: exclusive mkdir of the staging root)
          -> preflight:pre_launch  (the LAST injectable step, and it is diagnostic-only)
          -> stage_authorized_code (RUNNER-OWNED: the copy that will actually be launched)
          -> final_launch_binding_recheck
                                   (the TRUE final check: every launch-bearing byte AND the
                                    exact staged paths that appear in argv, re-read and
                                    re-hashed, types and aliases checked)
          -> launch_and_collect    (RUNNER-OWNED subprocess of the exact rechecked files)

      Nothing runs between the final recheck and process creation except the construction of the
      argument vector from values that check already bound. R5-1 reproduced the previous hole:
      `run_authorized` took a `clock`, and `final_recheck` called it AFTER hashing, so a caller's
      clock could rewrite the pinned interpreter that argv[0] then named. Production takes no
      clock, no preflight, no runner and no callback of any kind.

THE THREAT MODEL, STATED ONCE AND BOUNDED

This library is API ENFORCEMENT. IT IS NOT AN OS SANDBOX. A hostile local caller who can execute
arbitrary Python in this process can always import subprocess and start whatever it likes, and
nothing here pretends otherwise. What the module does is remove SUPPORTED routes: there is one
executable project API, it takes paths and external hashes, and every other public name refuses.

  ROOT OF TRUST      the local orchestrator that calls run_authorized, the externally pinned
                     Python interpreter named in the specification, and the external digests the
                     caller supplies from a review record outside this repository.
  UNTRUSTED          the specification file, the authorization record, evidence bundles, result
                     documents, paths, child output and any sidecar -- all of them until checked
                     against those external pins.
  TRUSTED ONLY AS    a collector or verifier becomes trusted only as the EXACT externally
                     authorized bytes, interpreter and dependency closure, re-read and re-hashed
                     as the last act before the process is created.
  VOCABULARY         "authorized", "canonical", "observed", "complete" and "authentic" are used
                     only inside the boundary implemented here, and every report says which.

R4-1 reproduced a second executable route: the public AuthorizedRun class could be constructed
directly and its launch_and_collect called with caller-influenced argv, no file binding, no
authorization record and no preflight. That class is now private and token-gated, __all__ names
the supported surface, and diagnostic_dry_run is the only injection-friendly path -- it stops at
the launch boundary and structurally cannot return a non-refused document.

DEFENCE IN DEPTH, NOT A PROOF

The import guard and the vocabulary scan raise the cost of reaching the scientific modules or
emitting a scientific claim; they are NOT a proof that arbitrary Python cannot do either. The
load-bearing controls are the allowlisted, TYPED result schema -- an unknown key is a refusal or is
confined to a clearly untrusted opaque string -- and the requirement that the collector be a
separately hashed file inside the authorized root, executed by the runner in a contained
subprocess.
"""
import ast
import hashlib
import math
import importlib.abc
import json
import os
import secrets
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import qual_spec as SPEC
import run_provenance as RP
import workload_preflight as WP

__all__ = ["RUNNER_ID", "RunnerError", "RefusalOnlyRunner", "QualificationRunner",
           "run_authorized", "diagnostic_dry_run", "coerce_retained",
           "assert_allowed_schema", "assert_engineering_only",
           "forbidden_imports_in_source", "ScienceImportGuard",
           "write_refusal_exclusive", "main"]

RUNNER_ID = "meepcoin-qualification-runner/2"

FORBIDDEN_MODULES = ("series_validate", "symmetric_series")

# ALLOWLIST. An engineering result may carry exactly these keys; anything else is a refusal.
RESULT_ALLOWED_KEYS = frozenset((
    "schema", "runner", "non_evidence", "engineering_only", "scope", "refused", "spec_id",
    "spec_sha256", "gate_inventory_sha256", "gate_semantics_sha256", "binding_sha256",
    "authorization_sha256", "authorized_root",
    "gate_ids", "collector", "collector_sha256", "collector_argv", "collector_exit",
    "retained", "opaque_collector_payload", "opaque_payload_note", "diagnostic_only",
    "child_sidecar_failures", "child_provenance_note",
    "staged_code", "child_record",
    "event_sequence", "launch_callback_invocations", "process_start_count",
    "preparation_side_effects",
    "final_launch_binding_recheck", "blocked_science_imports", "guard_note", "utc",
))
REFUSAL_ALLOWED_KEYS = frozenset((
    "schema", "runner", "non_evidence", "engineering_only", "refused", "code", "reason",
    "spec_id", "spec_status", "spec_sha256", "gate_inventory_sha256", "gate_semantics_sha256",
    "binding_sha256", "authorization_sha256", "event_sequence",
    "launch_callback_invocations", "preparation_side_effects", "side_effects",
    "file_side_effects", "detail", "diagnostic_only", "utc",
    "process_start_count", "child_record",
))
# What a collector may return, and the exact type each value must have. Anything else is either
# refused or confined to `opaque_collector_payload`, which is a STRING and therefore cannot
# impersonate an authorization or science field.
RETAINED_SCHEMA = {
    "raw_records": int,
    "branch_observations": int,
    "telemetry_retained": bool,
    "collection_seconds": float,
    "staging_dir": str,
    "note": str,
}
# R4-4: type-only validation is not semantic validation. Negative counts, NaN and infinite
# durations and a staging_dir pointing somewhere else were all accepted.
RETAINED_DOMAINS = {
    "raw_records": (0, 2 ** 53 - 1),
    "branch_observations": (0, 2 ** 53 - 1),
    "collection_seconds": (0.0, 604800.0),
}
MAX_NOTE_CHARS = 2000
# R5-4: an EMPTY object satisfied a schema that only constrained the keys that were present.
# A result may omit optional detail; it may not omit the facts that state collection happened.
RETAINED_REQUIRED = ("raw_records", "branch_observations", "collection_seconds")
# The collector speaks exactly one encoding and its output is read as bytes.
COLLECTOR_OUTPUT_ENCODING = "utf-8"
MAX_COLLECTOR_OUTPUT_BYTES = 4 * 1024 * 1024

FORBIDDEN_VERDICT_KEYS = ("series_valid", "invalid_reasons", "replay_gate", "equilibrium",
                          "none_equilibrium_entered", "partition_records", "triplet_ids",
                          "attack_confirmed", "hypothesis")
FORBIDDEN_VERDICT_PHRASES = ("series is valid", "series is invalid", "attack confirmed",
                             "attack is confirmed", "production ready", "production-ready",
                             "asic-proof", "gpu-proof", "browser-only", "secure for")
FORBIDDEN_VERDICT_FRAGMENTS = tuple(
    "%s%s" % (k, suf) for k in ("series_valid", "invalid_reasons", "replay_gate")
    for suf in ('":', "':", "=", ": "))


class RunnerError(RuntimeError):
    """A refusal or a structural violation. Never downgraded to a warning."""


# ------------------------------------------------------------------ structural self-check
def forbidden_imports_in_source(path, forbidden=FORBIDDEN_MODULES):
    """Module names this file imports statically that appear in `forbidden`. Parsed, not grepped."""
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in forbidden:
                    hits.append(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in forbidden:
                hits.append(node.module)
    return sorted(set(hits))


_self_hits = forbidden_imports_in_source(os.path.abspath(__file__))
if _self_hits:                                        # pragma: no cover - fails at import time
    raise ImportError("qual_runner_v2 statically imports forbidden module(s) %s" % _self_hits)


class ScienceImportGuard(importlib.abc.MetaPathFinder):
    """Blocks the scientific modules while installed. DEFENCE IN DEPTH, not a sandbox.

    A meta-path finder is consulted only on a cache miss, so a module already resident is never
    seen; that is why `require_absent` exists as a separate process-level precondition."""

    def __init__(self, forbidden=FORBIDDEN_MODULES, require_absent=True):
        self.forbidden = tuple(forbidden)
        self.require_absent = bool(require_absent)
        self.blocked = []

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in self.forbidden:
            self.blocked.append(fullname)
            raise ImportError(
                "qual_runner_v2 refuses to import %r: an engineering qualification must not reach "
                "the scientific series validator or the generic collection driver" % fullname)
        return None

    def __enter__(self):
        if self.require_absent:
            already = [m for m in sys.modules if m.split(".")[0] in self.forbidden]
            if already:
                raise RunnerError(
                    "refusing to run: %s already present in sys.modules; a qualification process "
                    "must not share an interpreter with the scientific modules" % sorted(already))
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, *exc):
        try:
            sys.meta_path.remove(self)
        except ValueError:                            # pragma: no cover - defensive
            pass
        return False


def assert_allowed_schema(doc, allowed, what):
    """An unknown top-level key is a refusal. A claim needs a name, and names are allowlisted."""
    extra = sorted(set(doc) - set(allowed))
    if extra:
        raise RunnerError("%s carries key(s) outside the allowlist: %s" % (what, extra))
    return True


def coerce_retained(raw, staging_dir=None, require_minimum=True):
    """(retained, opaque_json_or_None, failures).

    Allowlisted, TYPED, RANGED and, when `require_minimum`, subject to a MINIMUM CONTRACT.
    R4-4 reproduced negative counts, NaN and infinite durations and a staging_dir naming
    somewhere else. R5-4 reproduced the complement: `{}` passed, so a result that said nothing
    happened was indistinguishable from a result that said collection succeeded."""
    fails = []
    if not isinstance(raw, dict):
        return {}, None, ["the collector returned %s, not an object" % type(raw).__name__]
    if require_minimum:
        absent = [k for k in RETAINED_REQUIRED if k not in raw]
        if absent:
            fails.append("the collector's result omits %s; without them the document cannot "
                         "state that collection actually occurred" % absent)
    kept, unknown = {}, {}
    for k, v in sorted(raw.items()):
        if k not in RETAINED_SCHEMA:
            unknown[k] = v
            continue
        want = RETAINED_SCHEMA[k]
        if want is float:
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        elif want is int:
            ok = isinstance(v, int) and not isinstance(v, bool)
        else:
            ok = isinstance(v, want)
        if not ok:
            fails.append("collector result %r is %s, not %s"
                         % (k, type(v).__name__, want.__name__))
            continue
        if k in RETAINED_DOMAINS:
            lo, hi = RETAINED_DOMAINS[k]
            if want is int:
                comparable = v
            else:
                try:
                    comparable = float(v)
                except (OverflowError, TypeError, ValueError):
                    fails.append("collector result %r is outside the finite numeric range" % k)
                    continue
                if not math.isfinite(comparable):
                    fails.append("collector result %r is %r, which is not a finite number"
                                 % (k, v))
                    continue
            if not (lo <= comparable <= hi):
                fails.append("collector result %r = %r is outside its declared domain [%s, %s]"
                             % (k, v, lo, hi))
                continue
        if k == "staging_dir":
            if staging_dir is None:
                fails.append("collector result 'staging_dir' cannot be checked because no "
                             "canonical staging path was supplied; it must be omitted instead")
                continue
            if "\x00" in v or not os.path.isabs(v):
                fails.append("collector result 'staging_dir' must be a canonical absolute path "
                             "without NUL bytes, not %r" % v)
                continue
            if (not isinstance(staging_dir, str) or not staging_dir
                    or "\x00" in staging_dir or not os.path.isabs(staging_dir)):
                fails.append("the supplied actual staging root is not a canonical absolute path: "
                             "%r" % (staging_dir,))
                continue
            try:
                got_lexical = os.path.normpath(v)
                want_lexical = os.path.normpath(staging_dir)
                if os.path.normcase(got_lexical) != os.path.normcase(v):
                    fails.append("collector result 'staging_dir' is not in canonical lexical "
                                 "form: %r" % v)
                    continue
                if os.path.normcase(want_lexical) != os.path.normcase(staging_dir):
                    fails.append("the supplied actual staging root is not in canonical lexical "
                                 "form: %r" % staging_dir)
                    continue
                got_abs = os.path.abspath(v)
                want_abs = os.path.abspath(staging_dir)
                got_real = os.path.realpath(got_abs)
                want_real = os.path.realpath(want_abs)
            except (OSError, TypeError, ValueError) as e:
                fails.append("collector result 'staging_dir' could not be resolved safely: %s: %s"
                             % (type(e).__name__, e))
                continue
            if os.path.normcase(got_real) != os.path.normcase(got_abs):
                fails.append("collector result 'staging_dir' is an alias rather than its own "
                             "canonical path: %r" % v)
                continue
            if os.path.normcase(want_real) != os.path.normcase(want_abs):
                fails.append("the supplied actual staging root is an alias rather than its own "
                             "canonical path: %r" % staging_dir)
                continue
            got = os.path.normcase(got_real)
            want_p = os.path.normcase(want_real)
            if got != want_p:
                fails.append("collector result 'staging_dir' is %r, not the actual staging root "
                             "%r; a collector may report the real path or omit the field"
                             % (v, staging_dir))
                continue
        if k == "note" and len(v) > MAX_NOTE_CHARS:
            fails.append("collector result 'note' is %d characters, over the %d limit"
                         % (len(v), MAX_NOTE_CHARS))
            continue
        kept[k] = v
    opaque = None
    if unknown:
        try:
            opaque = json.dumps(unknown, sort_keys=True, allow_nan=False,
                                separators=(",", ":"))[:4000]
        except (TypeError, ValueError) as e:
            fails.append("the collector's unrecognised data is not deterministically "
                         "serialisable, so it is refused rather than carried: %s: %s"
                         % (type(e).__name__, e))
    return kept, opaque, fails


def assert_engineering_only(doc):
    """Defence in depth over the allowlist: reject scientific keys and serialised verdicts."""
    found_keys, found_phrases = [], []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                # A validated child_record is a raw process/provenance channel, not a verdict.
                # It must remain the exact capability object so the enclosing active recorder
                # can adopt even a refused collector.  Its fixed-schema argv/path strings are
                # therefore not interpreted as qualification prose by this vocabulary guard.
                if k == "child_record" and not path:
                    continue
                if k in FORBIDDEN_VERDICT_KEYS:
                    found_keys.append("%s.%s" % (path, k) if path else k)
                walk(v, "%s.%s" % (path, k) if path else k)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))
        elif isinstance(node, str):
            low = node.lower()
            for p in FORBIDDEN_VERDICT_PHRASES + FORBIDDEN_VERDICT_FRAGMENTS:
                if p in low:
                    found_phrases.append("%s: %r" % (path, p))

    walk(doc)
    if found_keys or found_phrases:
        raise RunnerError(
            "the qualification document would carry scientific vocabulary; keys=%s phrases=%s"
            % (sorted(set(found_keys)), sorted(set(found_phrases))))
    return True


def _sget(spec, key):
    if spec is None:
        return None
    if isinstance(spec, SPEC.FrozenSpec):
        return spec.get(key)
    return spec.get(key) if hasattr(spec, "get") else None


# ------------------------------------------------------------------ the refusal-only runner
class RefusalOnlyRunner:
    """Produces refusal documents. It cannot start a process, and there is no code path here that
    does: it holds no collector, accepts no callback and calls no subprocess API."""

    def __init__(self, spec, preflight=None, clock=time.time, guard_requires_absent=True):
        self.spec = spec
        self.preflight = preflight
        self.clock = clock
        self.guard_requires_absent = bool(guard_requires_absent)
        self.events = []
        self.launch_calls = 0
        self.process_start_count = 0
        self.preparation_side_effects = []

    def _note(self, kind, detail=None):
        self.events.append(kind if detail is None else "%s:%s" % (kind, detail))

    def prepare_gate(self):
        """None when the object survives every static check, else a refusal document. Surviving
        this is NOT permission to launch: only run_authorized launches, and it does not consult
        this method or accept this object."""
        self._note("authorization_check")
        reason = SPEC.refusal_reason(self.spec)
        if reason is not None:
            return self.refusal("SPEC_NOT_AUTHORIZED", reason)
        if not isinstance(self.spec, SPEC.FrozenSpec) \
                or not getattr(self.spec, "bound_by_bind_authorized", False):
            return self.refusal(
                "SPEC_NOT_BOUND",
                "this object claims AUTHORIZED but did not come out of "
                "qual_spec.bind_authorized, so nothing here was ever read from a file, hashed, "
                "deeply validated or cross-pinned against an authorization record. An object is "
                "not an authorization, and the digests it reports may be invented")
        missing = SPEC.completeness_failures(self.spec.as_plain(),
                                             getattr(self.spec, "authorized_root", None))
        if missing:
            return self.refusal("SPEC_INCOMPLETE",
                                "the bound specification is incomplete: %s" % missing)
        self._note("authorized", self.spec.spec_id)
        return None

    def refusal(self, code, reason, extra=None, file_side_effects=None):
        process_count = int(getattr(self, "process_start_count", 0) or 0)
        child_record = getattr(self, "child_record", None)
        doc = {
            "schema": "meepcoin-qualification-refusal/1",
            "runner": RUNNER_ID,
            "non_evidence": True,
            "engineering_only": True,
            "refused": True,
            "code": code,
            "reason": reason,
            "spec_id": _sget(self.spec, "spec_id"),
            "spec_status": _sget(self.spec, "status"),
            "spec_sha256": getattr(self.spec, "spec_sha256", None),
            "gate_inventory_sha256": getattr(self.spec, "inventory_sha256", None),
            "gate_semantics_sha256": getattr(self.spec, "semantics_sha256", None),
            "binding_sha256": getattr(self.spec, "binding_sha256", None),
            "authorization_sha256": getattr(self.spec, "authorization_sha256", None),
            "event_sequence": list(self.events),
            "launch_callback_invocations": self.launch_calls,
            "process_start_count": process_count,
            "child_record": child_record,
            "preparation_side_effects": list(self.preparation_side_effects),
            "side_effects": (
                ("%d collector process was started by the process-owning API and synchronously "
                 "returned/reaped; its exact child_record is retained for provenance adoption; "
                 "preparation side effects are listed separately" % process_count)
                if process_count else
                ("no process was started; none beyond any preparation side effects listed "
                 "above; the launch callback was invoked %d times" % self.launch_calls)),
            "file_side_effects": file_side_effects or [],
            "diagnostic_only": bool(getattr(self, "diagnostic_only", False)),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if extra:
            doc["detail"] = extra
        assert_allowed_schema(doc, REFUSAL_ALLOWED_KEYS, "the refusal document")
        try:
            assert_engineering_only(doc)
        except RunnerError:
            # The refusal boundary is total over untrusted collector text.  Reserved scientific
            # vocabulary is not allowed to escape as apparent prose, but it also must not turn a
            # refused real child into a Python exception or discard its exact adoption record.
            doc["reason"] = ("untrusted refusal diagnostics were redacted because they used "
                             "reserved scientific vocabulary")
            doc["spec_id"] = None
            doc["spec_status"] = None
            doc["event_sequence"] = ["untrusted_refusal_diagnostics_redacted"]
            doc["preparation_side_effects"] = (
                ["one or more preparation paths were redacted"]
                if self.preparation_side_effects else [])
            doc["file_side_effects"] = []
            doc["detail"] = {"redacted": True,
                             "why": "reserved scientific vocabulary in untrusted diagnostics"}
            assert_engineering_only(doc)
        return doc

    def run(self, staging_dir=None):
        """Always a refusal. This class has no launch capability at all."""
        try:
            guard = ScienceImportGuard(require_absent=self.guard_requires_absent)
            guard.__enter__()
        except RunnerError as e:
            return self.refusal("SCIENCE_MODULES_RESIDENT", str(e))
        try:
            refused = self.prepare_gate()
            if refused is not None:
                return refused
            return self.refusal(
                "RUNNER_NOT_EXECUTABLE",
                "this runner produces refusal documents only. It holds no collector, accepts no "
                "launch callback and contains no process-creation call. An authorized run must go "
                "through qual_runner_v2.run_authorized, which takes paths and external hashes, "
                "re-binds them itself, and owns process creation")
        finally:
            guard.__exit__(None, None, None)


# The historical name. It is the refusal-only class, so an old caller cannot launch.
QualificationRunner = RefusalOnlyRunner


# ------------------------------------------------------------------ the executable entry point
# API ENFORCEMENT, NOT A SANDBOX. Only run_authorized holds this token. R4-1 reproduced a public
# AuthorizedRun whose launch_and_collect could be called directly, with caller-influenced argv and
# no binding, no authorization record and no preflight. Arbitrary same-process Python can still
# call subprocess itself; what this removes is a SUPPORTED second route.
_LAUNCH_TOKEN = object()


class _AuthorizedRun:
    """Built ONLY by run_authorized / diagnostic_dry_run, from paths and external hashes."""

    # The environment a child may inherit. MEEPCOIN_CHILD_* are propagated on purpose: they are
    # how a child reports its own reads back, under a nonce this run generated.
    CHILD_ENV_PASSTHROUGH = ("PATH", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP")

    def __init__(self, spec, preflight, clock=time.time, diagnostic=False):
        self.spec = spec
        self.preflight = preflight
        # PRODUCTION NEVER PASSES A CLOCK. diagnostic_dry_run may, and even there the clock is
        # read BEFORE the byte checks, so no injected callable can act after them (R5-1).
        self.clock = clock if diagnostic else time.time
        self.diagnostic_only = bool(diagnostic)
        self.events = []
        self.launch_calls = 0
        self.process_start_count = 0
        self.preparation_side_effects = []
        self.recheck = None
        self.staged_code = None
        self.child_record = None
        self.child_entry = None
        self.interpreter = None

    _note = RefusalOnlyRunner._note
    refusal = RefusalOnlyRunner.refusal

    # ---- runner-owned preparation ----
    def prepare(self, staging_dir):
        self._note("prepare")
        os.mkdir(staging_dir)                        # exclusive; a racing creator loses
        self.preparation_side_effects = [
            "created the staging root %s (exclusive mkdir; no process was started)" % staging_dir]
        return self.preparation_side_effects

    # ---- every launch-bearing byte, re-read as the LAST act before process creation ----
    def resolved_interpreter(self):
        """The ONE canonical absolute path this run will execute, or a refusal reason.

        R5-3: the spec named a RELATIVE interpreter. The checks resolved it under the caller's
        current directory while argv kept the relative spelling, which the child process would
        have resolved under the staging directory -- a different object, or none at all."""
        cb = self.spec.get("collector_binding") or {}
        interp = (cb.get("interpreter") or {})
        raw = interp.get("path")
        if not isinstance(raw, str) or not raw:
            return None, "the specification names no interpreter path"
        if not os.path.isabs(raw):
            return None, ("the interpreter path %r is relative; a relative spelling is resolved "
                          "against whatever the current directory happens to be, so it names one "
                          "object at check time and another at launch time (R5-3)" % raw)
        if os.path.normpath(raw) != raw and os.path.normcase(os.path.normpath(raw)) \
                != os.path.normcase(raw):
            return None, "the interpreter path %r is not in canonical form" % raw
        return raw, None

    def launch_bearing_inputs(self, spec_path, expect_spec_sha256, authorization_path,
                              expect_authorization_sha256):
        """[(label, abspath, expected_digest)] -- the complete set, interpreter and the STAGED
        code that argv actually names included."""
        root = self.spec.authorized_root
        cb = self.spec.get("collector_binding") or {}
        interp = cb.get("interpreter") or {}
        interp_path, _why = self.resolved_interpreter()
        pairs = [("qualification specification", os.path.abspath(spec_path), expect_spec_sha256),
                 ("authorization record", os.path.abspath(authorization_path),
                  expect_authorization_sha256),
                 ("interpreter", interp_path or os.path.abspath(str(interp.get("path"))),
                  interp.get("sha256")),
                 ("collector", os.path.join(root, str(cb.get("path")).replace("/", os.sep)),
                  cb.get("sha256"))]
        if self.staged_code:
            for rel, dig in sorted(self.staged_code["digests"].items()):
                pairs.append(("STAGED %s (the path argv names)" % rel,
                              os.path.join(self.staged_code["root"],
                                           rel.replace("/", os.sep)), dig))
        for rel, dig in sorted((cb.get("dependencies") or {}).items()):
            pairs.append(("collector dependency %s" % rel,
                          os.path.join(root, rel.replace("/", os.sep)), dig))
        for gid, e in sorted((self.spec.get("evaluators") or {}).items()):
            pairs.append(("evaluator %s" % gid,
                          os.path.join(root, str((e or {}).get("module")).replace("/", os.sep)),
                          (e or {}).get("sha256")))
        return pairs

    def final_recheck(self, spec_path, expect_spec_sha256, authorization_path,
                      expect_authorization_sha256):
        """The LAST check before process creation. Type, path safety and exact bytes."""
        self._note("final_launch_binding_recheck")
        # The timestamp is taken FIRST. Nothing that is not this method's own code runs after
        # the byte checks below (R5-1).
        checked_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock()))
        drift, seen = [], {}
        interp_path, why = self.resolved_interpreter()
        if why:
            drift.append("interpreter: %s" % why)
        else:
            self.interpreter = interp_path
        pairs = self.launch_bearing_inputs(spec_path, expect_spec_sha256, authorization_path,
                                           expect_authorization_sha256)
        for label, path, want in pairs:
            kind = SPEC._ENV.file_kind(path)
            if kind != "regular":
                drift.append("%s: %r is %s, not a regular file" % (label, path, kind))
                continue
            norm = os.path.normcase(os.path.realpath(path))
            if norm != os.path.normcase(os.path.abspath(path)):
                drift.append("%s: %r is an alias for %r" % (label, path, norm))
                continue
            if norm in seen:
                drift.append("%s and %s name the same file %r" % (seen[norm], label, norm))
                continue
            seen[norm] = label
            got = SPEC.sha256_file(path)
            if got != want:
                drift.append("%s: %r now hashes to %s, not the bound %s"
                             % (label, path, got[:16], str(want)[:16]))
        self.recheck = {
            "files_rechecked": len(pairs),
            "labels": [p[0] for p in pairs],
            "drift": drift,
            "checked_utc": checked_utc,
            "canonical_interpreter": self.interpreter,
            "note": ("this is the LAST act before process creation. It covers the interpreter, "
                     "the specification, the authorization record and the exact STAGED files "
                     "argv names. No injected callback, provider, prelude or clock runs after "
                     "it; production accepts none at all"),
        }
        return drift

    def stage_authorized_code(self, staging_dir, spec_path, expect_spec_sha256,
                              authorization_path, expect_authorization_sha256):
        """Copy the just-verified collector and dependencies into the runner's own staging root
        and re-hash the copies, so the path that is LAUNCHED is the object that was checked."""
        root = self.spec.authorized_root
        dest = os.path.join(staging_dir, "_authorized_code")
        os.mkdir(dest)
        cb = self.spec.get("collector_binding") or {}
        want = {str(cb.get("path")): cb.get("sha256")}
        want.update({k: v for k, v in (cb.get("dependencies") or {}).items()})
        copied, fails = {}, []
        for rel, dig in sorted(want.items()):
            src = os.path.join(root, rel.replace("/", os.sep))
            dst = os.path.join(dest, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst) or dest, exist_ok=True)
            try:
                shutil.copyfile(src, dst, follow_symlinks=False)
            except OSError as e:
                fails.append("the authorized source %r could not be staged: %s: %s"
                             % (rel, type(e).__name__, e))
                continue
            got = SPEC.sha256_file(dst)
            copied[rel] = got
            if got != dig:
                fails.append("the staged copy of %r hashes to %s, not the bound %s"
                             % (rel, got[:16], str(dig)[:16]))
        self.staged_code = {"root": dest, "digests": copied, "failures": fails,
                            "note": "the launched path is this copy, made after authorization and "
                                    "preflight, then re-hashed as part of the final recheck"}
        return fails

    def collector_argv(self, staging_dir):
        """The EXACT command this runner will execute: the canonical absolute interpreter that
        final_recheck type-checked and hashed, and the staged collector it hashed with it."""
        cb = self.spec.get("collector_binding") or {}
        if not self.interpreter:
            raise RunnerError("collector_argv before the final recheck bound an interpreter")
        collector = os.path.join(self.staged_code["root"],
                                 str(cb.get("path")).replace("/", os.sep))
        return [self.interpreter, "-I", "-B", collector, "--staging=%s" % staging_dir,
                "--spec-sha256=%s" % self.spec.spec_sha256]

    def launch_and_collect(self, staging_dir, timeout=3600, token=None):
        """One process-owning provenance call creates, observes and reaps the collector.

        stdout and stderr are captured as RAW BYTES: the recorded sizes and digests are facts
        about the byte stream the child wrote, not about a decoding of it (R5-5). The caller
        cannot supply a process object, PID, return code or output bytes (R6-1)."""
        if token is not _LAUNCH_TOKEN:
            raise RunnerError(
                "process creation is reached only through qual_runner_v2.run_authorized. A "
                "directly constructed run object is not an authorization (R4-1)")
        self._note("launch_and_collect")
        self.launch_calls += 1
        argv = self.collector_argv(staging_dir)
        sidecar = os.path.join(staging_dir, "_child_provenance.json")
        env = {k: v for k, v in os.environ.items() if k in self.CHILD_ENV_PASSTHROUGH}
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONPATH": "",
                    "PYTHONHASHSEED": "0"})
        bound = {}
        for label, path, digest in self.launch_bearing_inputs(
                self.spec.path, self.spec.spec_sha256,
                os.path.join(self.spec.authorized_root,
                             str(self.spec.get("authorization_record")).replace("/", os.sep)),
                self.spec.authorization_sha256):
            # The executable has its own mandatory independent pin in run_observed. Supplying it
            # a second time as an ordinary input adds no identity and would make the path set
            # artificially non-unique.
            if os.path.normcase(os.path.realpath(path)) == \
                    os.path.normcase(os.path.realpath(self.interpreter)):
                continue
            if path in bound and bound[path] != digest:
                raise RunnerError("launch-bearing path %r has contradictory digests" % path)
            bound[os.path.abspath(path)] = digest
        r = RP.run_observed(
            argv, executable=self.interpreter,
            expect_executable_sha256=(self.spec.get("collector_binding") or {})
                                     .get("interpreter", {}).get("sha256"),
            cwd=staging_dir, root=self.spec.authorized_root,
            expected_inputs=bound, sidecar_path=sidecar, env=env, timeout=timeout)
        self.child_record = r.record
        self.child_sidecar_failures = list(r.sidecar_failures)
        self.process_start_count += int(bool(r.record.get("process_started")))
        return argv, r


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _sequence(spec_path, expect_spec_sha256, expect_inventory_sha256, expect_binding_sha256,
              authorization_path, expect_authorization_sha256, authorized_root, staging_dir,
              preflight, timeout, clock, guard_requires_absent, diagnostic):
    """The ONE sequence. `diagnostic` never creates a process and can never return a
    non-refused document."""
    run = _AuthorizedRun(None, preflight, clock, diagnostic=diagnostic)
    run.child_sidecar_failures = None
    try:
        guard = ScienceImportGuard(require_absent=guard_requires_absent)
        guard.__enter__()
    except RunnerError as e:
        return run.refusal("SCIENCE_MODULES_RESIDENT", str(e))
    try:
        # ---- 1. authorization: re-open, re-hash, re-parse, deeply validate, cross-pin ----
        run._note("authorization_check")
        if not isinstance(preflight, WP.WorkloadPreflight):
            return run.refusal(
                "NO_PREFLIGHT",
                "a competing-workload preflight is mandatory and must be the fail-closed "
                "workload_preflight.WorkloadPreflight owned by this runner")
        try:
            spec = SPEC.bind_authorized(spec_path, expect_spec_sha256, expect_inventory_sha256,
                                        expect_binding_sha256, authorization_path,
                                        expect_authorization_sha256, authorized_root, clock=clock)
        except SPEC.SpecError as e:
            return run.refusal("SPEC_REFUSED", str(e))
        run.spec = spec
        run._note("authorized", spec.spec_id)

        # The staging root is the runner's first filesystem side effect.  Refuse ambiguous or
        # caller-CWD-dependent spellings before lexists()/mkdir() can create anything (R6 review).
        if (not isinstance(staging_dir, str) or not staging_dir or "\x00" in staging_dir
                or not os.path.isabs(staging_dir)):
            return run.refusal(
                "STAGING_PATH_REFUSED",
                "staging_dir must be a canonical absolute path, not %r" % (staging_dir,))
        normalized_staging = os.path.normpath(staging_dir)
        if os.path.normcase(normalized_staging) != os.path.normcase(staging_dir):
            return run.refusal(
                "STAGING_PATH_REFUSED",
                "staging_dir is not in canonical lexical form: %r" % staging_dir)
        staging_parent = os.path.dirname(staging_dir)
        if (not os.path.isdir(staging_parent)
                or os.path.normcase(os.path.realpath(staging_parent))
                != os.path.normcase(os.path.abspath(staging_parent))):
            return run.refusal(
                "STAGING_PATH_REFUSED",
                "the canonical staging parent %r must be a real, non-aliased directory"
                % staging_parent)
        if os.path.lexists(staging_dir):
            return run.refusal("STAGING_EXISTS",
                               "refusing to reuse the existing staging path %r" % staging_dir)

        # ---- 2. lead-in process inventory ----
        run._note("preflight", "lead_in")
        pre = preflight.check("lead_in", spec.as_plain())
        if not pre.allowed:
            return run.refusal("PREFLIGHT_LEAD_IN", pre.summary(), pre.as_dict())

        # ---- 3. runner-owned staging ----
        try:
            run.prepare(staging_dir)
        except (OSError, TypeError, ValueError) as e:
            return run.refusal("STAGING_FAILED", "%s: %s" % (type(e).__name__, e))

        # ---- 4. pre-launch process inventory: the LAST injectable step in the sequence ----
        run._note("preflight", "pre_launch")
        post = preflight.check("pre_launch", spec.as_plain())
        if not post.allowed:
            return run.refusal("PREFLIGHT_PRE_LAUNCH", post.summary(), post.as_dict())

        # ---- 5. RUNNER-OWNED staging of the code that will actually be launched ----
        try:
            staged_fails = run.stage_authorized_code(staging_dir, spec_path,
                                                     expect_spec_sha256,
                                                     authorization_path,
                                                     expect_authorization_sha256)
        except (OSError, TypeError, ValueError) as e:
            return run.refusal(
                "STAGED_CODE_UNAVAILABLE",
                "the runner could not create its private authorized-code staging tree: %s: %s"
                % (type(e).__name__, e),
                {"process_start_count": run.process_start_count})
        if staged_fails:
            return run.refusal("STAGED_CODE_MISMATCH",
                               "the runner's own copy does not match the bound bytes: %s"
                               % staged_fails, run.staged_code)

        # ---- 6. THE TRUE FINAL CHECK: every launch-bearing byte AND every staged path in
        #         argv, re-read, type-checked, alias-checked and re-hashed. Nothing runs after
        #         this except the construction of argv from values it bound (R5-1, R5-3).
        drift = run.final_recheck(spec_path, expect_spec_sha256, authorization_path,
                                  expect_authorization_sha256)
        if drift:
            return run.refusal("LAUNCH_BEARING_DRIFT",
                               "launch-bearing bytes changed after the bind: %s" % drift,
                               run.recheck)

        # ---- 7. immediate runner-owned process creation ----
        if diagnostic:
            return run.refusal(
                "DIAGNOSTIC_ONLY",
                "diagnostic_dry_run performed the complete sequence and stopped at the launch "
                "boundary. It creates no process and cannot return a non-refused document",
                {"would_launch": run.collector_argv(staging_dir),
                 "final_recheck": run.recheck, "staged_code": run.staged_code})
        try:
            argv, r = run.launch_and_collect(staging_dir, timeout=timeout, token=_LAUNCH_TOKEN)
        except RP.LaunchObserverError as e:
            return run.refusal(
                "PROCESS_OBSERVATION_REFUSED",
                "the process-owning launch boundary refused before it could return a completed "
                "child record: %s" % e,
                {"process_start_count": run.process_start_count,
                 "child_record": run.child_record})
        if r.returncode != 0:
            return run.refusal("COLLECTOR_FAILED",
                               "the pinned collector exited %s" % r.returncode,
                               {"stderr": (r.stderr or b"")[:400].decode("utf-8", "replace"),
                                "argv": argv})
        blob = r.stdout or b""
        if len(blob) > MAX_COLLECTOR_OUTPUT_BYTES:
            return run.refusal("COLLECTOR_OUTPUT_TOO_LARGE",
                               "the collector wrote %d bytes, over the %d limit"
                               % (len(blob), MAX_COLLECTOR_OUTPUT_BYTES), {"argv": argv})
        try:
            text = blob.decode(COLLECTOR_OUTPUT_ENCODING)   # STRICT: no replacement characters
        except UnicodeDecodeError as e:
            return run.refusal("COLLECTOR_OUTPUT_NOT_%s" % COLLECTOR_OUTPUT_ENCODING.upper(),
                               "the collector's stdout is not valid %s: %s"
                               % (COLLECTOR_OUTPUT_ENCODING, e),
                               {"argv": argv, "stdout_bytes": len(blob)})
        try:
            raw = json.loads(text.strip().splitlines()[-1])
        except Exception as e:
            return run.refusal("COLLECTOR_OUTPUT_UNREADABLE",
                               "%s: %s" % (type(e).__name__, e), {"argv": argv})
        retained, opaque, bad = coerce_retained(raw, staging_dir=staging_dir)
        if bad:
            return run.refusal("COLLECTOR_RESULT_REJECTED",
                               "the collector's result violates the typed, ranged, minimum "
                               "schema: %s" % bad, {"argv": argv})
        if run.child_sidecar_failures:
            return run.refusal(
                "COLLECTOR_PROVENANCE_REJECTED",
                "the collector returned no valid provenance sidecar, so what it read and ran "
                "is not observed: %s" % run.child_sidecar_failures[:6],
                {"argv": argv, "sidecar_path": run.child_record.get("sidecar_path"),
                 "sidecar_failures": run.child_sidecar_failures})

        doc = {
            "schema": "meepcoin-qualification-result/2",
            "runner": RUNNER_ID,
            "non_evidence": True,
            "engineering_only": True,
            "scope": "cadence and integrity of the harness only. This document issues no "
                     "scientific verdict and tests no timestamp hypothesis. It DOES carry "
                     "provisional engineering checks and candidate validity checks, which "
                     "remain pending an estimand decision",
            "refused": False,
            "diagnostic_only": False,
            "spec_id": spec.spec_id,
            "spec_sha256": spec.spec_sha256,
            "gate_inventory_sha256": spec.inventory_sha256,
            "gate_semantics_sha256": spec.semantics_sha256,
            "binding_sha256": spec.binding_sha256,
            "authorization_sha256": spec.authorization_sha256,
            "authorized_root": spec.authorized_root,
            "gate_ids": [g["id"] for g in spec["gates"]],
            "collector": (spec.get("collector_binding") or {}).get("path"),
            "collector_sha256": (spec.get("collector_binding") or {}).get("sha256"),
            "collector_argv": list(argv),
            "collector_exit": r.returncode,
            "staged_code": run.staged_code,
            "child_record": run.child_record,
            "child_sidecar_failures": [],
            "child_provenance_note": ("the collector's own sidecar was validated against this "
                                      "launch's nonce, canonical command identity, cwd, root, "
                                      "executable digest and observed exit before this document "
                                      "could be non-refused"),
            "retained": retained,
            "opaque_collector_payload": opaque,
            "opaque_payload_note": ("UNTRUSTED. Anything the collector returned outside the "
                                    "typed, ranged allowlist is serialised here as one "
                                    "deterministic string. It is not interpreted and cannot "
                                    "impersonate an authorization or science field"),
            "event_sequence": list(run.events),
            "launch_callback_invocations": run.launch_calls,
            "process_start_count": run.process_start_count,
            "preparation_side_effects": list(run.preparation_side_effects),
            "final_launch_binding_recheck": run.recheck,
            "blocked_science_imports": list(guard.blocked),
            "guard_note": "the import guard and vocabulary scan are defence in depth, not a proof "
                          "that arbitrary Python cannot reach or emit science",
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        assert_allowed_schema(doc, RESULT_ALLOWED_KEYS, "the engineering result")
        try:
            assert_engineering_only(doc)
        except RunnerError:
            return run.refusal(
                "COLLECTOR_RESULT_REJECTED",
                "the collector output used reserved scientific vocabulary and cannot be "
                "retained in an engineering-only qualification document",
                {"collector_stdout_bytes": len(blob),
                 "collector_stdout_sha256": hashlib.sha256(blob).hexdigest(),
                 "vocabulary_check": "refused"})
        return doc
    finally:
        guard.__exit__(None, None, None)


def run_authorized(spec_path, expect_spec_sha256, expect_inventory_sha256, expect_binding_sha256,
                   authorization_path, expect_authorization_sha256, authorized_root,
                   staging_dir, timeout=3600, guard_requires_absent=True):
    """THE ONLY SUPPORTED EXECUTABLE ENTRY POINT.

    It takes PATHS, EXTERNAL HASHES and two booleans -- never an object, never a callable. There
    is no clock, no preflight, no runner, no collector and no prelude parameter: R5-1 reproduced
    a caller's clock rewriting the pinned interpreter after the final hashes, and the fix is not
    a better clock but no injectable anything in production."""
    preflight = WP.WorkloadPreflight()                # production providers, owned here
    return _sequence(spec_path, expect_spec_sha256, expect_inventory_sha256,
                     expect_binding_sha256, authorization_path, expect_authorization_sha256,
                     authorized_root, staging_dir, preflight, timeout, time.time,
                     guard_requires_absent, False)


def diagnostic_dry_run(spec_path, expect_spec_sha256, expect_inventory_sha256,
                       expect_binding_sha256, authorization_path, expect_authorization_sha256,
                       authorized_root, staging_dir, preflight, timeout=3600, clock=time.time,
                       guard_requires_absent=True):
    """DIAGNOSTIC ONLY. Accepts an injected preflight so tests can drive synthetic inventories.

    It runs the complete sequence and STOPS at the launch boundary: it creates no process, and it
    structurally cannot return a non-refused document -- the only non-refusal path in _sequence is
    guarded by `if diagnostic: return run.refusal(...)` before process creation. An injected
    clock is read only BEFORE the final byte checks, so even here nothing injected can act
    after them."""
    return _sequence(spec_path, expect_spec_sha256, expect_inventory_sha256,
                     expect_binding_sha256, authorization_path, expect_authorization_sha256,
                     authorized_root, staging_dir, preflight, timeout, clock,
                     guard_requires_absent, True)


# ------------------------------------------------------------------ CLI
def write_refusal_exclusive(path, doc):
    """Create a detached refusal file EXCLUSIVELY. Never overwrites; never silently replaces."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    return path


def main(argv):
    arg = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in argv if "=" in a}
    spec_path = arg.get("--spec")
    if not spec_path:
        print(__doc__)
        return 2

    file_effects = []
    try:
        doc = SPEC.load_spec(spec_path, expect_file_sha256=arg.get("--spec-sha256"),
                             expect_inventory_sha256=arg.get("--inventory-sha256"),
                             expect_binding_sha256=arg.get("--binding-sha256"))
    except SPEC.SpecError as e:
        print("SPEC REFUSED: %s" % e)
        return 3

    runner = RefusalOnlyRunner(doc)
    if SPEC.refusal_reason(doc) is None:
        out = runner.refusal(
            "CLI_NOT_CONFIGURED",
            "this specification claims AUTHORIZED, but the default command line configures no "
            "authorized root and no authorization-record binding. An authorized run must call "
            "qual_runner_v2.run_authorized with every pin supplied independently.")
    else:
        out = runner.prepare_gate()

    print("REFUSED [%s]: %s" % (out["code"], out["reason"]))
    print("launch callback invocations: %d" % out["launch_callback_invocations"])
    dest = arg.get("--out")
    if dest:
        try:
            write_refusal_exclusive(dest, out)
            file_effects.append(dest)
            print("refusal written (exclusive create) ->", dest)
        except FileExistsError:
            print("REFUSING to overwrite an existing file at %s; nothing was written" % dest)
            return 4
    print("file side effects of this invocation: %s" % (file_effects or "none"))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
