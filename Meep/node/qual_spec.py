#!/usr/bin/env python3
"""The qualification specification, its integrity pins, and what authorization actually requires.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE. This module launches nothing and measures nothing.

WHAT THESE PINS ARE, AND WHAT THEY ARE NOT

Everything here is an INTEGRITY pin: it detects change. None of it is AUTHENTICATION: nothing here
proves *who* produced a byte, and this file is not "unforgeable". Anyone who can write the
specification can also write a matching authorization record and recompute every digest. What the
pins buy is that a change cannot be silent, and that the caller must supply the expected values
from somewhere the file itself does not control -- a constant in an audited caller, an operator
argument, or a review record. Real authentication would need a signature scheme and a key
custodian, and there is none. That gap is stated rather than papered over.

THE FIRST CORRECTIVE AUDIT REPRODUCED THIS

    load the committed DRAFT, set doc["status"] = "AUTHORIZED" in memory, leave all 17 thresholds
    null -> the runner reached the collector, while still reporting the DRAFT's _spec_sha256

THE THIRD CORRECTIVE AUDIT REPRODUCED TWO MORE (R3-1 and R3-6)

    R3-1  construct qual_spec.FrozenSpec DIRECTLY -- no file, no bind_authorized(), no
          authorization record -- around a document with EMPTY gates, replicates=-5,
          rates="as fast as possible", ports={"base":99999999}, durations={"mine":-1}, a
          one-entry role list and made-up 64-character digests. completeness_failures() returned
          [], the runner accepted it because isinstance(FrozenSpec) was true, a collector that
          merely CLAIMED the pinned digest satisfied the collector check, and launch_and_collect
          ran. The runner reported "a"*64 as its spec digest.
    R3-6  a synthetic AUTHORIZED document with nonexistent evaluator and collector paths,
          arbitrary 64-character hashes, replicates=0, durations={"mine": inf}, ports={"base":-7},
          a duplicated condition order and thresholds={"threshold": "TBD"} on every gate also
          returned NO completeness failures.

Both had the same root cause: completeness was a PRESENCE test over a caller-supplied object.
Presence is not validity, an object is not a document, and `isinstance` is not authorization.

WHAT NOW HOLDS

  ALLOWLISTED     every top-level and nested key is allowlisted; an unknown field is a refusal, so
                  a new claim cannot arrive under a new name.
  TYPED           replicates is a positive int (a bool is not an int here), ports and namespace
                  have structure, durations and rates are finite and positive, thresholds are
                  present, non-null, finite, typed and inside any declared domain, and the
                  condition order is unique and agrees with the schedule.
  ON DISK         every evaluator, the collector and each of its declared dependencies must EXIST
                  under the authorized root, be a regular file, and hash to the pinned value. An
                  arbitrary 64-character string no longer passes for a pin.
  INDEPENDENT     the authorization record separately pins the spec bytes, the gate-identity
                  digest, the FULL gate-semantics digest, the required envelope roles, the
                  evaluator inventory, the collector identity, the bundled verifier and every
                  launch-bearing value. A specification's own self-pins are only consistency
                  checks.
  NOT AN OBJECT   `bind_authorized` is the only producer of a FrozenSpec, and a FrozenSpec is not
                  a permission slip: the executable entry point in qual_runner_v2 does not accept
                  one. See qual_runner_v2.run_authorized, which re-reads and re-binds from PATHS
                  and external hashes immediately before any side effect.

`_CONSTRUCTION_TOKEN` below is DEFENCE IN DEPTH, not a security boundary. Any code in this process
can read a module global. It exists so that a directly constructed FrozenSpec is *detectable*; the
load-bearing control remains that no executable path accepts a caller-supplied object at all.
"""
import hashlib
import json
import math
import os
import re
import types

import evidence_envelope as _ENV

SPEC_SCHEMA = "meepcoin-qualification-spec/2"
AUTHZ_SCHEMA = "meepcoin-qualification-authorization/2"

STATUS_DRAFT = "DRAFT_NO_LAUNCH"
STATUS_AUTHORIZED = "AUTHORIZED"
STATUSES = (STATUS_DRAFT, STATUS_AUTHORIZED)

KIND_SHAPE = "shape"
KIND_CADENCE = "cadence"
KIND_INTEGRITY = "integrity"
KINDS = (KIND_SHAPE, KIND_CADENCE, KIND_INTEGRITY)

# Execution layers. A check that logically happens after sealing cannot be reported inside the
# pre-seal results the seal covers; the layer makes that orderable and checkable.
LAYER_PRE_COLLECTION = "pre_collection_eligibility"
LAYER_DURING = "during_collection_fidelity"
LAYER_PRE_SEAL = "pre_seal_bound_by_envelope"
LAYER_FINALIZATION = "envelope_finalization_invariant"
LAYER_POST_SEAL = "post_seal_sterile_verification"
LAYER_ATTESTATION = "detached_attestation_assertion"
LAYERS = (LAYER_PRE_COLLECTION, LAYER_DURING, LAYER_PRE_SEAL, LAYER_FINALIZATION,
          LAYER_POST_SEAL, LAYER_ATTESTATION)

# Every field an AUTHORIZED specification must carry, filled and non-provisional. The draft has
# none of them, which is exactly why a status edit alone cannot reach a launch.
REQUIRED_AUTHORIZED_FIELDS = (
    "run_identity", "snapshot", "schedule", "condition_order", "replicates", "rates",
    "durations", "ports", "namespace", "refusal_policy", "evaluators", "required_envelope_roles",
    "collector_binding", "authorization_record",
)
# Values that mean "not decided yet". Any of these in a required field is a refusal.
PROVISIONAL_MARKERS = ("TBD", "TODO", "PROVISIONAL", "DRAFT", "PLACEHOLDER", "?", "")

# ---- allowlists. An unknown key is a refusal, at every level. ----
SPEC_ALLOWED_KEYS = frozenset((
    "schema", "spec_id", "spec_version", "status", "gates", "gate_inventory_sha256",
    "binding_sha256",
    # narrative / design fields the committed draft carries
    "provisional_candidate", "provisional_candidate_note", "status_note", "non_evidence",
    "engineering_only", "scope", "execution_layers", "execution_layer_note",
    "deliberately_absent", "deliberately_absent_note", "denied_workloads",
    "denied_workloads_note", "covariate_only", "covariate_only_note",
    "separately_named_not_a_gate", "integrity_not_authentication",
    # operational fields only an AUTHORIZED specification carries
    "run_identity", "snapshot", "schedule", "condition_order", "replicates", "rates",
    "durations", "ports", "namespace", "refusal_policy", "evaluators",
    "required_envelope_roles", "collector_binding", "authorization_record",
))
GATE_ALLOWED_KEYS = frozenset((
    "index", "id", "title", "kind", "layer", "thresholds", "thresholds_note", "domain",
))
SNAPSHOT_ALLOWED_KEYS = frozenset(("id", "sha256", "note"))
SCHEDULE_ALLOWED_KEYS = frozenset(("order", "note"))
PORTS_ALLOWED_KEYS = frozenset(("base", "count", "note"))
REFUSAL_POLICY_ALLOWED_KEYS = frozenset(("on_denied_workload", "on_ambiguous_process", "note"))
COLLECTOR_ALLOWED_KEYS = frozenset(("path", "sha256", "interpreter", "dependencies", "note"))
# The interpreter is an EXECUTABLE INPUT, not a convenience string. R4-3 reproduced a
# nonexistent interpreter path reaching argv[0] with no validation and no recheck.
INTERPRETER_ALLOWED_KEYS = frozenset(("path", "sha256", "note"))
EVALUATOR_ALLOWED_KEYS = frozenset(("module", "sha256", "note"))
AUTHZ_ALLOWED_KEYS = frozenset((
    "schema", "authority", "utc", "note",
    "authorizes_spec_sha256", "authorizes_binding_sha256", "authorizes_gate_inventory_sha256",
    "authorizes_gate_semantics_sha256", "authorized_required_envelope_roles",
    "authorized_evaluators", "authorized_collector", "authorized_interpreter",
    "authorized_launch_values", "authorized_bundled_verifier_sha256",
    "authorized_bootstrap_sha256",
))
AUTHZ_REQUIRED_PINS = (
    "authorizes_spec_sha256", "authorizes_binding_sha256", "authorizes_gate_inventory_sha256",
    "authorizes_gate_semantics_sha256", "authorized_required_envelope_roles",
    "authorized_evaluators", "authorized_collector", "authorized_interpreter",
    "authorized_launch_values", "authorized_bundled_verifier_sha256",
    "authorized_bootstrap_sha256", "authority", "utc",
)
# Every value that changes what a run DOES. The authorization record pins each one independently.
LAUNCH_BEARING_FIELDS = ("run_identity", "snapshot", "schedule", "condition_order", "replicates",
                         "rates", "durations", "ports", "namespace", "refusal_policy")

# The envelope-role floor comes from the module that ENFORCES it, not from a copy of the list.
CODE_ROLE_FLOOR = tuple(_ENV.AUTHORIZED_REQUIRED_ROLES)

NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
MIN_PORT, MAX_PORT = 1024, 65535


class SpecError(ValueError):
    """A specification that cannot be trusted. Always fatal; never downgraded to a warning."""


class AuthorizationError(SpecError):
    """The specification may be well formed, but it does not authorize anything."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def is_hex64(s):
    """EXACTLY 64 LOWERCASE hex characters, as every message about this predicate says.

    R5-17: `s.lower()` made the check case-insensitive while the refusals it produced claimed
    lowercase. A digest is a canonical string here; two spellings of the same value are two
    strings, and comparing them by equality elsewhere would then be inconsistent with this."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _is_int(v):
    """A real integer. `True` is an instance of int in Python and is NOT an integer here."""
    return isinstance(v, int) and not isinstance(v, bool)


def _is_finite_number(v):
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return False
    try:
        return math.isfinite(float(v))
    except (OverflowError, TypeError, ValueError):
        return False


# ------------------------------------------------------------------ deep freeze
def deep_freeze(obj):
    """A recursively read-only view. Mutating it raises instead of silently succeeding."""
    if isinstance(obj, dict):
        return types.MappingProxyType({k: deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return tuple(deep_freeze(v) for v in obj)
    return obj


# Defence in depth ONLY. A module global is readable by anything in this process; the real
# boundary is that no executable path accepts a caller-constructed object.
_CONSTRUCTION_TOKEN = object()


class FrozenSpec:
    """An authorized specification, bound to the exact bytes it was built from.

    Produced ONLY by bind_authorized. It is a *record of a completed bind*, never a permission
    slip: qual_runner_v2's executable entry point takes paths and external hashes and performs the
    bind itself, so possessing one of these grants nothing."""

    __slots__ = ("_doc", "path", "spec_sha256", "inventory_sha256", "semantics_sha256",
                 "binding_sha256", "authorization_sha256", "authorized_root", "bound_utc",
                 "bound_by_bind_authorized", "_authorization_path", "_authorization_claims",
                 "_authorization_binding")

    def __init__(self, doc, path, spec_sha256, inventory_sha256, semantics_sha256,
                 binding_sha256, authorization_sha256, authorized_root, bound_utc, token=None,
                 authorization_claims=None, authorization_path=None):
        bound = token is _CONSTRUCTION_TOKEN
        object.__setattr__(self, "_doc", deep_freeze(doc))
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "spec_sha256", spec_sha256)
        object.__setattr__(self, "inventory_sha256", inventory_sha256)
        object.__setattr__(self, "semantics_sha256", semantics_sha256)
        object.__setattr__(self, "binding_sha256", binding_sha256)
        object.__setattr__(self, "authorization_sha256", authorization_sha256)
        object.__setattr__(self, "authorized_root", authorized_root)
        object.__setattr__(self, "bound_utc", bound_utc)
        object.__setattr__(self, "bound_by_bind_authorized", bound)

        # These are claims READ from the already validated, separately pinned authorization
        # record. They are deliberately not copied from the specification: the bundled verifier
        # and bootstrap are runtime identities and the specification has no truthful value to
        # compare them with. A production consumer must compare these retained claims with its
        # independently supplied runtime pins. Merely reading this mapping grants no authority;
        # executable entry points still take paths and pins and call bind_authorized themselves.
        raw_claims = {}
        if bound and isinstance(authorization_claims, dict):
            raw_claims = {k: authorization_claims[k]
                          for k in sorted(AUTHZ_ALLOWED_KEYS) if k in authorization_claims}
        claims = deep_freeze(raw_claims)
        auth_path = (os.path.abspath(authorization_path)
                     if bound and isinstance(authorization_path, str) else None)
        object.__setattr__(self, "_authorization_path", auth_path)
        object.__setattr__(self, "_authorization_claims", claims)

        ai = raw_claims.get("authorized_interpreter") \
            if isinstance(raw_claims.get("authorized_interpreter"), dict) else {}
        summary = {
            "bound_by_bind_authorized": bool(bound),
            "spec_path": os.path.abspath(path) if bound else None,
            "authorized_spec_sha256": spec_sha256 if bound else None,
            "gate_inventory_sha256": inventory_sha256 if bound else None,
            "gate_semantics_sha256": semantics_sha256 if bound else None,
            "full_binding_sha256": binding_sha256 if bound else None,
            "authorization_record_path": auth_path,
            "authorization_record_sha256": authorization_sha256 if bound else None,
            "authorized_root": os.path.abspath(authorized_root) if bound else None,
            "interpreter_path": ai.get("path") if bound else None,
            "interpreter_sha256": ai.get("sha256") if bound else None,
            "bundled_verifier_sha256": (raw_claims.get(
                "authorized_bundled_verifier_sha256") if bound else None),
            "bootstrap_closure_sha256": (raw_claims.get(
                "authorized_bootstrap_sha256") if bound else None),
            "authorized_required_envelope_roles": (raw_claims.get(
                "authorized_required_envelope_roles") if bound else None),
            "authorized_evaluators": (raw_claims.get("authorized_evaluators")
                                      if bound else None),
            "authorized_collector": (raw_claims.get("authorized_collector")
                                     if bound else None),
            "authorized_interpreter": (raw_claims.get("authorized_interpreter")
                                       if bound else None),
            "authorized_launch_values": (raw_claims.get("authorized_launch_values")
                                         if bound else None),
            "authority": raw_claims.get("authority") if bound else None,
            "authorization_utc": raw_claims.get("utc") if bound else None,
        }
        object.__setattr__(self, "_authorization_binding", deep_freeze(summary))

    def __setattr__(self, *a):                        # pragma: no cover - trivially defensive
        raise TypeError("a FrozenSpec is immutable")

    def __getitem__(self, k):
        return self._doc[k]

    def get(self, k, default=None):
        return self._doc.get(k, default)

    def __contains__(self, k):
        return k in self._doc

    def keys(self):
        return self._doc.keys()

    @property
    def status(self):
        return self._doc.get("status")

    @property
    def spec_id(self):
        return self._doc.get("spec_id")

    @property
    def authorization_path(self):
        """Canonical path of the authorization record that bind_authorized opened."""
        return self._authorization_path

    @property
    def authorization_claims(self):
        """Recursively read-only snapshot of the validated authorization-record claims.

        This is evidence about the completed bind, not a permission object. Production entry
        points must never accept it in place of paths, external pins and a fresh bind.
        """
        return self._authorization_claims

    @property
    def authorization_binding(self):
        """Read-only, consumer-facing summary of the completed authorization bind."""
        return self._authorization_binding

    def authorization_binding_plain(self):
        """JSON-compatible copy of authorization_binding for a result or attestation."""
        return json.loads(json.dumps(
            self._authorization_binding,
            default=lambda o: dict(o) if hasattr(o, "keys") else list(o)))

    def as_plain(self):
        return json.loads(json.dumps(self._doc, default=lambda o: dict(o)))


def authorization_runtime_pin_failures(bound_spec, *, expect_bundled_verifier_sha256,
                                       expect_bootstrap_sha256):
    """Compare independently supplied runtime pins with a completed authorization bind.

    The authorization record, not the specification, is the object that prospectively claims
    which bundled verifier and bootstrap were authorized. This helper therefore compares against
    the immutable record snapshot retained by bind_authorized. It cannot turn an arbitrary
    FrozenSpec into an authorization and refuses any object not produced by that bind.
    """
    out = []
    if not isinstance(bound_spec, FrozenSpec) \
            or not getattr(bound_spec, "bound_by_bind_authorized", False):
        return ["runtime pins require a FrozenSpec produced by bind_authorized"]
    for label, value in (("expect_bundled_verifier_sha256",
                          expect_bundled_verifier_sha256),
                         ("expect_bootstrap_sha256", expect_bootstrap_sha256)):
        if not is_hex64(value):
            out.append("%s must be 64 lowercase hex characters" % label)
    if out:
        return out
    binding = bound_spec.authorization_binding
    if binding.get("bundled_verifier_sha256") != expect_bundled_verifier_sha256:
        out.append("the authorization record approves bundled verifier %s, not the externally "
                   "pinned %s"
                   % (str(binding.get("bundled_verifier_sha256"))[:16],
                      expect_bundled_verifier_sha256[:16]))
    if binding.get("bootstrap_closure_sha256") != expect_bootstrap_sha256:
        out.append("the authorization record approves bootstrap closure %s, not the externally "
                   "pinned %s"
                   % (str(binding.get("bootstrap_closure_sha256"))[:16],
                      expect_bootstrap_sha256[:16]))
    return out


# ------------------------------------------------------------------ digests
def gate_inventory_digest(gates):
    """Digest over the ORDERED gate IDENTITY inventory: index, id, title, kind, layer.

    Index catches a reorder, title catches a rename (a title is a claim), layer catches a check
    being moved across the seal boundary, and the count catches an omission. It deliberately does
    NOT cover thresholds; see gate_semantics_digest, which does."""
    lines = []
    for i, g in enumerate(gates):
        lines.append("%d\x1f%s\x1f%s\x1f%s\x1f%s"
                     % (i, g["id"], g["title"], g["kind"], g.get("layer", "")))
    return hashlib.sha256("\x1e".join(lines).encode("utf-8")).hexdigest()


def _canon(obj):
    """Deterministic JSON for hashing: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=lambda o: dict(o) if hasattr(o, "keys") else list(o))


def gate_semantics_digest(gates):
    """Digest over the FULL gate semantics -- thresholds and declared domains included.

    The identity digest cannot see a threshold move. This one can, and the authorization record
    must pin it independently of the file."""
    return hashlib.sha256(_canon(list(gates)).encode("utf-8")).hexdigest()


# Everything that could change what a run does or how it is judged. `gates` is hashed WHOLE, so
# thresholds are inside this digest even though they are outside gate_inventory_sha256.
BOUND_SEMANTICS = ("schema", "spec_id", "spec_version", "status", "run_identity", "snapshot",
                   "schedule", "condition_order", "replicates", "rates", "durations", "ports",
                   "namespace", "refusal_policy", "evaluators", "required_envelope_roles",
                   "collector_binding", "denied_workloads", "covariate_only", "gates")


def full_binding_digest(doc):
    """Digest over EVERY bound semantic, not just gate labels."""
    payload = {k: doc.get(k) for k in BOUND_SEMANTICS}
    return hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()


def _require(cond, msg, cls=SpecError):
    if not cond:
        raise cls(msg)


# ------------------------------------------------------------------ parsing
def parse_spec(raw_bytes, source="<bytes>"):
    """Structural validation of any specification, draft or authorized.

    Does NOT check file digests, does NOT touch the filesystem and does NOT decide authorization;
    see load_spec / deep_validate_authorized / bind_authorized."""
    try:
        doc = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        raise SpecError("%s: not valid UTF-8 JSON: %s: %s" % (source, type(e).__name__, e))
    _require(isinstance(doc, dict), "%s: top level is not an object" % source)
    unknown = sorted(set(doc) - SPEC_ALLOWED_KEYS)
    _require(not unknown,
             "%s: unknown top-level field(s) %s; a specification field must be allowlisted, so a "
             "new claim cannot arrive under a new name" % (source, unknown))
    _require(doc.get("schema") == SPEC_SCHEMA,
             "%s: schema %r != %r" % (source, doc.get("schema"), SPEC_SCHEMA))
    _require(doc.get("status") in STATUSES,
             "%s: status %r is not one of %s" % (source, doc.get("status"), list(STATUSES)))
    for field in ("spec_id", "spec_version", "gate_inventory_sha256", "gates"):
        _require(doc.get(field) not in (None, "", []), "%s: missing %s" % (source, field))
    _require(isinstance(doc.get("spec_id"), str) and doc["spec_id"].strip(),
             "%s: spec_id must be a non-empty string" % source)
    _require(isinstance(doc.get("spec_version"), str) and doc["spec_version"].strip(),
             "%s: spec_version must be a non-empty string" % source)
    _require(is_hex64(doc.get("gate_inventory_sha256")),
             "%s: gate_inventory_sha256 is not 64 lowercase hex characters" % source)
    _require("binding_sha256" in doc, "%s: missing binding_sha256" % source)
    _require(is_hex64(doc.get("binding_sha256")),
             "%s: binding_sha256 is not 64 lowercase hex characters" % source)

    gates = doc["gates"]
    _require(isinstance(gates, list), "%s: gates is not a list" % source)
    seen = {}
    for i, g in enumerate(gates):
        _require(isinstance(g, dict), "%s: gate %d is not an object" % (source, i))
        extra = sorted(set(g) - GATE_ALLOWED_KEYS)
        _require(not extra, "%s: gate %d carries unknown field(s) %s" % (source, i, extra))
        for field in ("index", "id", "title", "kind", "layer"):
            _require(g.get(field) not in (None, ""), "%s: gate %d missing %s" % (source, i, field))
        _require(_is_int(g["index"]) and g["index"] == i,
                  "%s: gate %d declares index %r -- the inventory is reordered or renumbered"
                  % (source, i, g["index"]))
        _require(isinstance(g["id"], str) and g["id"].strip(),
                 "%s: gate %d id must be a non-empty string" % (source, i))
        _require(isinstance(g["title"], str) and g["title"].strip(),
                 "%s: gate %s title must be a non-empty string" % (source, g["id"]))
        _require(isinstance(g["kind"], str),
                 "%s: gate %s kind must be a string" % (source, g["id"]))
        _require(isinstance(g["layer"], str),
                 "%s: gate %s layer must be a string" % (source, g["id"]))
        _require(g["kind"] in KINDS,
                 "%s: gate %s kind %r is not one of %s" % (source, g["id"], g["kind"],
                                                           list(KINDS)))
        _require(g["layer"] in LAYERS,
                 "%s: gate %s layer %r is not one of %s" % (source, g["id"], g["layer"],
                                                            list(LAYERS)))
        if g["id"] in seen:
            raise SpecError("%s: duplicate gate id %r at indices %d and %d"
                            % (source, g["id"], seen[g["id"]], i))
        seen[g["id"]] = i

    derived_inv = gate_inventory_digest(gates)
    _require(derived_inv == doc["gate_inventory_sha256"],
             "%s: declared gate_inventory_sha256 %s != %s recomputed from the %d gates -- the "
             "inventory was reordered, renamed, relayered, extended or truncated"
             % (source, doc["gate_inventory_sha256"][:16], derived_inv[:16], len(gates)))
    derived_bind = full_binding_digest(doc)
    _require(derived_bind == doc["binding_sha256"],
             "%s: declared binding_sha256 %s != %s recomputed over the bound semantics %s"
             % (source, str(doc["binding_sha256"])[:16], derived_bind[:16],
                list(BOUND_SEMANTICS)))
    doc["_derived_gate_inventory_sha256"] = derived_inv
    doc["_derived_gate_semantics_sha256"] = gate_semantics_digest(gates)
    doc["_derived_binding_sha256"] = derived_bind
    return doc


def load_spec(path, expect_file_sha256=None, expect_inventory_sha256=None,
              expect_binding_sha256=None):
    """Load and integrity-check. Expected values must come from OUTSIDE the file."""
    try:
        raw = open(path, "rb").read()
    except (OSError, TypeError, ValueError) as e:
        raise SpecError("%r: specification bytes are unavailable: %s: %s"
                        % (path, type(e).__name__, e))
    actual = sha256_bytes(raw)
    if expect_file_sha256 is not None and actual != expect_file_sha256:
        raise SpecError("%s: file sha256 %s != expected %s -- the specification bytes changed"
                        % (path, actual, expect_file_sha256))
    doc = parse_spec(raw, source=path)
    if (expect_inventory_sha256 is not None
            and doc["_derived_gate_inventory_sha256"] != expect_inventory_sha256):
        raise SpecError("%s: gate inventory sha256 %s != expected %s"
                        % (path, doc["_derived_gate_inventory_sha256"], expect_inventory_sha256))
    if (expect_binding_sha256 is not None
            and doc["_derived_binding_sha256"] != expect_binding_sha256):
        raise SpecError("%s: full binding sha256 %s != expected %s"
                        % (path, doc["_derived_binding_sha256"], expect_binding_sha256))
    doc["_spec_path"] = os.path.abspath(path)
    doc["_spec_sha256"] = actual
    return doc


# ------------------------------------------------------------------ authorization
def _provisional(value):
    if value is None:
        return True
    if isinstance(value, str) and value.strip().upper() in PROVISIONAL_MARKERS:
        return True
    if isinstance(value, (list, tuple, dict)) and len(value) == 0:
        return True
    return False


def _looks_provisional_anywhere(value):
    """A placeholder buried at any depth. {"threshold": "TBD"} is not a threshold."""
    if isinstance(value, str):
        return value.strip().upper() in PROVISIONAL_MARKERS
    if isinstance(value, dict):
        return any(_looks_provisional_anywhere(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_looks_provisional_anywhere(v) for v in value)
    return value is None


def _resolved_under(root, rel):
    """(abspath, reason) -- reason is None only for a safe relative path inside `root`."""
    if not isinstance(rel, str) or not rel:
        return None, "is not a non-empty string"
    why = _ENV.unsafe_relpath_reason(rel)
    if why:
        return None, why
    full = os.path.join(root, rel.replace("/", os.sep))
    if not _ENV.contained_in(root, full):
        return None, "resolves outside the authorized root"
    return full, None


def _check_pinned_file(out, label, root, rel, digest):
    """Existence + regular type + exact bytes, inside the authorized root."""
    if not is_hex64(digest):
        out.append("%s: sha256 %r is not 64 lowercase hex characters" % (label, digest))
        return None
    full, why = _resolved_under(root, rel)
    if why:
        out.append("%s: path %r %s" % (label, rel, why))
        return None
    kind = _ENV.file_kind(full)
    if kind != "regular":
        out.append("%s: %r is %s, not a regular file inside the authorized root"
                   % (label, rel, kind))
        return None
    got = sha256_file(full)
    if got != digest:
        out.append("%s: %r hashes to %s but the specification pins %s"
                   % (label, rel, got[:16], digest[:16]))
        return None
    return full


def deep_validate_authorized(doc, authorized_root):
    """Typed, on-disk validation of an AUTHORIZED document. Returns a list of failures.

    `authorized_root` is the directory every declared code path must resolve inside. Nothing here
    is a presence test: every pinned path is opened and hashed."""
    out = []
    root = os.path.abspath(authorized_root or "")
    if not os.path.isdir(root):
        return ["authorized_root %r is not a directory; nothing can be pinned against it" % root]

    for f in REQUIRED_AUTHORIZED_FIELDS:
        if f not in doc:
            out.append("required field %r is absent" % f)
        elif _provisional(doc.get(f)):
            out.append("required field %r is null, empty or provisional (%r)" % (f, doc.get(f)))
    if out:
        return out                                    # the typed checks below assume presence

    # ---- run identity ----
    if not isinstance(doc["run_identity"], str) \
            or _looks_provisional_anywhere(doc["run_identity"]):
        out.append("run_identity must be a non-placeholder string")

    # ---- snapshot ----
    snap = doc["snapshot"]
    if not isinstance(snap, dict):
        out.append("snapshot must be an object with an id and a sha256")
    else:
        bad = sorted(set(snap) - SNAPSHOT_ALLOWED_KEYS)
        if bad:
            out.append("snapshot carries unknown field(s) %s" % bad)
        if not isinstance(snap.get("id"), str) or _looks_provisional_anywhere(snap.get("id")):
            out.append("snapshot.id must be a non-placeholder string")
        if not is_hex64(snap.get("sha256")):
            out.append("snapshot.sha256 must be 64 lowercase hex characters")

    # ---- condition order and schedule ----
    order = doc["condition_order"]
    if not isinstance(order, list) or len(order) < 2 \
            or not all(isinstance(c, str) and c.strip() for c in order):
        out.append("condition_order must be a list of at least two non-empty condition names")
    elif len(set(order)) != len(order):
        out.append("condition_order repeats a condition: %r" % (order,))
    sched = doc["schedule"]
    if not isinstance(sched, dict):
        out.append("schedule must be an object carrying the order it schedules")
    else:
        bad = sorted(set(sched) - SCHEDULE_ALLOWED_KEYS)
        if bad:
            out.append("schedule carries unknown field(s) %s" % bad)
        if sched.get("order") != order:
            out.append("schedule.order %r does not equal condition_order %r"
                       % (sched.get("order"), order))

    # ---- replicates ----
    if not _is_int(doc["replicates"]) or doc["replicates"] < 1:
        out.append("replicates must be a positive integer, not %r" % (doc["replicates"],))

    # ---- rates and durations ----
    for field in ("rates", "durations"):
        v = doc[field]
        if not isinstance(v, dict) or not v:
            out.append("%s must be a non-empty object of finite positive numbers" % field)
            continue
        for k, x in sorted(v.items()):
            if not _is_finite_number(x) or x <= 0:
                out.append("%s[%r] = %r is not a finite positive number" % (field, k, x))

    # ---- ports ----
    ports = doc["ports"]
    if not isinstance(ports, dict):
        out.append("ports must be an object with a base port")
    else:
        bad = sorted(set(ports) - PORTS_ALLOWED_KEYS)
        if bad:
            out.append("ports carries unknown field(s) %s" % bad)
        base, count = ports.get("base"), ports.get("count", 1)
        if not _is_int(base) or not (MIN_PORT <= base <= MAX_PORT):
            out.append("ports.base %r is not an integer in [%d, %d]" % (base, MIN_PORT, MAX_PORT))
        elif not _is_int(count) or count < 1 or base + count - 1 > MAX_PORT:
            out.append("ports.count %r does not describe a range inside [%d, %d] from base %d"
                       % (count, MIN_PORT, MAX_PORT, base))

    # ---- namespace ----
    ns = doc["namespace"]
    if not isinstance(ns, str) or not NAMESPACE_RE.match(ns):
        out.append("namespace %r does not match %s" % (ns, NAMESPACE_RE.pattern))

    # ---- refusal policy ----
    pol = doc["refusal_policy"]
    if not isinstance(pol, dict):
        out.append("refusal_policy must be an object")
    else:
        bad = sorted(set(pol) - REFUSAL_POLICY_ALLOWED_KEYS)
        if bad:
            out.append("refusal_policy carries unknown field(s) %s" % bad)
        if pol.get("on_denied_workload") != "refuse":
            out.append("refusal_policy.on_denied_workload must be 'refuse', not %r"
                       % (pol.get("on_denied_workload"),))

    # ---- required envelope roles: a SUPERSET of the code floor ----
    roles = doc["required_envelope_roles"]
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        out.append("required_envelope_roles must be a list of role names")
    else:
        if len(set(roles)) != len(roles):
            out.append("required_envelope_roles repeats a role")
        unknown = sorted(set(roles) - set(_ENV.ROLES))
        if unknown:
            out.append("required_envelope_roles names unknown role(s) %s" % unknown)
        short = sorted(set(CODE_ROLE_FLOOR) - set(roles))
        if short:
            out.append("required_envelope_roles is missing %s; a specification may EXTEND the "
                       "code floor and may never shrink it" % short)

    # ---- gates and thresholds ----
    gates = doc.get("gates") or []
    for g in gates:
        gid = g.get("id")
        th = g.get("thresholds")
        if not isinstance(th, dict) or not th:
            out.append("gate %s carries no thresholds object; an authorized inventory cannot "
                       "leave a gate undefined" % gid)
            continue
        if _looks_provisional_anywhere(th):
            out.append("gate %s thresholds contain a placeholder: %r" % (gid, th))
            continue
        domain = g.get("domain") if isinstance(g.get("domain"), dict) else {}
        for k, v in sorted(th.items()):
            if not _is_finite_number(v):
                out.append("gate %s threshold %r = %r is not a finite number" % (gid, k, v))
                continue
            d = domain.get(k)
            if isinstance(d, dict):
                lo, hi = d.get("min"), d.get("max")
                if _is_finite_number(lo) and v < lo:
                    out.append("gate %s threshold %r = %r is below its declared minimum %r"
                               % (gid, k, v, lo))
                if _is_finite_number(hi) and v > hi:
                    out.append("gate %s threshold %r = %r is above its declared maximum %r"
                               % (gid, k, v, hi))

    # ---- evaluators: exactly the gate ids, each an existing pinned file ----
    ev = doc["evaluators"]
    claimed_paths = {}
    if not isinstance(ev, dict):
        out.append("evaluators must be a mapping from gate id to a pinned module")
    else:
        gate_ids = [g.get("id") for g in gates]
        missing = sorted(set(gate_ids) - set(ev))
        extra = sorted(set(ev) - set(gate_ids))
        if missing:
            out.append("evaluators has no entry for gate(s) %s" % missing)
        if extra:
            out.append("evaluators names %s, which are not gates in this inventory" % extra)
        for gid in sorted(set(gate_ids) & set(ev)):
            e = ev[gid]
            if not isinstance(e, dict):
                out.append("evaluator for %s is not an object" % gid)
                continue
            bad = sorted(set(e) - EVALUATOR_ALLOWED_KEYS)
            if bad:
                out.append("evaluator for %s carries unknown field(s) %s" % (gid, bad))
            full = _check_pinned_file(out, "evaluator %s" % gid, root, e.get("module"),
                                      e.get("sha256"))
            if full:
                claimed_paths.setdefault(os.path.normcase(full), []).append("evaluator %s" % gid)

    # ---- collector: an existing pinned file plus a COMPLETE dependency inventory ----
    cb = doc["collector_binding"]
    if not isinstance(cb, dict):
        out.append("collector_binding must be an object naming an audited collector")
    else:
        bad = sorted(set(cb) - COLLECTOR_ALLOWED_KEYS)
        if bad:
            out.append("collector_binding carries unknown field(s) %s" % bad)
        full = _check_pinned_file(out, "collector", root, cb.get("path"), cb.get("sha256"))
        if full:
            claimed_paths.setdefault(os.path.normcase(full), []).append("collector")
        interp = cb.get("interpreter")
        if interp is None:
            out.append("collector_binding.interpreter must name the exact interpreter that will "
                       "become argv[0], with its sha256; an unpinned executable input is not "
                       "pinned at all")
        elif not isinstance(interp, dict):
            out.append("collector_binding.interpreter must be an object with a path and a "
                       "sha256, not %s" % type(interp).__name__)
        else:
            bad = sorted(set(interp) - INTERPRETER_ALLOWED_KEYS)
            if bad:
                out.append("collector_binding.interpreter carries unknown field(s) %s" % bad)
            ipath, idig = interp.get("path"), interp.get("sha256")
            if not is_hex64(idig):
                out.append("collector_binding.interpreter.sha256 is not 64 lowercase hex "
                           "characters")
            elif not isinstance(ipath, str) or not ipath:
                out.append("collector_binding.interpreter.path must be a non-empty string")
            else:
                # An interpreter normally lives OUTSIDE the authorized root, so an absolute path
                # is permitted -- but it must be a real, regular, non-reparse file whose bytes
                # match, exactly like every other launch-bearing input.
                full = os.path.abspath(ipath)
                kind = _ENV.file_kind(full)
                if kind != "regular":
                    out.append("collector_binding.interpreter %r is %s, not a regular file"
                               % (ipath, kind))
                elif sha256_file(full) != idig:
                    out.append("collector_binding.interpreter %r hashes to %s but the "
                               "specification pins %s"
                               % (ipath, sha256_file(full)[:16], idig[:16]))
                else:
                    claimed_paths.setdefault(os.path.normcase(full), []).append("interpreter")
        deps = cb.get("dependencies")
        if not isinstance(deps, dict):
            out.append("collector_binding.dependencies must be a mapping of every project-local "
                       "source the collector may import, path -> sha256 (an empty object is a "
                       "positive claim that it imports none)")
        else:
            for rel in sorted(deps):
                f = _check_pinned_file(out, "collector dependency %r" % rel, root, rel, deps[rel])
                if f:
                    claimed_paths.setdefault(os.path.normcase(f), []).append("dependency %s" % rel)

    for norm, owners in sorted(claimed_paths.items()):
        if len(owners) > 1:
            out.append("%s all name the same file %r; every cross-reference must name one unique "
                       "object" % (owners, norm))

    # ---- the authorization record is a path, resolved later against its own pin ----
    ar = doc["authorization_record"]
    _, why = _resolved_under(root, ar) if isinstance(ar, str) else (None, "is not a string")
    if why:
        out.append("authorization_record %r %s" % (ar, why))
    return out


def completeness_failures(doc, authorized_root=None):
    """Why this document may not authorize a run. Empty means genuinely complete AND valid.

    `authorized_root` is required for the on-disk half. Without one this function can NEVER return
    an empty list, because R3-1 and R3-6 both walked straight through a presence-only check."""
    if authorized_root is None:
        base = []
        for f in REQUIRED_AUTHORIZED_FIELDS:
            if f not in doc:
                base.append("required field %r is absent" % f)
            elif _provisional(doc.get(f)):
                base.append("required field %r is null, empty or provisional (%r)"
                            % (f, doc.get(f)))
        for g in doc.get("gates") or []:
            if _provisional(g.get("thresholds")) \
                    or _looks_provisional_anywhere(g.get("thresholds")):
                base.append("gate %s carries no usable thresholds" % g.get("id"))
        base.append("no authorized_root was supplied, so the pinned evaluator, collector and "
                    "dependency files could not be opened and hashed; presence is not validity "
                    "and this document is NOT complete")
        return base
    return deep_validate_authorized(doc, authorized_root)


def is_authorized(doc):
    """Exact status only. 'authorized', 'AUTHORISED' and ' AUTHORIZED' are not authorization.

    Status alone is NEVER sufficient; see bind_authorized."""
    status = doc.status if isinstance(doc, FrozenSpec) else (doc or {}).get("status")
    return status == STATUS_AUTHORIZED


def refusal_reason(doc):
    """Why a live side effect is not permitted, or None when the document at least claims to be
    authorized. Completeness and binding are checked separately by bind_authorized."""
    if doc is None:
        return "no specification was loaded"
    status = doc.status if isinstance(doc, FrozenSpec) else (doc or {}).get("status")
    spec_id = doc.spec_id if isinstance(doc, FrozenSpec) else (doc or {}).get("spec_id")
    if status == STATUS_DRAFT:
        return ("specification %s is %s: it is a design document, not an authorisation, and no "
                "port check, process launch or result directory may be created from it"
                % (spec_id, STATUS_DRAFT))
    if status != STATUS_AUTHORIZED:
        return ("specification %s carries status %r, which is not the exact string %r"
                % (spec_id, status, STATUS_AUTHORIZED))
    return None


def load_authorization_record(path, expect_sha256=None):
    """A record, separate from the specification, saying exactly what was authorized.

    It is an INTEGRITY binding, not an identity claim: it ties an approval to exact bytes. It does
    not prove who approved anything, and this module has no signature verification.

    It must pin, INDEPENDENTLY of the specification file: the spec bytes, the full binding digest,
    the gate-identity digest, the gate-semantics digest (thresholds included), the required
    envelope roles, the evaluator inventory, the collector identity, the bundled verifier and
    every launch-bearing value. A specification's own self-pins are only consistency checks."""
    try:
        raw = open(path, "rb").read()
    except (OSError, TypeError, ValueError) as e:
        raise AuthorizationError("%r: authorization record bytes are unavailable: %s: %s"
                                 % (path, type(e).__name__, e))
    actual = sha256_bytes(raw)
    if expect_sha256 is not None and actual != expect_sha256:
        raise AuthorizationError("%s: authorization record sha256 %s != expected %s"
                                 % (path, actual, expect_sha256))
    try:
        rec = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise AuthorizationError("%s: unreadable: %s: %s" % (path, type(e).__name__, e))
    _require(isinstance(rec, dict), "%s: top level is not an object" % path, AuthorizationError)
    unknown = sorted(set(rec) - AUTHZ_ALLOWED_KEYS)
    _require(not unknown, "%s: unknown authorization field(s) %s" % (path, unknown),
             AuthorizationError)
    _require(rec.get("schema") == AUTHZ_SCHEMA,
             "%s: schema %r != %r" % (path, rec.get("schema"), AUTHZ_SCHEMA),
             AuthorizationError)
    for f in AUTHZ_REQUIRED_PINS:
        _require(not _provisional(rec.get(f)), "%s: missing %s" % (path, f), AuthorizationError)
    for f in ("authorizes_spec_sha256", "authorizes_binding_sha256",
              "authorizes_gate_inventory_sha256", "authorizes_gate_semantics_sha256",
              "authorized_bundled_verifier_sha256", "authorized_bootstrap_sha256"):
        _require(is_hex64(rec.get(f)),
                 "%s: %s is not 64 lowercase hex characters" % (path, f), AuthorizationError)
    _require(isinstance(rec.get("authorized_required_envelope_roles"), list),
             "%s: authorized_required_envelope_roles must be a list" % path, AuthorizationError)
    roles = rec["authorized_required_envelope_roles"]
    _require(all(isinstance(role, str) and role.strip() for role in roles),
             "%s: authorized_required_envelope_roles must contain only non-empty strings" % path,
             AuthorizationError)
    _require(len(set(roles)) == len(roles),
             "%s: authorized_required_envelope_roles contains duplicates" % path,
             AuthorizationError)
    _require(not (set(roles) - set(_ENV.ROLES)),
             "%s: authorized_required_envelope_roles names unknown roles %s"
             % (path, sorted(set(roles) - set(_ENV.ROLES))), AuthorizationError)
    _require(isinstance(rec.get("authorized_evaluators"), dict),
             "%s: authorized_evaluators must be a mapping of gate id -> sha256" % path,
             AuthorizationError)
    _require(all(isinstance(gid, str) and gid.strip() and is_hex64(dig)
                 for gid, dig in rec["authorized_evaluators"].items()),
             "%s: authorized_evaluators must map non-empty gate ids to lowercase sha256 values"
             % path, AuthorizationError)
    _require(isinstance(rec.get("authorized_collector"), dict),
             "%s: authorized_collector must be an object with a path and a sha256" % path,
             AuthorizationError)
    _require(isinstance(rec.get("authorized_interpreter"), dict),
             "%s: authorized_interpreter must be an object with a path and a sha256" % path,
             AuthorizationError)
    for name in ("authorized_collector", "authorized_interpreter"):
        pin = rec[name]
        _require(set(pin) == {"path", "sha256"},
                 "%s: %s must contain exactly ['path', 'sha256']" % (path, name),
                 AuthorizationError)
        _require(isinstance(pin.get("path"), str) and pin["path"],
                 "%s: %s.path must be a non-empty string" % (path, name),
                 AuthorizationError)
        _require(is_hex64(pin.get("sha256")),
                 "%s: %s.sha256 is not 64 lowercase hex characters" % (path, name),
                 AuthorizationError)
    _require(_ENV.unsafe_relpath_reason(rec["authorized_collector"]["path"]) is None,
             "%s: authorized_collector.path is not a safe relative path" % path,
             AuthorizationError)
    ipath = rec["authorized_interpreter"]["path"]
    _require("\x00" not in ipath and os.path.isabs(ipath)
             and os.path.normcase(os.path.normpath(ipath)) == os.path.normcase(ipath)
             and os.path.normcase(os.path.realpath(ipath)) == os.path.normcase(os.path.abspath(ipath)),
             "%s: authorized_interpreter.path must be a canonical absolute non-alias path" % path,
             AuthorizationError)
    _require(isinstance(rec.get("authorized_launch_values"), dict),
             "%s: authorized_launch_values must be an object" % path, AuthorizationError)
    missing = sorted(set(LAUNCH_BEARING_FIELDS) - set(rec["authorized_launch_values"]))
    _require(not missing, "%s: authorized_launch_values does not pin %s" % (path, missing),
             AuthorizationError)
    extra = sorted(set(rec["authorized_launch_values"]) - set(LAUNCH_BEARING_FIELDS))
    _require(not extra, "%s: authorized_launch_values carries unknown field(s) %s"
             % (path, extra), AuthorizationError)
    _require(isinstance(rec.get("authority"), str) and rec["authority"].strip(),
             "%s: authority must be a non-empty string" % path, AuthorizationError)
    _require(isinstance(rec.get("utc"), str) and rec["utc"].strip(),
             "%s: utc must be a non-empty string" % path, AuthorizationError)
    if "note" in rec:
        _require(isinstance(rec["note"], str), "%s: note must be a string" % path,
                 AuthorizationError)
    rec["_sha256"] = actual
    rec["_path"] = os.path.abspath(path)
    return rec


def cross_pin_failures(doc, rec):
    """Every disagreement between the authorization record and the specification on disk."""
    out = []
    if rec["authorizes_spec_sha256"] != doc["_spec_sha256"]:
        out.append("the authorization record approves spec bytes %s but the file on disk is %s"
                   % (rec["authorizes_spec_sha256"][:16], doc["_spec_sha256"][:16]))
    if rec["authorizes_binding_sha256"] != doc["_derived_binding_sha256"]:
        out.append("the authorization record approves binding %s but the file computes %s"
                   % (rec["authorizes_binding_sha256"][:16],
                      doc["_derived_binding_sha256"][:16]))
    if rec["authorizes_gate_inventory_sha256"] != doc["_derived_gate_inventory_sha256"]:
        out.append("the authorization record approves gate inventory %s but the file computes %s"
                   % (rec["authorizes_gate_inventory_sha256"][:16],
                      doc["_derived_gate_inventory_sha256"][:16]))
    if rec["authorizes_gate_semantics_sha256"] != doc["_derived_gate_semantics_sha256"]:
        out.append("the authorization record approves gate semantics %s but the file computes "
                   "%s -- a threshold moved"
                   % (rec["authorizes_gate_semantics_sha256"][:16],
                      doc["_derived_gate_semantics_sha256"][:16]))
    if sorted(rec["authorized_required_envelope_roles"]) != \
            sorted(doc.get("required_envelope_roles") or []):
        out.append("the authorization record approves roles %s but the specification declares %s"
                   % (sorted(rec["authorized_required_envelope_roles"]),
                      sorted(doc.get("required_envelope_roles") or [])))
    ev = {k: (v or {}).get("sha256") for k, v in (doc.get("evaluators") or {}).items()}
    if rec["authorized_evaluators"] != ev:
        out.append("the authorization record's evaluator inventory does not equal the "
                   "specification's")
    cb = doc.get("collector_binding") or {}
    ac = rec["authorized_collector"]
    if ac.get("path") != cb.get("path") or ac.get("sha256") != cb.get("sha256"):
        out.append("the authorization record approves collector %r/%s but the specification "
                   "names %r/%s" % (ac.get("path"), str(ac.get("sha256"))[:16],
                                    cb.get("path"), str(cb.get("sha256"))[:16]))
    ai = rec.get("authorized_interpreter") or {}
    ci = (cb.get("interpreter") or {}) if isinstance(cb.get("interpreter"), dict) else {}
    if ai.get("path") != ci.get("path") or ai.get("sha256") != ci.get("sha256"):
        out.append("the authorization record approves interpreter %r/%s but the specification "
                   "names %r/%s" % (ai.get("path"), str(ai.get("sha256"))[:16],
                                    ci.get("path"), str(ci.get("sha256"))[:16]))
    for f in LAUNCH_BEARING_FIELDS:
        if rec["authorized_launch_values"].get(f) != doc.get(f):
            out.append("launch-bearing field %r differs: the authorization record pins %r, the "
                       "specification says %r"
                       % (f, rec["authorized_launch_values"].get(f), doc.get(f)))
    return out


def bind_authorized(spec_path, expect_file_sha256, expect_inventory_sha256,
                    expect_binding_sha256, authorization_path, expect_authorization_sha256,
                    authorized_root, clock=None):
    """RE-READ the exact bytes and return an immutable FrozenSpec, or raise.

    Every pin is mandatory, `authorized_root` included: without a root the pinned evaluator,
    collector and dependency files cannot be opened, and an unopened pin is not a pin."""
    import time
    clock = clock or time.time
    for name, val in (("expect_file_sha256", expect_file_sha256),
                      ("expect_inventory_sha256", expect_inventory_sha256),
                      ("expect_binding_sha256", expect_binding_sha256),
                      ("authorization_path", authorization_path),
                      ("expect_authorization_sha256", expect_authorization_sha256),
                      ("authorized_root", authorized_root)):
        _require(not _provisional(val),
                 "an authorized bind requires %s to be supplied independently of the "
                 "specification file" % name, AuthorizationError)

    doc = load_spec(spec_path, expect_file_sha256, expect_inventory_sha256, expect_binding_sha256)
    reason = refusal_reason(doc)
    if reason is not None:
        raise AuthorizationError(reason)

    if not isinstance(authorized_root, str) or not authorized_root \
            or "\x00" in authorized_root or not os.path.isabs(authorized_root):
        raise AuthorizationError(
            "authorized_root must be a canonical absolute non-alias path, not %r"
            % (authorized_root,))
    try:
        normalized_root = os.path.normpath(authorized_root)
        lexical_root = os.path.abspath(normalized_root)
        resolved_root = os.path.realpath(lexical_root)
    except (OSError, TypeError, ValueError) as e:
        raise AuthorizationError(
            "authorized_root %r cannot be resolved as a canonical path: %s: %s"
            % (authorized_root, type(e).__name__, e))
    if os.path.normcase(normalized_root) != os.path.normcase(authorized_root) \
            or os.path.normcase(resolved_root) != os.path.normcase(lexical_root):
        raise AuthorizationError(
            "authorized_root %r is not a canonical absolute non-alias path"
            % authorized_root)
    root = resolved_root
    missing = deep_validate_authorized(doc, root)
    if missing:
        raise AuthorizationError(
            "%s claims AUTHORIZED but is incomplete or invalid, so it authorizes nothing: %s"
            % (doc.get("spec_id"), missing))

    # R4-3: the specification may DECLARE authorization_record at one safe relative path while
    # the caller opens a different file entirely. The two must be the same object.
    declared = doc.get("authorization_record")
    want, why = _resolved_under(root, declared) if isinstance(declared, str) else (None, "?")
    if why or want is None:
        raise AuthorizationError("authorization_record %r is not a safe path inside the "
                                 "authorized root: %s" % (declared, why))
    got = os.path.abspath(authorization_path)
    if _ENV._norm(got) != _ENV._norm(want):
        raise AuthorizationError(
            "the specification declares authorization_record %r, which resolves to %r, but the "
            "caller supplied %r. An authorization record the specification does not name is not "
            "that specification's authorization" % (declared, want, got))

    rec = load_authorization_record(authorization_path, expect_authorization_sha256)
    bad = cross_pin_failures(doc, rec)
    if bad:
        raise AuthorizationError("the authorization record does not match the specification: %s"
                                 % bad)

    return FrozenSpec(doc, os.path.abspath(spec_path), doc["_spec_sha256"],
                      doc["_derived_gate_inventory_sha256"],
                      doc["_derived_gate_semantics_sha256"], doc["_derived_binding_sha256"],
                      rec["_sha256"], root,
                      __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ",
                                                  __import__("time").gmtime(clock())),
                      token=_CONSTRUCTION_TOKEN, authorization_claims=rec,
                      authorization_path=rec["_path"])
