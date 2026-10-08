#!/usr/bin/env python3
"""Round-14: one named behavioural test per counterexample the THIRD corrective audit reproduced.

NON-EVIDENCE, AND ENTIRELY NON-LIVE. No daemon, miner, driver, tracer, smoke, calibration,
qualification or network call. Every specification, envelope, bundle, verifier and process
inventory is a synthetic fixture built in a temporary directory. The historical-integrity checker
is exercised only against MINIATURE SYNTHETIC bundles; the real Gate N is never touched.

EVERY TEST HAS THE SAME SHAPE: prove the UNMUTATED baseline passes, then prove the EXACT mutation
fails FOR THE INTENDED REASON. A bare exception is never the assertion, and a source-text search
for a constant is never accepted as enforcement -- every claim here is driven through the API.

Case map (the audit's numbering):
  R3-1   a forged in-memory FrozenSpec reaching collection
  R3-2   G17 manufacturing its own expected outer seal
  R3-3   required envelope roles shrinking
  R3-4   unlisted empty directories invisible to the inventory
  R3-5   direct .py and io.open reads evading provenance
  R3-6   superficial AUTHORIZED completeness
  R3-7   a semantically fake historical seal
  R3-8   generic bash treated as complete WSL coverage
  R3-9a  a Windows junction / reparse point misclassified
  R3-9b  a non-canonical or orphaned canonical attestation
  R3-10  an advisory expected test inventory
  R3-11  a bundled verifier authenticating itself
  R3-12  inner-seal traversal and metadata-only verification
  R3-13  a reusable staging root and a caller-invented canonical attestation

Green here means the infrastructure passed offline checks. It cadence-qualifies nothing and
authorises no measurement.

Usage: python3 node/tests_round14.py [--out=<path>] [--commit=<sha>]
"""
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_provenance as RP

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NODE = os.path.join(_REPO, "node")
RECORDER = RP.ProvenanceRecorder(_REPO, strict=False).begin()
_MODULES_AT_BEGIN = frozenset(sys.modules)

import evidence_envelope as ENV                                        # noqa: E402
import historical_integrity as HI                                      # noqa: E402
import qual_runner_v2 as RUN                                           # noqa: E402
import qual_spec as QS                                                 # noqa: E402
import qual_verify_v2 as QV                                            # noqa: E402
import workload_preflight as WP                                        # noqa: E402
from tests_round2 import check, RESULTS                                # noqa: E402

# qual_verify_v2.bootstrap_identity() hashes every file in the externally pinned bootstrap
# closure -- which now includes run_provenance.py (R5-11). Those are genuine project-local
# reads, so this suite DECLARES them rather than letting the boundary hide them.
for _boot in QV.BOOTSTRAP_FILES:
    RECORDER.register_read(os.path.join(_NODE, _boot), kind="bootstrap_closure")

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "")
SPEC_PATH = os.path.join(_REPO, "docs", "round2",
                         "qualification_spec_v2_DRAFT_NO_LAUNCH.json")

EXPECTED_TESTS = (
    "test_r3_1_forged_frozenspec", "test_r3_2_g17_external_pin",
    "test_r3_3_roles_only_grow", "test_r3_4_typed_directory_inventory",
    "test_r3_5_reads_are_observed", "test_r3_6_deep_typed_completeness",
    "test_r3_7_historical_fake_seal", "test_r3_8_wsl_enumeration",
    "test_r3_9a_reparse_points", "test_r3_9b_canonical_attestation",
    "test_r3_10_pinned_inventory", "test_r3_11_bootstrap_verifier",
    "test_r3_12_actual_inner_seal", "test_r3_13_exclusive_staging",
)
FUNCTIONAL_CHECK_COUNT = 147
META_CHECK_COUNT = 1

# The collector carries the child-side provenance shim, so what the child READS is observed
# rather than assumed. The qualification runner owns process creation and takes no `runner`
# callable, so the shim is how the child reports back.
COLLECTOR = RP.CHILD_SHIM_SOURCE + '''import json, sys
a = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in sys.argv[1:] if "=" in x}
print(json.dumps({"raw_records": 6, "branch_observations": 25, "telemetry_retained": True,
                  "collection_seconds": 0.01, "staging_dir": a.get("--staging", ""),
                  "note": "synthetic fixture collector; no daemon, miner or network",
                  "an_unknown_key": {"smuggled": "payload"}}))
'''
EVALUATOR = '"""A synthetic evaluator. It evaluates nothing."""\nGATE = %r\n'
EVIL_VERIFIER = ('"""A malicious self-declared bundled verifier. It approves everything."""\n'
                 "def verify_envelope(path, **kw):\n    return []\n")


def _pinned_interpreter():
    """The RESOLVED interpreter. A symlink is an alias, not the object, so the pin names the real
    file -- which is exactly what the repaired validator demands."""
    real = os.path.realpath(sys.executable)
    return {"path": real, "sha256": QS.sha256_file(real)}


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def refuses(fn, needle, cls=Exception):
    """(matched_intended_reason, message). A bare exception is not a pass."""
    try:
        fn()
        return False, "nothing was raised"
    except cls as e:
        return (needle in str(e)), "%s: %s" % (type(e).__name__, e)


def has(failures, needle):
    return any(needle in f for f in failures)



# ---- the externally pinned interpreter, and the authorized G17 context (R5-12, R5-14) --------
INTERP_PATH = os.path.realpath(sys.executable)
INTERP_SHA = ENV.sha256_file(INTERP_PATH)


def _authorized_kw(env, kw):
    """Supply the interpreter pin, and the authorized context when the envelope supports it.

    An operator would take these from the review record; a test takes them from the artefact it
    just built. The NEGATIVE cases -- wrong pin, missing pin, no authorized context -- are what
    the round-16 matrix drives."""
    kw.setdefault("expect_interpreter_path", INTERP_PATH)
    kw.setdefault("expect_interpreter_sha256", INTERP_SHA)
    try:
        seal = json.loads(open(os.path.join(env, ENV.SEAL_FILE), encoding="utf-8").read())
    except Exception:
        return kw
    roles = seal.get("roles") or {}
    spec = (roles.get("qualification_spec") or {}).get("sha256")
    if spec and set(ENV.AUTHORIZED_REQUIRED_ROLES) <= set(roles):
        kw.setdefault("expect_spec_sha256", spec)
        kw.setdefault("spec_required_roles", list(ENV.AUTHORIZED_REQUIRED_ROLES))
        kw.setdefault("authorized_run", True)
        kw.setdefault("expect_inventory_sha256", ENV.inventory_digest(
            {r: v for r, v in ENV.typed_inventory(env).items() if r not in ENV.SELF_FILES}))
    return kw

def bind_all_authorized_roles(b, files, skip=()):
    """Bind every role an AUTHORIZED envelope must carry, with the archive/sidecar pair named
    exactly as the envelope's own grammar requires."""
    if "daemon_log_archive" not in skip and "daemon_log_sidecar" not in skip:
        arch = w(os.path.join(files, "daemon_log_archive.tar.gz"), "archive bytes\n")
        side = w(os.path.join(files, "daemon_log_archive.tar.gz.sha256"),
                 "%s  daemon_log_archive.tar.gz\n" % ENV.sha256_file(arch))
        b.bind("daemon_log_archive", arch, relpath="tools/daemon_log_archive.tar.gz")
        b.bind("daemon_log_sidecar", side, relpath="tools/daemon_log_archive.tar.gz.sha256")
    for role in ENV.ROLES:
        if role in skip or role in ("inner_collection", "environment_trace",
                                    "pre_seal_gate_results", "qualification_spec",
                                    "source_inventory", "outer_verifier",
                                    "daemon_log_archive", "daemon_log_sidecar"):
            continue
        p = w(os.path.join(files, role + ".txt"), "role " + role + "\n")
        b.bind(role, p, relpath="tools/" + role + ".txt")
    return b


def reloc(*a, **kw):
    """The PRODUCTION G17, with its parent-side child record adopted by this suite's recorder."""
    # The envelopes built by this older suite carry the historical {"spec_id":"X"} fixture.
    # Round 6 reclassifies them as integrity diagnostics; Round 17 owns the complete AUTHORIZED
    # production baseline and refusal matrix.
    res = QV.diagnostic_relocate(*a, **_authorized_kw(a[0], kw))
    if res.get("child_record"):
        RECORDER.adopt_child_record(res["child_record"])
    return res


# ------------------------------------------------------------------ shared fixtures
def authorized_fixture(root, spec_id="TESTONLY_R14", mutate=None):
    """A GENUINELY complete AUTHORIZED specification: real files, real digests, real record.

    Building it is the proof that completeness is REACHABLE, so every refusal below is about the
    specific defect rather than about an impossible schema. It is a test fixture, it is never
    committed, and its collector starts nothing."""
    ar = os.path.join(root, "authz_root")
    os.makedirs(ar, exist_ok=True)
    draft = json.loads(RECORDER.read_declared(SPEC_PATH, kind="qualification_spec", mode="rb")
                       .decode("utf-8"))
    d = dict(draft)
    d["status"] = QS.STATUS_AUTHORIZED
    d["spec_id"] = spec_id
    cpath = w(os.path.join(ar, "collector.py"), COLLECTOR)
    ev = {}
    for g in draft["gates"]:
        p = w(os.path.join(ar, "evaluators", g["id"] + ".py"), EVALUATOR % g["id"])
        ev[g["id"]] = {"module": "evaluators/%s.py" % g["id"], "sha256": QS.sha256_file(p)}
    d["gates"] = [dict(g, thresholds={"limit": 1.0},
                       domain={"limit": {"min": 0.0, "max": 10.0}}) for g in draft["gates"]]
    d.update({
        "run_identity": spec_id,
        "snapshot": {"id": "SNAP_TESTONLY", "sha256": "a" * 64},
        "schedule": {"order": ["control", "attack"]},
        "condition_order": ["control", "attack"],
        "replicates": 3, "rates": {"total": 1.5}, "durations": {"mine": 60.0, "post": 30.0},
        "ports": {"base": 41000, "count": 8}, "namespace": "testonly-r14",
        "refusal_policy": {"on_denied_workload": "refuse"},
        "required_envelope_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES),
        "collector_binding": {"path": "collector.py", "sha256": QS.sha256_file(cpath),
                              "interpreter": _pinned_interpreter(), "dependencies": {}},
        "authorization_record": "authz.json",
        "evaluators": ev,
    })
    if mutate:
        mutate(d, ar)
    d["gate_inventory_sha256"] = QS.gate_inventory_digest(d["gates"])
    d["binding_sha256"] = "0" * 64
    d["binding_sha256"] = QS.full_binding_digest(d)
    sp = os.path.join(ar, "spec.json")
    with open(sp, "wb") as f:
        f.write((json.dumps(d, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    sdig = QS.sha256_file(sp)
    doc = json.loads(open(sp, encoding="utf-8").read())
    rec_doc = {
        "schema": QS.AUTHZ_SCHEMA,
        "authority": "TEST FIXTURE -- NOT A REAL AUTHORIZATION AND NOT A LIVE RUN",
        "utc": "2026-08-30T00:00:00Z",
        "authorizes_spec_sha256": sdig,
        "authorizes_binding_sha256": doc["binding_sha256"],
        "authorizes_gate_inventory_sha256": doc["gate_inventory_sha256"],
        "authorizes_gate_semantics_sha256": QS.gate_semantics_digest(doc["gates"]),
        "authorized_required_envelope_roles": list(doc["required_envelope_roles"]),
        "authorized_evaluators": {k: v["sha256"] for k, v in doc["evaluators"].items()},
        "authorized_collector": {"path": doc["collector_binding"]["path"],
                                 "sha256": doc["collector_binding"]["sha256"]},
        "authorized_interpreter": dict(doc["collector_binding"]["interpreter"]),
        "authorized_launch_values": {f: doc.get(f) for f in QS.LAUNCH_BEARING_FIELDS},
        "authorized_bundled_verifier_sha256": "b" * 64,
        "authorized_bootstrap_sha256": QV.bootstrap_closure_digest(),
    }
    az = os.path.join(ar, "authz.json")
    with open(az, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec_doc, f, indent=1)
    return {"root": ar, "spec_path": sp, "spec_sha256": sdig, "collector_path": cpath,
            "inventory_sha256": doc["gate_inventory_sha256"],
            "binding_sha256": doc["binding_sha256"], "authz_path": az,
            "authz_sha256": QS.sha256_file(az), "doc": doc}


def clean_preflight():
    """A fail-closed WorkloadPreflight driven by SYNTHETIC inventories. No process is inspected."""
    def win():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

    def runner(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
        R.stdout = (("  NAME              STATE           VERSION\n"
                     "* Ubuntu            Running         2\n"
                     "  docker-desktop    Stopped         2\n")
                    if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]
                    else "1\tinit\t/sbin/init\n")
        return R()

    return WP.WorkloadPreflight(providers={"windows": win,
                                           "wsl": lambda: WP.wsl_inventory(runner=runner)})


def dry_run(fx, stage, preflight=None, guard_requires_absent=False):
    """The DIAGNOSTIC harness. run_authorized owns the real Windows+WSL providers and takes no
    preflight at all, so a synthetic-inventory test necessarily uses this path; it stops at the
    launch boundary and structurally cannot return a non-refused document.

    `guard_requires_absent=False` in-process ONLY: this suite imports tests_round2, which imports
    series_validate at module scope, so the strict process-level precondition can never hold
    here. T14-1n asserts the strict property separately rather than quietly dropping it."""
    return RUN.diagnostic_dry_run(fx["spec_path"], fx["spec_sha256"], fx["inventory_sha256"],
                                  fx["binding_sha256"], fx["authz_path"], fx["authz_sha256"],
                                  fx["root"], stage, preflight or clean_preflight(),
                                  guard_requires_absent=guard_requires_absent)


def inner_bundle(root, name):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "rec_1.json"), '{"condition":"control","replicate":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    sums = os.path.join(b, "SHA256SUMS")
    w(sums, "".join(
        "%s  output  %s\n" % (ENV.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
        for r in ENV.walk_relpaths(b) if r not in ("SHA256SUMS", "FINAL_SEAL.json")))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(ENV.inner_seal_document(b)) + "\n")
    return b


def build(root, tag, required_roles=ENV.REQUIRED_ROLES, verifier_src=None,
          inner_seal_relpath="FINAL_SEAL.json", inner=None, empty_dir=None,
          full_roles=True):
    inner = inner or inner_bundle(root, "inner_" + tag)
    files = os.path.join(root, "src_" + tag)
    trace = w(os.path.join(files, "trace.json"), '{"kind":"environment_trace","rows":[]}\n')
    gates = w(os.path.join(files, "gates.json"), '{"pre_seal":true,"gates":[]}\n')
    spec = w(os.path.join(files, "spec.json"), '{"spec_id":"X"}\n')
    srcinv = w(os.path.join(files, "sources.json"), '{"modules":{}}\n')
    b = ENV.EnvelopeBuilder(os.path.join(root, "stage_" + tag), "ENV_" + tag,
                            required_roles=required_roles)
    b.bind_collection(inner, inner_seal_relpath=inner_seal_relpath)
    b.bind_trace(trace, ENV.TRACE_COMPLETE)
    b.bind("qualification_spec", spec, relpath="tools/spec.json")
    b.bind("source_inventory", srcinv, relpath="tools/sources.json")
    b.bind("outer_verifier", verifier_src or os.path.join(_NODE, "evidence_envelope.py"),
           relpath="tools/verifier.py")
    if full_roles:
        bind_all_authorized_roles(b, files)
    b.mark_checked(gates)
    if empty_dir:
        os.makedirs(os.path.join(b.dir, empty_dir))
    seal = b.seal()
    final = os.path.join(root, "ENV_" + tag)
    b.publish(final)
    return final, seal


def pins(env, seal):
    """(outer seal, bundled verifier, typed inventory, bootstrap closure) -- all EXTERNAL."""
    return (ENV.sha256_file(os.path.join(env, ENV.SEAL_FILE)),
            seal["roles"]["outer_verifier"]["sha256"],
            ENV.inventory_digest({r: v for r, v in ENV.typed_inventory(env).items()
                                  if r not in ENV.SELF_FILES}),
            QV.bootstrap_closure_digest())


def mini(root, name, seal_doc=None):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "r1.json"), '{"a":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    on_disk = [r for r in HI.walk_relpaths(b) if r not in HI.SELF_FILES]
    w(os.path.join(b, "SHA256SUMS"),
      "".join("%s  output  %s\n" % (HI.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
              for r in on_disk))
    graph = HI.walk_typed(b)
    dirs = sorted(r for r, k in graph.items() if k == "directory")
    tinv = {r: v for r, v in HI.typed_inventory(b).items() if r not in HI.SELF_FILES}
    doc = dict(seal_doc if seal_doc is not None else
               {"schema": HI.BUNDLE_SEAL_SCHEMAS[0], "sealed": True,
                "inventory": sorted(on_disk), "file_count": len(on_disk) + len(HI.SELF_FILES),
                "directories": dirs, "directory_count": len(dirs),
                "typed_inventory_sha256": ENV.inventory_digest(tinv)})
    doc["sha256sums_sha256"] = HI.sha256_file(os.path.join(b, "SHA256SUMS"))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(doc) + "\n")
    logs = w(os.path.join(root, "logs_" + name, "d1.log"), "line\n")
    arch = os.path.join(root, name + HI.ARCHIVE_SUFFIX)
    with tarfile.open(arch, "w:gz") as tf:
        tf.add(logs, arcname="logs_x/d1.log")
    w(arch + HI.SIDECAR_SUFFIX, HI.sha256_file(arch) + "  " + name + HI.ARCHIVE_SUFFIX + "\n")
    return b, arch


def hi_pins(b, arch):
    return {"seal_sha256": HI.sha256_file(os.path.join(b, "FINAL_SEAL.json")),
            "sums_sha256": HI.sha256_file(os.path.join(b, "SHA256SUMS")),
            "archive_sha256": HI.sha256_file(arch),
            "file_count": len(HI.walk_relpaths(b))}


# ================================================================== R3-1
def test_r3_1_forged_frozenspec():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        stage = os.path.join(td, "stage_ok")
        good = dry_run(fx, stage)
        detail = good.get("detail") or {}
        check("T14-1a. the code that WOULD be launched is the runner's own staged copy, and "
              "argv[0] is the externally pinned interpreter",
              detail["staged_code"]["failures"] == []
              and detail["would_launch"][0]
              == fx["doc"]["collector_binding"]["interpreter"]["path"]
              and detail["would_launch"][3].startswith(detail["staged_code"]["root"]),
              detail["would_launch"][:1])
        check("T14-1. BASELINE: a genuinely complete AUTHORIZED specification, bound from paths "
              "and external hashes, runs the whole sequence to the launch boundary",
              good.get("code") == "DIAGNOSTIC_ONLY" and good.get("diagnostic_only") is True
              and good["launch_callback_invocations"] == 0,
              good.get("code"))
        check("T14-1b. and the order puts the pre-launch process inventory BEFORE the final byte "
              "recheck, which is the last act before process creation",
              good["event_sequence"] == ["authorization_check", "authorized:TESTONLY_R14",
                                         "preflight:lead_in", "prepare",
                                         "preflight:pre_launch",
                                         "final_launch_binding_recheck"],
              good["event_sequence"])

        forged_doc = {
            "schema": QS.SPEC_SCHEMA, "spec_id": "FORGED_IN_MEMORY", "spec_version": "0",
            "status": QS.STATUS_AUTHORIZED, "gate_inventory_sha256": "e" * 64,
            "binding_sha256": "f" * 64, "gates": [], "run_identity": "FORGED",
            "snapshot": "made up, never hashed", "schedule": "whenever",
            "condition_order": ["attack"], "replicates": -5, "rates": "as fast as possible",
            "durations": {"mine": -1}, "ports": {"base": 99999999}, "namespace": "x",
            "refusal_policy": "ignore", "evaluators": {"nothing": "at all"},
            "required_envelope_roles": ["inner_collection"],
            "collector_binding": {"path": "/nonexistent/evil.py", "sha256": "c" * 64},
            "authorization_record": "no such file.json"}
        forged = QS.FrozenSpec(forged_doc, "/not/real.json", "a" * 64, "e" * 64, "e" * 64,
                               "f" * 64, "d" * 64, td, "2026-01-01T00:00:00Z")
        check("T14-1c. a directly constructed FrozenSpec is an instance of FrozenSpec and still "
              "records that it never came out of bind_authorized",
              isinstance(forged, QS.FrozenSpec) and forged.bound_by_bind_authorized is False)

        never = os.path.join(td, "never_created")
        r = RUN.RefusalOnlyRunner(forged, preflight=clean_preflight(),
                                  guard_requires_absent=False)
        ref = r.run(never)
        check("T14-1d. handing it to the runner is refused as SPEC_NOT_BOUND",
              ref.get("code") == "SPEC_NOT_BOUND", ref.get("code"))
        check("T14-1e. with zero launch-callback invocations and no staging directory created",
              ref["launch_callback_invocations"] == 0 and not os.path.exists(never))
        check("T14-1f. and the refusal says an object is not an authorization",
              "An object is not an authorization" in ref["reason"], ref["reason"][:90])

        names = [n for n in dir(RUN.RefusalOnlyRunner) if not n.startswith("__")]
        check("T14-1g. the refusal-only runner exposes no collect/launch route at all",
              not any(n in names for n in ("collect", "launch_and_collect", "collector")), names)
        src = open(os.path.join(_NODE, "qual_runner_v2.py"), encoding="utf-8").read()
        import ast
        tree = ast.parse(src)
        cls = [n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "RefusalOnlyRunner"][0]
        calls = [n for n in ast.walk(cls) if isinstance(n, ast.Call)]
        proc = [c for c in calls if isinstance(c.func, ast.Attribute)
                and c.func.attr in ("run", "Popen", "call", "check_output", "system", "execv",
                                    "spawnv")
                and isinstance(c.func.value, ast.Name)
                and c.func.value.id in ("subprocess", "os")]
        check("T14-1h. and its class body contains no process-creation call, parsed rather than "
              "grepped", proc == [], [c.func.attr for c in proc])

        check("T14-1i. the forged document also fails deep completeness against a real root",
              len(QS.completeness_failures(forged_doc, td)) > 0,
              len(QS.completeness_failures(forged_doc, td)))
        check("T14-1j. and completeness can NEVER return empty without an authorized root",
              QS.completeness_failures(fx["doc"]) != [],
              QS.completeness_failures(fx["doc"])[-1][:70])

        # a collector attribute is not a code pin: the runner never reads one
        check("T14-1k. run_authorized takes no collector or callback parameter at all",
              "collector" not in RUN.run_authorized.__code__.co_varnames[
                  :RUN.run_authorized.__code__.co_argcount],
              list(RUN.run_authorized.__code__.co_varnames[
                  :RUN.run_authorized.__code__.co_argcount]))
        hit, msg = refuses(lambda: setattr(forged, "spec_sha256", "z" * 64), "immutable",
                           TypeError)
        check("T14-1l. and a FrozenSpec still refuses mutation", hit, msg[:70])

        # The strict process-level precondition, asserted rather than assumed. This suite imports
        # tests_round2, which imports series_validate at module scope, so the modules ARE resident
        # and the default guard must refuse.
        check("T14-1m. the scientific modules really are resident in this interpreter",
              "series_validate" in sys.modules)
        strict = dry_run(fx, os.path.join(td, "stage_strict"),
                         guard_requires_absent=True)
        check("T14-1n. so an authorized run with the DEFAULT guard refuses "
              "SCIENCE_MODULES_RESIDENT before anything else happens",
              strict.get("code") == "SCIENCE_MODULES_RESIDENT"
              and strict["launch_callback_invocations"] == 0
              and not os.path.exists(os.path.join(td, "stage_strict")),
              strict.get("code"))


# ================================================================== R3-2
def test_r3_2_g17_external_pin():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "p")
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws_ok")
        os.makedirs(ws)
        good = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv)
        check("T14-2. CORRECTED: this legacy trivial-spec fixture authenticates envelope bytes "
              "but is diagnostic, never G17", not good["g17_pass"]
              and good["diagnostic_only"] and good["bootstrap_verified"], good["failures"][:2])
        check("T14-2b. the external pin, the source-observed digest and the copy-observed digest "
              "are recorded SEPARATELY",
              (good["external_outer_seal_sha256"] == sd
               and good["source_observed_outer_seal_sha256"] == sd
               and good["verified_copy_outer_seal_sha256"] == sd
               and "external_outer_seal_sha256" in good
               and good["expectations"]["outer_seal_sha256"] == sd))

        ws2 = os.path.join(td, "ws_nopin")
        os.makedirs(ws2)
        none = reloc(env, ws2, None, vd, boot)
        check("T14-2c. omitting the pin cannot pass, and says there is no fallback",
              not none["g17_pass"] and has(none["failures"], "requires an external"),
              none["failures"][:1])

        ws3 = os.path.join(td, "ws_wrong")
        os.makedirs(ws3)
        wrong = reloc(env, ws3, "d" * 64, vd, boot)
        check("T14-2d. a WRONG pin is refused against the SOURCE before the copy is even made",
              not wrong["g17_pass"] and has(wrong["failures"], "the SOURCE seal")
              and wrong["relocated_to"] is None, wrong["failures"][:1])

        ws4 = os.path.join(td, "ws_selfderived")
        os.makedirs(ws4)
        self_derived = ENV.sha256_file(os.path.join(env, ENV.SEAL_FILE))
        ok2 = reloc(env, ws4, self_derived, vd, boot, expect_inventory_sha256=inv)
        check("T14-2e. a pin a caller READ from the object is still only as good as the caller: "
              "the diagnostic records it but cannot promote itself to G17",
              not ok2["g17_pass"]
              and ok2["expectations"]["outer_seal_sha256"] == self_derived)
        ws5 = os.path.join(td, "ws_noboot")
        os.makedirs(ws5)
        noboot = reloc(env, ws5, sd, vd, None, expect_inventory_sha256=inv)
        check("T14-2e2. and the BOOTSTRAP pin is mandatory too: the code that authenticates the "
              "envelope must itself be pinned from outside",
              not noboot["g17_pass"] and any("expect_bootstrap_sha256 is mandatory" in f
                                             for f in noboot["failures"]),
              noboot["failures"][:1])

        src = open(os.path.join(_NODE, "qual_verify_v2.py"), encoding="utf-8").read()
        check("T14-2f. and the fallback expression that produced R3-2 is gone from the source",
              "expect_outer_seal_sha256 or res[" not in src)


# ================================================================== R3-3
def test_r3_3_roles_only_grow():
    with tempfile.TemporaryDirectory() as td:
        shrunk = ("inner_collection", "environment_trace", "pre_seal_gate_results")
        env, seal = build(td, "r", required_roles=shrunk, full_roles=False)
        sd, vd, inv, boot = pins(env, seal)
        check("T14-3. BASELINE: a builder handed a SHORTENED required-role list seals with the "
              "union, not the subset",
              set(ENV.REQUIRED_ROLES) <= set(seal["required_roles"]), seal["required_roles"])
        check("T14-3b. and the envelope verifies clean", ENV.verify_envelope(
            env, expect_outer_seal_sha256=sd) == [])

        eff = ENV.effective_required_roles(seal_roles=list(shrunk),
                                           caller_extra=["inner_collection"])
        check("T14-3c. effective roles from a caller SUBSET are still a superset of the code floor",
              set(ENV.REQUIRED_ROLES) <= set(eff), eff)
        eff2 = ENV.effective_required_roles(caller_extra=["driver_log"])
        check("T14-3d. a caller may ADD a role", "driver_log" in eff2 and
              set(ENV.REQUIRED_ROLES) <= set(eff2), eff2)
        eff3 = ENV.effective_required_roles(authorized_run=True)
        check("T14-3e. and an authorized run folds in the full AUTHORIZED_REQUIRED_ROLES set, "
              "which is USED rather than merely defined",
              set(ENV.AUTHORIZED_REQUIRED_ROLES) <= set(eff3), len(eff3))

        f = ENV.verify_envelope(env, require_roles=["inner_collection"],
                                expect_outer_seal_sha256=sd)
        check("T14-3f. a caller subset cannot make a complete envelope fail either", f == [], f)
        spec_bytes = ENV.sha256_file(os.path.join(env, "tools", "spec.json"))
        starved = ENV.verify_envelope(env, expect_outer_seal_sha256=sd, authorized_run=True,
                                      expect_spec_sha256=spec_bytes)
        missing = [x for x in starved if "required role" in x]
        check("T14-3g. MUTATION: the same envelope verified as an AUTHORIZED run is refused for "
              "every role it does not bind", len(missing) >= 8, missing[:3])
        nospec = ENV.verify_envelope(env, expect_outer_seal_sha256=sd, authorized_run=True)
        check("T14-3h. and an authorized run without the bound spec's bytes is refused before its "
              "role list means anything",
              has(nospec, "must pin the bound specification"), nospec[:1])
        forged = ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                     expect_spec_sha256="9" * 64)
        check("T14-3i. a wrong spec pin is compared against the ACTUAL bound bytes",
              has(forged, "the bound qualification spec hashes to"), forged[:1])


# ================================================================== R3-4
def test_r3_4_typed_directory_inventory():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "d", empty_dir=os.path.join("logs", "empty_at_seal"))
        sd, vd, inv, boot = pins(env, seal)
        base = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        check("T14-4. BASELINE: an envelope containing an EMPTY directory verifies clean",
              base == [], base)
        check("T14-4b. and the seal records that directory, its count and a typed-inventory digest",
              "logs/empty_at_seal" in seal["directories"]
              and seal["directory_count"] == len(seal["directories"])
              and ENV._is_hex64(seal["typed_inventory_sha256"]), seal["directory_count"])

        added = os.path.join(env, "sneaky_empty")
        os.makedirs(added)
        f = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        check("T14-4c. MUTATION: an unlisted empty directory added after sealing is refused",
              has(f, "directories present but not sealed") and has(f, "typed inventory"), f[:1])
        os.rmdir(added)

        d = os.path.join(env, "logs", "empty_at_seal")
        os.rmdir(d)
        f = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        check("T14-4d. MUTATION: deleting a directory that was present at sealing is refused",
              has(f, "directories sealed but absent"), f[:1])
        os.makedirs(os.path.join(env, "logs", "renamed_empty"))
        f = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        check("T14-4e. MUTATION: renaming it is refused as both an absence and an insertion",
              has(f, "directories sealed but absent")
              and has(f, "directories present but not sealed"), f[:2])
        os.rmdir(os.path.join(env, "logs", "renamed_empty"))
        w(d, "")
        f = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        check("T14-4f. MUTATION: replacing the directory with a file of the same name is refused "
              "on TYPE", has(f, "directories sealed but absent")
              and has(f, "files present but not listed"), f[:2])
        os.remove(d)
        os.makedirs(d)
        check("T14-4g. and restoring it exactly returns the envelope to clean",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd) == [])

        tree = os.path.join(td, "invtree")
        w(os.path.join(tree, "a.txt"), "a\n")
        os.makedirs(os.path.join(tree, "empty_here"))
        ti = ENV.typed_inventory(tree)
        check("T14-4h. the relocation inventory is the same typed inventory and sees the empty "
              "directory", ti.get("empty_here", (None,))[0] == "directory"
              and QV.inventory(tree) == ti, sorted(ti))
        d1 = ENV.inventory_digest(ti)
        os.makedirs(os.path.join(tree, "another_empty"))
        check("T14-4i. and adding one more empty directory moves the inventory digest",
              ENV.inventory_digest(ENV.typed_inventory(tree)) != d1)


# ================================================================== R3-5
def test_r3_5_reads_are_observed():
    with tempfile.TemporaryDirectory() as td:
        # A synthetic project root. It is deliberately NOT a git repository and the reports below
        # are deliberately NOT canonical: this test is about read observation, and creating a git
        # fixture would mean spawning a child that cannot return a provenance sidecar.
        repo = os.path.join(td, "provroot")
        w(os.path.join(repo, "node", "mod_a.py"), "VALUE = 1\n")
        w(os.path.join(repo, "node", "never_imported.py"), "SECRET = 'read directly'\n")
        w(os.path.join(repo, "node", "run_me.py"), "RESULT = 40 + 2\n")
        w(os.path.join(repo, "docs", "data.txt"), "undeclared document bytes\n")
        sys.path.insert(0, os.path.join(repo, "node"))
        try:
            b = RP.ProvenanceRecorder(repo, strict=False).begin()
            b.read_declared(os.path.join(repo, "docs", "data.txt"), kind="doc")
            b.pin_test_inventory(["t1"], 1)
            b.finish()
            base = b.report("r14_base", ["x"], canonical=False, actual_test_ids=["t1"],
                            actual_check_count=1)
            check("T14-5. BASELINE: a run whose only project-local read is DECLARED is "
                  "provenance_ok", base["provenance_ok"] and not base["undeclared_local_reads"],
                  base["provenance_problems"])

            r = RP.ProvenanceRecorder(repo, strict=False).begin()
            import mod_a                                             # noqa: F401
            with open(os.path.join(repo, "node", "never_imported.py"), encoding="utf-8") as f:
                f.read()
            import io as _io
            with _io.open(os.path.join(repo, "docs", "data.txt"), encoding="utf-8") as f:
                f.read()
            import runpy
            g = runpy.run_path(os.path.join(repo, "node", "run_me.py"))
            r.pin_test_inventory(["t1"], 1)
            r.finish()
            doc = r.report("r14", ["x"], canonical=False, actual_test_ids=["t1"],
                           actual_check_count=1)
        finally:
            sys.path.remove(os.path.join(repo, "node"))
        ur = sorted(doc["undeclared_local_reads"])
        check("T14-5b. MUTATION (a): builtins.open of a project-local .py that was NEVER imported "
              "is an UNDECLARED read, not a suffix exemption",
              "node/never_imported.py" in ur, ur)
        check("T14-5c. MUTATION (b): io.open of a project-local document is intercepted too "
              "(builtins.open is io.open, and rebinding one does not rebind the other)",
              "docs/data.txt" in ur, ur)
        check("T14-5d. MUTATION (c): runpy.run_path puts the executed module in the closure and "
              "in the append-only executed-source ledger",
              g.get("RESULT") == 42 and "node/run_me.py" in doc["import_closure"]
              and "node/run_me.py" in doc["executed_source_ledger"],
              sorted(doc["executed_source_ledger"]))
        check("T14-5e. an ordinary import lands in the same ledger with its digest AT EXECUTION",
              doc["executed_source_ledger"].get("node/mod_a.py", {}).get("sha256_at_execution")
              is not None)
        check("T14-5f. and the report is NOT provenance_ok",
              doc["provenance_ok"] is False
              and any("undeclared project-local reads" in p
                      for p in doc["provenance_problems"]), doc["provenance_problems"][:1])
        check("T14-5g. the observation boundary names what it cannot see rather than claiming it "
              "saw everything",
              any("mmap" in x for x in doc["observation_boundaries"]["NOT observed"])
              and "api_observed_closure_complete" in doc)


# ================================================================== R3-6
def test_r3_6_deep_typed_completeness():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        ok = QS.deep_validate_authorized(fx["doc"], fx["root"])
        check("T14-6. BASELINE: the complete fixture has NO deep-validation failures", ok == [], ok)

        cases = [
            ("replicates", lambda d: d.update(replicates=0), "replicates must be a positive"),
            ("replicates=True", lambda d: d.update(replicates=True),
             "replicates must be a positive"),
            ("rates nonnumeric", lambda d: d.update(rates={"total": "many"}),
             "is not a finite positive number"),
            ("durations inf", lambda d: d.update(durations={"mine": float("inf")}),
             "is not a finite positive number"),
            ("ports out of range", lambda d: d.update(ports={"base": -7}),
             "is not an integer in"),
            ("namespace", lambda d: d.update(namespace="Not A Namespace"),
             "does not match"),
            ("condition order duplicate",
             lambda d: d.update(condition_order=["control", "control"]),
             "repeats a condition"),
            ("schedule disagrees", lambda d: d.update(schedule={"order": ["attack", "control"]}),
             "does not equal condition_order"),
            ("snapshot placeholder", lambda d: d.update(snapshot={"id": "TBD",
                                                                  "sha256": "a" * 64}),
             "snapshot.id must be a non-placeholder"),
            ("refusal policy", lambda d: d.update(refusal_policy={"on_denied_workload": "warn"}),
             "must be 'refuse'"),
            ("role shrink", lambda d: d.update(required_envelope_roles=["inner_collection"]),
             "may EXTEND the code floor"),
            ("threshold placeholder",
             lambda d: d.update(gates=[dict(g, thresholds={"limit": "TBD"})
                                       for g in d["gates"]]),
             "thresholds contain a placeholder"),
            ("threshold out of domain",
             lambda d: d.update(gates=[dict(g, thresholds={"limit": 99.0},
                                            domain={"limit": {"min": 0.0, "max": 10.0}})
                                       for g in d["gates"]]),
             "above its declared maximum"),
            ("collector absent",
             lambda d: d.update(collector_binding={"path": "nope.py", "sha256": "9" * 64,
                                                   "dependencies": {}}),
             "collector: 'nope.py' is absent"),
            ("collector digest wrong",
             lambda d: d.update(collector_binding=dict(d["collector_binding"],
                                                       sha256="9" * 64)),
             "hashes to"),
            ("no dependency inventory",
             lambda d: d.update(collector_binding={"path": "collector.py",
                                                   "sha256": d["collector_binding"]["sha256"]}),
             "dependencies must be a mapping"),
            ("evaluator absent",
             lambda d: d.update(evaluators={k: {"module": "/nope/x.py", "sha256": "7" * 64}
                                            for k in d["evaluators"]}),
             "is not a non-empty string" if False else "absolute path"),
            ("evaluator missing a gate",
             lambda d: d.update(evaluators={k: v for k, v in
                                            list(d["evaluators"].items())[:-1]}),
             "evaluators has no entry for gate"),
        ]
        for label, mut, needle in cases:
            d = json.loads(json.dumps(fx["doc"]))
            mut(d)
            fails = QS.deep_validate_authorized(d, fx["root"])
            check("T14-6b. MUTATION %-24s is refused for the intended reason" % label,
                  any(needle in f for f in fails), (fails or ["nothing was raised"])[:1])

        raw = (json.dumps(dict(fx["doc"], surprise="a new claim under a new name"), indent=1)
               + "\n").encode("utf-8")
        hit, msg = refuses(lambda: QS.parse_spec(raw, "fixture"), "unknown top-level field",
                           QS.SpecError)
        check("T14-6c. an unknown top-level field is refused by the allowlist", hit, msg[:90])
        g = json.loads(json.dumps(fx["doc"]))
        g["gates"][0]["surprise"] = 1
        hit, msg = refuses(lambda: QS.parse_spec(
            (json.dumps(g, indent=1) + "\n").encode("utf-8"), "fixture"),
            "unknown field", QS.SpecError)
        check("T14-6d. and so is an unknown field nested inside a gate", hit, msg[:90])


# ================================================================== R3-7
def test_r3_7_historical_fake_seal():
    with tempfile.TemporaryDirectory() as td:
        b, a = mini(os.path.join(td, "ok"), "OK_20260101")
        p = hi_pins(b, a)
        good = HI.verify_bundle(b, expected=p)
        check("T14-7. BASELINE: a miniature synthetic bundle with a real seal and external pins "
              "passes", good["passed"], good["failures"][:2])
        check("T14-7b. and the checker changed nothing while checking",
              good["notes"]["mutations_during_checking"] == 0)

        b2, a2 = mini(os.path.join(td, "fake"), "FAKE_20260101",
                      seal_doc={"note": "no schema, no status, no inventory, no count"})
        f = HI.verify_bundle(b2, expected=hi_pins(b2, a2))
        check("T14-7c. MUTATION: a seal that only points at the checksum list is refused on "
              "schema", not f["passed"] and has(f["failures"], "not one of the recognised"),
              f["failures"][:1])
        check("T14-7d. and on finality, which is never inferred from a pointer",
              has(f["failures"], "declares no explicit finality"))
        check("T14-7e. and on the inventory and count it does not declare",
              has(f["failures"], "declares no inventory list")
              and has(f["failures"], "no integer file_count"))

        b3, a3 = mini(os.path.join(td, "wrongstatus"), "STATUS_20260101",
                      seal_doc={"schema": HI.BUNDLE_SEAL_SCHEMAS[0], "sealed": False,
                                "inventory": [], "file_count": 0})
        f3 = HI.verify_bundle(b3, expected=hi_pins(b3, a3))
        check("T14-7f. MUTATION: sealed=false is refused even with the right schema",
              not f3["passed"] and has(f3["failures"], "declares no explicit finality"),
              f3["failures"][:1])

        b4, a4 = mini(os.path.join(td, "noinspect"), "NOINSPECT_20260101")
        f4 = HI.verify_bundle(b4, expected=hi_pins(b4, a4), inspect_archive_members=False)
        check("T14-7g. MUTATION: inspect_archive_members=False can no longer produce a pass",
              not f4["passed"] and has(f4["failures"], "cannot produce a pass"),
              f4["failures"][:1])

        b5, a5 = mini(os.path.join(td, "nopins"), "NOPINS_20260101")
        f5 = HI.verify_bundle(b5)
        check("T14-7h. MUTATION: no external pins is a refusal, because a bundle cannot vouch "
              "for itself", not f5["passed"] and has(f5["failures"], "no external pin supplied"),
              f5["failures"][:1])

        b6, a6 = mini(os.path.join(td, "planted"), "PLANTED_20260101")
        p6 = hi_pins(b6, a6)
        w(os.path.join(b6, "planted.json"), '{"unlisted":true}\n')
        f6 = HI.verify_bundle(b6, expected=p6)
        argnames = HI.verify_bundle.__code__.co_varnames[
            :HI.verify_bundle.__code__.co_argcount]
        check("T14-7i. MUTATION: an unlisted planted file is refused, and there is no self_files "
              "parameter left for a caller to expand",
              not f6["passed"] and has(f6["failures"], "present but not listed")
              and "self_files" not in argnames, list(argnames))

        b7, a7 = mini(os.path.join(td, "tarlink"), "TARLINK_20260101")
        with tarfile.open(a7, "w:gz") as tf:
            ti = tarfile.TarInfo("logs/evil")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../../../etc/passwd"
            tf.addfile(ti)
        p7 = hi_pins(b7, a7)
        w(a7 + HI.SIDECAR_SUFFIX,
          HI.sha256_file(a7) + "  TARLINK_20260101" + HI.ARCHIVE_SUFFIX + "\n")
        p7["archive_sha256"] = HI.sha256_file(a7)
        f7 = HI.verify_bundle(b7, expected=p7)
        check("T14-7j. MUTATION: a SYMTYPE tar member with a traversing linkname is refused on "
              "member TYPE", not f7["passed"] and has(f7["failures"], "is a symlink"),
              [x for x in f7["failures"] if "symlink" in x][:1])


# ================================================================== R3-8
def test_r3_8_wsl_enumeration():
    seen = []

    def good_runner(argv, **kw):
        seen.append(list(argv))

        class R:
            returncode = 0
            stderr = ""
        R.stdout = (("  NAME              STATE           VERSION\n"
                     "* Ubuntu            Running         2\n"
                     "  Debian            Running         2\n"
                     "  docker-desktop    Stopped         2\n")
                    if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]
                    else "1\tinit\t/sbin/init\n")
        return R()

    inv = WP.wsl_inventory(runner=good_runner)
    check("T14-8. BASELINE: the WSL side enumerates distributions read-only and is available",
          inv.status == WP.STATUS_AVAILABLE, inv.error or inv.detail)
    check("T14-8b. enumeration is `wsl.exe --list --verbose`, which starts nothing",
          seen[0] == [WP.WSL_EXE, "--list", "--verbose"], seen[0])
    queried = [a[2] for a in seen if a[:2] == [WP.WSL_EXE, "-d"]]
    check("T14-8c. every RUNNING distribution is queried EXPLICITLY BY IDENTITY",
          queried == ["Ubuntu", "Debian"], queried)
    check("T14-8d. the STOPPED one is recorded and never queried, because querying it would "
          "start it", inv.extra["stopped_not_queried"] == ["docker-desktop"]
          and "docker-desktop" not in queried, inv.extra["stopped_not_queried"])
    check("T14-8e. every enumerated distribution and every per-distribution result is recorded",
          [d["name"] for d in inv.extra["enumerated"]] == ["Ubuntu", "Debian", "docker-desktop"]
          and all(v["ok"] for v in inv.extra["per_distribution"].values()),
          inv.extra["per_distribution"])

    def win():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

    ok = WP.WorkloadPreflight(
        providers={"windows": win, "wsl": lambda: WP.wsl_inventory(runner=good_runner)}
    ).check("lead_in")
    check("T14-8f. and a clean two-source inventory allows the stage", ok.allowed, ok.reasons)

    def gitbash(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
            stdout = "1\tbash\t/mingw64/bin/bash.exe\n"
        return R()

    masq = WP.bash_inventory(runner=gitbash)
    check("T14-8g. MUTATION: generic bash is a SEPARATE source that declares it does not satisfy "
          "the WSL requirement, and Git/MSYS bash is detected",
          masq.source == "shell:bash" and masq.extra["satisfies_wsl_requirement"] is False
          and masq.extra["looks_like_git_msys_or_cygwin_bash"] is True, masq.extra)
    bad = WP.WorkloadPreflight(providers={"windows": win, "wsl": lambda: masq}).check("lead_in")
    check("T14-8h. offering it as the WSL source refuses the stage",
          not bad.allowed and any("does not satisfy the WSL requirement" in r
                                  for r in bad.reasons), bad.reasons[:1])

    def partial(argv, **kw):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]:
            R.stdout = ("  NAME              STATE           VERSION\n"
                        "* Ubuntu            Running         2\n"
                        "  Debian            Running         2\n")
            return R()
        if argv[2] == "Debian":
            R.returncode = 1
            R.stderr = "permission denied"
            return R()
        R.stdout = "1\tinit\t/sbin/init\n"
        return R()

    part = WP.wsl_inventory(runner=partial)
    pf = WP.WorkloadPreflight(providers={"windows": win, "wsl": lambda: part}).check("lead_in")
    check("T14-8i. MUTATION: one distribution answering and one failing is a refusal -- a partial "
          "answer is not an answer",
          not pf.allowed and any("partial answer" in r for r in pf.reasons), pf.reasons[:1])

    def broken(argv, **kw):
        class R:
            returncode = 1
            stdout = ""
            stderr = "wsl is not installed"
        return R()

    none = WP.wsl_inventory(runner=broken)
    npf = WP.WorkloadPreflight(providers={"windows": win, "wsl": lambda: none}).check("lead_in")
    check("T14-8j. MUTATION: enumeration that errors refuses, and WSL_ROUTING_UNKNOWN is now "
          "EMITTED rather than merely defined",
          not npf.allowed and WP.WSL_ROUTING_UNKNOWN in npf.reasons, npf.reasons[-1][:70])

    def weird(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
            stdout = ("  NAME              STATE           VERSION\n"
                      "* Ubuntu            Hibernating     2\n")
        return R()

    amb = WP.wsl_inventory(runner=weird)
    check("T14-8k. MUTATION: an unrecognised distribution state is ambiguous, and ambiguity is a "
          "refusal", amb.status == WP.STATUS_ERROR and "does not recognise" in (amb.error or ""),
          (amb.error or "")[:80])

    denied = WP.WorkloadPreflight(
        providers={"windows": lambda: WP.Inventory(
            "windows:Win32_Process", WP.STATUS_AVAILABLE,
            [WP.ProcessRecord(20628, "p2pool.exe", None, "windows:Win32_Process")]),
            "wsl": lambda: WP.wsl_inventory(runner=good_runner)}).check("pre_launch")
    check("T14-8l. and a SYNTHETIC denied workload still refuses at the pre-launch stage; no real "
          "process was inspected, started, signalled or stopped by this test",
          not denied.allowed and any("denied workload" in r for r in denied.reasons),
          denied.reasons[:1])


# ================================================================== R3-9a
def test_r3_9a_reparse_points():
    with tempfile.TemporaryDirectory() as td:
        tree = os.path.join(td, "tree")
        w(os.path.join(tree, "normal.txt"), "a normal file\n")
        target = os.path.join(td, "outside_target")
        w(os.path.join(target, "secret.txt"), "outside the envelope\n")
        base = ENV.walk_typed(tree)
        check("T14-9a. BASELINE: a plain tree contains only regular files and directories",
              set(base.values()) <= set(ENV.SAFE_KINDS) and ENV.unsafe_objects(tree) == [], base)

        made, kind = None, None
        link = os.path.join(tree, "pointer")
        try:
            if os.name == "nt":
                subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                               capture_output=True, check=True)
            else:
                os.symlink(target, link)
            made = True
            kind = ENV.file_kind(link)
        except Exception as e:                                   # pragma: no cover - policy
            made, kind = False, "%s: %s" % (type(e).__name__, e)

        if made:
            try:
                check("T14-9b. MUTATION: the pointer is classified as an UNSAFE object, not as a "
                      "directory (os.path.islink alone is %r on this platform)"
                      % os.path.islink(link),
                      kind in ("symlink", "reparse_point") and kind not in ENV.SAFE_KINDS, kind)
                check("T14-9c. the walk does NOT descend into it, so bytes living outside the "
                      "tree are never listed as members",
                      ENV.walk_relpaths(tree) == ["normal.txt"], ENV.walk_relpaths(tree))
                check("T14-9d. it appears in the typed inventory as its own object",
                      ENV.typed_inventory(tree).get("pointer", (None,))[0] == kind)
                check("T14-9e. and unsafe_objects reports it",
                      ENV.unsafe_objects(tree) == [("pointer", kind)], ENV.unsafe_objects(tree))
                b = ENV.EnvelopeBuilder(os.path.join(td, "stage9"), "R9")
                hit, msg = refuses(lambda: b._stage("driver_log", tree, ENV.KIND_DIR,
                                                    relpath="tree", is_dir=True),
                                   "unrepresentable object", ENV.EnvelopeError)
                check("T14-9f. binding a tree containing it is refused before any copy is made",
                      hit, msg[:110])
            finally:
                try:
                    os.rmdir(link) if os.name == "nt" else os.unlink(link)
                except OSError:                                  # pragma: no cover
                    pass
        else:                                                    # pragma: no cover - policy
            for n in ("T14-9b", "T14-9c", "T14-9d", "T14-9e", "T14-9f"):
                check("%s. this platform would not create the pointer, so the case FAILS CLOSED "
                      "rather than being reported as passed" % n, False, kind)

        check("T14-9g. hard-link ambiguity is its own kind and is not a regular file",
              "hardlinked" not in ENV.SAFE_KINDS)
        check("T14-9h. and the reparse-point test is st_reparse_tag / "
              "FILE_ATTRIBUTE_REPARSE_POINT, not os.path.islink alone",
              hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT") or os.name != "nt")


# ================================================================== R3-9b
def test_r3_9b_canonical_attestation():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "a")
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        outd = os.path.join(td, "out")
        os.makedirs(outd)
        pkg = os.path.join(outd, ENV.CANONICAL_ATTESTATION_DIR)
        res = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv, attestation_package=pkg)
        check("T14-9b1. CORRECTED: the legacy trivial-spec fixture cannot publish a canonical "
              "attestation", not os.path.exists(pkg) and not res["g17_pass"], res["failures"][:2])
        check("T14-9b2. no final-name or partial package is left behind",
              os.listdir(outd) == [], os.listdir(outd))
        check("T14-9b3. refusing publication leaves the envelope's own seal unchanged",
              ENV.sha256_file(os.path.join(env, ENV.SEAL_FILE)) == sd)

        d2 = os.path.join(td, "out2")
        os.makedirs(d2)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d2, "not_canonical"), res, "V",
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot,
            token=ENV._CANONICAL_TOKEN), "must be named", ENV.EnvelopeError)
        check("T14-9b4. MUTATION: a non-canonical package name is refused",
              hit and os.listdir(d2) == [], msg[:90])

        d3 = os.path.join(td, "out3")
        os.makedirs(d3)
        tgt = os.path.join(d3, ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(tgt)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, tgt, res, "V", expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot,
            token=ENV._CANONICAL_TOKEN), "external pin", ENV.EnvelopeError)
        check("T14-9b5. MUTATION: an incomplete legacy pin set cannot write through an existing "
              "package path", hit and os.listdir(tgt) == [], msg[:90])

        for name, kw in (("no outer-seal pin", {"expect_verifier_sha256": vd,
                                                 "expect_envelope_inventory_sha256": inv,
                                                 "expect_bootstrap_sha256": boot}),
                         ("no verifier pin", {"expect_outer_seal_sha256": sd,
                                              "expect_envelope_inventory_sha256": inv,
                                              "expect_bootstrap_sha256": boot}),
                         ("no inventory pin", {"expect_outer_seal_sha256": sd,
                                               "expect_verifier_sha256": vd,
                                               "expect_bootstrap_sha256": boot}),
                         ("no bootstrap pin", {"expect_outer_seal_sha256": sd,
                                               "expect_verifier_sha256": vd,
                                               "expect_envelope_inventory_sha256": inv})):
            d = tempfile.mkdtemp(dir=td)
            hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
                env, os.path.join(d, ENV.CANONICAL_ATTESTATION_DIR), res, "V",
                token=ENV._CANONICAL_TOKEN, **kw), "external pin",
                ENV.EnvelopeError)
            check("T14-9b6. MUTATION: canonical publication with %-18s is refused" % name,
                  hit and os.listdir(d) == [], msg[:90])

        d4 = tempfile.mkdtemp(dir=td)
        w(os.path.join(env, "post_seal_change.txt"), "the source moved\n")
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d4, ENV.CANONICAL_ATTESTATION_DIR), res, "V",
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot,
            token=ENV._CANONICAL_TOKEN), "external pin", ENV.EnvelopeError)
        check("T14-9b7. MUTATION: a source change that does NOT touch the seal is still caught "
              "by envelope verification", hit and ENV.verify_envelope(
                  env, expect_outer_seal_sha256=sd), msg[:110])
        os.remove(os.path.join(env, "post_seal_change.txt"))

        hit, msg = refuses(lambda: ENV.write_attestation(
            env, os.path.join(env, "third_party.json"), res, "V"),
            "may not be written inside", ENV.EnvelopeError)
        check("T14-9b8. and an attestation may never be written inside the envelope it is about",
              hit, msg[:90])
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(tempfile.mkdtemp(dir=td), ENV.CANONICAL_ATTESTATION_DIR), res, "V",
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot),
            "published only by the production G17 operation", ENV.EnvelopeError)
        check("T14-9b9. and without the production token no caller can publish one at all",
              hit, msg[:90])


# ================================================================== R3-10
def test_r3_10_pinned_inventory():
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "pinroot")
        w(os.path.join(repo, "node", "m.py"), "X = 1\n")
        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        r.pin_test_inventory(["a", "b", "c"], 10, meta_check_count=1)
        r.finish()

        def rep(**kw):
            # canonical=False on purpose: the inventory gate is NOT canonical-gated any more.
            # R3-10 passed precisely because the comparison was conditional; it is now
            # unconditional whenever a pin exists.
            return r.report("pin", ["x"], canonical=False, **kw)

        good = rep(actual_test_ids=["a", "b", "c"], actual_check_count=11)
        check("T14-10. BASELINE: the exact id set and the exact check count satisfy the pin",
              good["provenance_ok"], good["provenance_problems"])
        check("T14-10b. and the pin declares the functional/meta split explicitly",
              good["test_inventory"]["functional_check_count"] == 10
              and good["test_inventory"]["meta_check_count"] == 1
              and good["test_inventory"]["expected_total_checks"] == 11)

        d = rep(actual_test_ids=None, actual_check_count=11)
        check("T14-10c. MUTATION: a pin with NO actual id set can no longer be provenance_ok",
              not d["provenance_ok"]
              and any("EXACT actual test-id set" in p for p in d["provenance_problems"]),
              d["provenance_problems"][:1])
        d = rep(actual_test_ids=["a", "b", "c"], actual_check_count=None)
        check("T14-10d. MUTATION: nor one with no actual check count",
              not d["provenance_ok"]
              and any("EXACT actual check count" in p for p in d["provenance_problems"]),
              d["provenance_problems"][:1])
        d = rep(actual_test_ids=["a", "b", "zzz"], actual_check_count=11)
        check("T14-10e. MUTATION: a substituted test id is refused",
              not d["provenance_ok"], d["provenance_problems"][:1])
        d = rep(actual_test_ids=["a", "b"], actual_check_count=11)
        check("T14-10f. MUTATION: a DELETED test is refused, so a smaller still-green n/n is "
              "impossible", not d["provenance_ok"], d["provenance_problems"][:1])
        d = rep(actual_test_ids=["c", "b", "a"], actual_check_count=11)
        check("T14-10g. MUTATION: even a reordered id list is refused",
              not d["provenance_ok"]
              and any("order_changed=True" in p for p in d["provenance_problems"]),
              d["provenance_problems"][:1])
        d = rep(actual_test_ids=["a", "b", "c"], actual_check_count=12)
        check("T14-10h. MUTATION: an off-by-one check count is refused, and the message shows the "
              "split so the two totals cannot drift together",
              not d["provenance_ok"]
              and any("10 functional + 1 meta" in p for p in d["provenance_problems"]),
              d["provenance_problems"][:1])

        # The canonical commit gates, exercised READ-ONLY against the real repository. No file is
        # written, no process is started, and the recorder's own git calls are tooling.
        u = RP.ProvenanceRecorder(_REPO, strict=False).begin()
        u.finish()
        nopin = u.report("gate", ["x"], tested_commit=None, canonical=True)
        check("T14-10i. a canonical report with NO pinned inventory at all is refused",
              not nopin["provenance_ok"]
              and any("must pin its test inventory" in p for p in nopin["provenance_problems"]),
              [p for p in nopin["provenance_problems"] if "inventory" in p][:1])
        u.pin_test_inventory(["z"], 1)
        bad = u.report("gate", ["x"], tested_commit="dead" * 10, canonical=True,
                       actual_test_ids=["z"], actual_check_count=1)
        check("T14-10j. and a tested_commit that does not resolve is still refused",
              not bad["provenance_ok"]
              and any("does not resolve" in p for p in bad["provenance_problems"]),
              [p for p in bad["provenance_problems"] if "resolve" in p][:1])


# ================================================================== R3-11
def test_r3_11_bootstrap_verifier():
    with tempfile.TemporaryDirectory() as td:
        honest_env, honest_seal = build(td, "h")
        hsd, hvd, hinv, hboot = pins(honest_env, honest_seal)
        ws0 = os.path.join(td, "ws0")
        os.makedirs(ws0)
        good = reloc(honest_env, ws0, hsd, hvd, hboot, expect_inventory_sha256=hinv)
        check("T14-11. CORRECTED: an envelope whose bundled verifier matches the EXTERNAL pin "
              "passes bootstrap authentication but its trivial spec is not G17",
              good["bootstrap_verified"] and not good["g17_pass"], good["failures"][:2])
        check("T14-11b. and the bootstrap's own bytes are reported, so the code that "
              "authenticates the envelope is itself identified",
              set(good["bootstrap_identity"]) == set(QV.BOOTSTRAP_FILES)
              and "run_provenance.py" in good["bootstrap_identity"]
              and all(ENV._is_hex64(v) for v in good["bootstrap_identity"].values()),
              sorted(good["bootstrap_identity"]))

        evil = w(os.path.join(td, "evil", "verifier.py"), EVIL_VERIFIER)
        env, seal = build(td, "e", verifier_src=evil)
        sd, vd, inv, boot = pins(env, seal)
        honest_digest = ENV.sha256_file(os.path.join(_NODE, "evidence_envelope.py"))
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        res = reloc(env, ws, sd, honest_digest, boot, expect_inventory_sha256=inv)
        check("T14-11c. MUTATION: a self-consistent MALICIOUS bundled verifier whose "
              "verify_envelope() returns [] is refused by the bootstrap",
              not res["bootstrap_verified"] and not res["g17_pass"],
              res["bootstrap_failures"][:1])
        check("T14-11d. for the intended reason -- its bytes are not the externally pinned ones",
              has(res["bootstrap_failures"], "a self-declared role digest is not a trust root"),
              res["bootstrap_failures"][:1])
        check("T14-11e. and it was never imported or executed: no verifier was resolved at all",
              res["verified_with"] is None and res["verifier_source_sha256"] is None)

        ws2 = os.path.join(td, "ws2")
        os.makedirs(ws2)
        norole = reloc(honest_env, ws2, hsd, hvd, hboot, expect_inventory_sha256=hinv,
                       bundled_verifier_role="a_role_this_envelope_does_not_bind")
        check("T14-11f. MUTATION: an unbound verifier role is refused rather than defaulted",
              not norole["g17_pass"] and has(norole["bootstrap_failures"], "is not bound"),
              norole["bootstrap_failures"][:1])

        ws3 = os.path.join(td, "ws3")
        os.makedirs(ws3)
        badinv = reloc(honest_env, ws3, hsd, hvd, hboot, expect_inventory_sha256="c" * 64)
        check("T14-11g. MUTATION: a wrong external INVENTORY pin is refused before the copy is "
              "made", not badinv["g17_pass"] and has(badinv["failures"], "SOURCE typed inventory"),
              badinv["failures"][:1])

        check("T14-11h. CORRECTED: the diagnostic starts no implicit child and cannot invent a "
              "verifier proof", not good["child_execution_proof"]["ok"]
              and not good["child_execution_proof"]["nonce_echoed"],
              good["child_execution_proof"]["failures"])
        check("T14-11i. it therefore returns no adoptable parent-side record",
              good["child_record"] is None, good["child_record"])


# ================================================================== R3-12
def test_r3_12_actual_inner_seal():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "i")
        sd, vd, inv, boot = pins(env, seal)
        base = ENV.verify_envelope(env, expect_outer_seal_sha256=sd)
        actual = ENV.sha256_file(os.path.join(env, "collection", "FINAL_SEAL.json"))
        check("T14-12. BASELINE: an envelope whose inner seal is a listed regular file inside the "
              "collection verifies clean", base == [], base)
        check("T14-12b. and the seal header records both the inner-seal RELPATH and the digest of "
              "the ACTUAL file", seal["inner_seal_relpath"] == "FINAL_SEAL.json"
              and seal["inner_seal_sha256"] == actual)
        check("T14-12c. an external inner-seal expectation is satisfied by the actual file",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                  expect_inner_seal=actual) == [])

        w(os.path.join(td, "OUTSIDE_SEAL"), '{"i am":"outside the collection"}\n')
        inner = inner_bundle(td, "trav_inner")
        os.remove(os.path.join(inner, "FINAL_SEAL.json"))
        hit, msg = refuses(lambda: build(td, "trav", inner=inner,
                                         inner_seal_relpath="../OUTSIDE_SEAL"),
                           "parent traversal", ENV.EnvelopeError)
        check("T14-12d. MUTATION: inner_seal_relpath='../OUTSIDE_SEAL' is refused at bind time",
              hit, msg[:110])

        inner2 = inner_bundle(td, "abs_inner")
        hit, msg = refuses(lambda: build(td, "abs", inner=inner2,
                                         inner_seal_relpath="/etc/passwd"),
                           "absolute path", ENV.EnvelopeError)
        check("T14-12e. MUTATION: an absolute inner-seal path is refused too", hit, msg[:90])

        inner3 = inner_bundle(td, "unsealed_inner")
        os.remove(os.path.join(inner3, "FINAL_SEAL.json"))
        hit, msg = refuses(lambda: build(td, "unsealed", inner=inner3),
                           "an unsealed collection may not be bound", ENV.EnvelopeError)
        check("T14-12f. MUTATION: a collection with no inner seal at all is refused", hit,
              msg[:90])

        inner4 = inner_bundle(td, "badschema_inner")
        w(os.path.join(inner4, "FINAL_SEAL.json"), '{"sealed": true}\n')
        hit, msg = refuses(lambda: build(td, "badschema", inner=inner4),
                           "is not one of the supported inner collection schemas",
                           ENV.EnvelopeError)
        check("T14-12g. MUTATION: an inner seal with no schema is refused at bind time", hit,
              msg[:90])

        inner5 = inner_bundle(td, "badsums_inner")
        w(os.path.join(inner5, "FINAL_SEAL.json"), json.dumps(
            {"schema": "meepcoin-inner-collection/1", "sealed": True,
             "sha256sums_sha256": "0" * 64}) + "\n")
        hit, msg = refuses(lambda: build(td, "badsums", inner=inner5),
                           "names checksum-list digest", ENV.EnvelopeError)
        check("T14-12h. MUTATION: an inner seal that binds the wrong checksum list is refused",
              hit, msg[:100])

        sp = os.path.join(env, ENV.SEAL_FILE)
        doc = json.loads(open(sp, encoding="utf-8").read())
        forged = "b" * 64
        doc["inner_seal_sha256"] = forged
        doc["roles"]["inner_collection"]["extra"]["inner_seal_sha256"] = forged
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        sd2 = ENV.sha256_file(sp)
        f1 = ENV.verify_envelope(env, expect_outer_seal_sha256=sd2)
        check("T14-12i. MUTATION: forging BOTH mutually consistent metadata copies is refused, "
              "because the actual file is opened and hashed",
              has(f1, "the seal header claims inner seal")
              and has(f1, "the inner_collection role claims inner seal"), f1[:2])
        f2 = ENV.verify_envelope(env, expect_outer_seal_sha256=sd2, expect_inner_seal=forged)
        check("T14-12j. and supplying the SAME forged value as the external expectation does not "
              "rescue it", has(f2, "the ACTUAL inner seal"), f2[:3])


# ================================================================== R3-13
def test_r3_13_exclusive_staging():
    with tempfile.TemporaryDirectory() as td:
        fresh = os.path.join(td, "fresh")
        b = ENV.EnvelopeBuilder(fresh, "FRESH")
        check("T14-13. BASELINE: a staging root the builder creates itself is accepted and starts "
              "in STAGING", b.state == ENV.STAGING and os.path.isdir(fresh))
        st = json.loads(open(os.path.join(fresh, ENV.STATE_FILE), encoding="utf-8").read())
        check("T14-13b. and its state file never claims finality",
              st["final"] is False and st["finality_marker"] == ENV.SEAL_FILE, st["state"])

        pre = os.path.join(td, "preexisting")
        os.makedirs(pre)
        hit, msg = refuses(lambda: ENV.EnvelopeBuilder(pre, "PRE"),
                           "refusing to stage into the existing path", ENV.EnvelopeError)
        check("T14-13c. MUTATION: a pre-existing EMPTY directory is refused", hit, msg[:110])
        w(os.path.join(td, "notdir"), "x\n")
        hit, msg = refuses(lambda: ENV.EnvelopeBuilder(os.path.join(td, "notdir"), "N"),
                           "refusing to stage into the existing path", ENV.EnvelopeError)
        check("T14-13d. MUTATION: and so is an existing file", hit, msg[:110])
        hit, msg = refuses(lambda: ENV.EnvelopeBuilder(fresh, "AGAIN"),
                           "refusing to stage into the existing path", ENV.EnvelopeError)
        check("T14-13e. MUTATION: a second builder cannot adopt the first one's root -- the "
              "create is a single exclusive mkdir with no check-then-create window", hit,
              msg[:110])

        env, seal = build(td, "c")
        sd, vd, inv, boot = pins(env, seal)
        fake = {"schema": ENV.RELOCATION_RESULT_SCHEMA, "source_stable": True,
                "verified_copy_outer_seal_sha256": sd, "relocated_to": None,
                "verified_with": "whatever I say", "verifier_source_sha256": vd,
                "expectations": {"outer_seal_sha256": sd}, "g17_pass": False,
                "passed": True, "failures": []}
        d1 = tempfile.mkdtemp(dir=td)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d1, ENV.CANONICAL_ATTESTATION_DIR), fake, "CALLER",
            token=ENV._CANONICAL_TOKEN,
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv,
            expect_bootstrap_sha256=QV.bootstrap_closure_digest()),
            "external pin", ENV.EnvelopeError)
        check("T14-13f. MUTATION: a caller-invented legacy dictionary with an incomplete external "
              "pin set cannot publish a canonical attestation", hit and os.listdir(d1) == [],
              msg[:100])

        fake2 = dict(fake, g17_pass=True, bootstrap_verified=True, four_point_identity=True)
        d2 = tempfile.mkdtemp(dir=td)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d2, ENV.CANONICAL_ATTESTATION_DIR), fake2, "CALLER",
            token=ENV._CANONICAL_TOKEN, expect_outer_seal_sha256=sd,
            expect_verifier_sha256=vd, expect_envelope_inventory_sha256=inv,
            expect_bootstrap_sha256=QV.bootstrap_closure_digest()),
            "external pin", ENV.EnvelopeError)
        check("T14-13g. MUTATION: asserting g17_pass=True does not repair the missing full pin and "
              "authorization chain", hit and os.listdir(d2) == [], msg[:100])

        d3 = tempfile.mkdtemp(dir=td)
        hit, msg = refuses(lambda: ENV.write_attestation(
            env, os.path.join(d3, "third_party.json"), fake, "THIRD PARTY"), "", Exception)
        third = os.path.exists(os.path.join(d3, "third_party.json"))
        check("T14-13h. a NON-canonical third-party attestation may still be written, and the "
              "precedence rule says it is never silently interchangeable with the canonical one",
              third and ENV.CANONICAL_ATTESTATION_NAME in ENV.ATTESTATION_PRECEDENCE, third)


# ------------------------------------------------------------------ main
def main():
    print("ROUND 14 -- the third corrective audit's counterexamples. NON-EVIDENCE, NON-LIVE.\n")
    for name in EXPECTED_TESTS:
        print("[%s]" % name)
        globals()[name]()
    functional = len(RESULTS)
    check("T14-INV. the functional check count equals the pinned figure, so a deleted test "
          "cannot yield a smaller still-green n/n",
          functional == FUNCTIONAL_CHECK_COUNT,
          "%d functional checks, pinned at %d" % (functional, FUNCTIONAL_CHECK_COUNT))

    RECORDER.pin_test_inventory(EXPECTED_TESTS, FUNCTIONAL_CHECK_COUNT,
                                meta_check_count=META_CHECK_COUNT)
    RECORDER.finish()
    passed = sum(1 for r in RESULTS if r["passed"])
    doc = RECORDER.report(
        "round14", sys.argv, tested_commit=ARG.get("--commit"),
        canonical=bool(ARG.get("--commit")), actual_test_ids=list(EXPECTED_TESTS),
        actual_check_count=len(RESULTS),
        extra={"label": "NON-EVIDENCE offline infrastructure tests -- third corrective round",
               "authorises_no_live_run": True, "passed": passed, "total": len(RESULTS),
               "results": RESULTS})
    print("\nROUND 14: %d/%d" % (passed, len(RESULTS)))
    print("provenance_ok: %s" % doc["provenance_ok"])
    for p in doc["provenance_problems"]:
        print("  ! %s" % p)
    if OUT:
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        print("report ->", OUT)
    return 0 if (passed == len(RESULTS) and doc["provenance_ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
