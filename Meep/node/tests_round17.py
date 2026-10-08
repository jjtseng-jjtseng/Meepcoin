#!/usr/bin/env python3
"""Round-17: behavioural closures for the SIXTH corrective audit.

NON-EVIDENCE, ENTIRELY NON-LIVE.  Nothing in this suite starts a MeepCoin daemon, miner,
driver, collector, topology, network listener, environment trace or scientific measurement.
The only processes used by the ordinary suite are short, harmless Python children whose exact
PID, return code, raw output and cooperative provenance sidecar are observed by
``run_provenance.run_observed``.  Every specification, authorization record, envelope, seal and
attestation is a miniature synthetic fixture in a disposable directory.

The real concurrent-input-drift, deliberately unadopted-child, post-Popen-exception, and
untrusted-runner-output negative
controls are intentionally separated from the canonical suite.  Run ``--diagnostic=drift``,
``--diagnostic=unadopted``, ``--diagnostic=aborted``, or ``--diagnostic=runner`` to execute one.
Each mode produces a
strict, explicitly noncanonical report and succeeds only when the report truthfully says
``api_observed_closure_complete=false`` and ``provenance_ok=false``.  Hiding either child merely
to obtain a green canonical report would repeat the defect this round repairs.

The supported project APIs are the boundary under test.  This remains cooperative Python API
instrumentation, not an operating-system tracer, signature scheme, TPM measurement or defence
against hostile code already executing inside the parent interpreter.

Usage:
  python3 node/tests_round17.py [--out=<path>] [--commit=<sha>]
  python3 node/tests_round17.py [--out=<path>] [--commit=<sha>] --diagnostic=drift
  python3 node/tests_round17.py [--out=<path>] [--commit=<sha>] --diagnostic=unadopted
  python3 node/tests_round17.py [--out=<path>] [--commit=<sha>] --diagnostic=aborted
  python3 node/tests_round17.py [--out=<path>] [--commit=<sha>] --diagnostic=runner
"""
import contextlib
import copy
import hashlib
import inspect
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_provenance as RP

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NODE = os.path.join(_REPO, "node")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1]
       for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "")
DIAGNOSTIC_MODE = ARG.get("--diagnostic", "")

# Begin before any production module under test is imported.
RECORDER = RP.ProvenanceRecorder(_REPO, strict=bool(DIAGNOSTIC_MODE)).begin()

import evidence_envelope as ENV                                      # noqa: E402
import qual_runner_v2 as RUN                                         # noqa: E402
import qual_spec as QS                                               # noqa: E402
import qual_verify_v2 as QV                                          # noqa: E402
import workload_preflight as WP                                      # noqa: E402
from tests_round2 import check, RESULTS                              # noqa: E402

SPEC_PATH = os.path.join(_REPO, "docs", "round2",
                         "qualification_spec_v2_DRAFT_NO_LAUNCH.json")

# These files are opened and hashed deliberately while constructing synthetic fixtures and the
# bootstrap identity.  Declare those reads rather than making the observer infer our intent.
RECORDER.register_read(SPEC_PATH, kind="qualification_spec_fixture_source")
for _name in sorted(set(getattr(QV, "BOOTSTRAP_FILES", ())) |
                    {"evidence_envelope.py", "qual_spec.py", "qual_verify_v2.py",
                     "run_provenance.py"}):
    _path = os.path.join(_NODE, _name)
    if os.path.isfile(_path):
        RECORDER.register_read(_path, kind="bootstrap_or_fixture_source")

with open(SPEC_PATH, "rb") as _f:
    _DRAFT_BYTES = _f.read()
_DRAFT = json.loads(_DRAFT_BYTES.decode("utf-8"))


ORDINARY_TESTS = (
    "test_r6_0_public_contracts_and_bootstrap",
    "test_r6_1_real_process_ownership",
    "test_r6_1_recorder_lifecycle_boundaries",
    "test_r6_1_prelaunch_refusals",
    "test_r6_1_runner_source_deleted_at_prelaunch",
    "test_r6_2_diagnostics_never_complete_closure",
    "test_r6_3_real_authorization_positive",
    "test_r6_3_authorization_refusal_matrix",
    "test_r6_3_malformed_nested_authority_inputs",
    "test_r6_3_missing_unreadable_authority_inputs",
    "test_r6_3_malformed_bootstrap_and_numeric_inputs",
    "test_r6_4_cli_parser_and_refusal",
    "test_r6_5_complete_attestation_pins",
    "test_r6_6_strict_sidecar_schema",
    "test_r6_6_parent_rederivation_and_limits",
)
DIAGNOSTIC_TESTS = {
    "aborted": ("test_r6_diagnostic_post_popen_exception",),
    "drift": ("test_r6_diagnostic_actual_concurrent_input_drift",),
    "runner": ("test_r6_diagnostic_runner_untrusted_output",),
    "unadopted": ("test_r6_diagnostic_unadopted_real_child",),
}

# Filled with the observed number after this file's inventory is stable.  It is deliberately a
# literal, not len(RESULTS), so deleting a check cannot yield a smaller still-green n/n.
ORDINARY_FUNCTIONAL_CHECK_COUNT = 168
DIAGNOSTIC_FUNCTIONAL_CHECK_COUNTS = {
    "aborted": 3, "drift": 3, "runner": 3, "unadopted": 3}
META_CHECK_COUNT = 1


COLLECTOR = RP.CHILD_SHIM_SOURCE + '''import json, sys
a = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in sys.argv[1:] if "=" in x}
print(json.dumps({"raw_records": 6, "branch_observations": 25,
                  "telemetry_retained": True, "collection_seconds": 0.02,
                  "staging_dir": a.get("--staging", ""),
                  "note": "synthetic Round-17 collector; starts no daemon or network"}))
'''
EVALUATOR = '"""Synthetic Round-17 evaluator; evaluates no real record."""\nGATE = %r\n'


def w(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def wb(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def jwrite(path, doc):
    return w(path, json.dumps(doc, indent=1, ensure_ascii=False) + "\n")


def digest(path):
    return ENV.sha256_file(path)


def has(items, needle):
    return any(needle.lower() in str(x).lower() for x in (items or []))


def refusal(fn, needle, cls=Exception):
    try:
        fn()
        return False, "nothing was raised"
    except cls as e:
        msg = "%s: %s" % (type(e).__name__, e)
        return needle.lower() in msg.lower(), msg


def result_record(result):
    if isinstance(result, dict):
        return result.get("child_record")
    return getattr(result, "record", None)


def adopt(result):
    record = result_record(result)
    if not isinstance(record, dict):
        raise AssertionError("the operation returned no child record")
    return RECORDER.adopt_child_record(record)


def sidecar_doc(result):
    doc = getattr(result, "sidecar_document", None)
    if isinstance(doc, dict):
        return copy.deepcopy(doc)
    record = result_record(result) or {}
    with open(record["sidecar_path"], encoding="utf-8") as f:
        return json.load(f)


def sidecar_probe(record, doc, tag="mutation"):
    """Drive the same strict validator without launching a deliberately invalid child."""
    path = os.path.join(os.path.dirname(record["sidecar_path"]), "%s.json" % tag)
    return RP.sidecar_failures(record, doc, path,
                               expected_inputs=record.get("declared_inputs") or {})


def harmless_observed_child(root, tag="A", stdout_bytes=b"round17-bytes\x00\xff"):
    """Run one real, harmless child and return its production observation.

    The child reads one bound file, fetches one disposable local source with ``open_code``,
    classifies one external read, inventories one bound directory, writes a marker, emits an
    exact raw byte sequence and exits.  It opens no socket and imports no MeepCoin code.
    """
    root = os.path.abspath(root)
    os.makedirs(root, exist_ok=True)
    input_path = wb(os.path.join(root, "input_%s.bin" % tag), b"bound input " + tag.encode())
    meta_dir = os.path.join(root, "meta_%s" % tag)
    os.makedirs(meta_dir, exist_ok=True)
    w(os.path.join(meta_dir, "entry.txt"), "entry\n")
    code_path = w(os.path.join(root, "helper_%s.py" % tag),
                  "ROUND17_HELPER_VALUE = 17\n")
    marker = os.path.join(root, "marker_%s.txt" % tag)
    sidecar = os.path.join(root, "child_%s.provenance.json" % tag)
    executable = os.path.realpath(sys.executable)
    program = RP.CHILD_SHIM_SOURCE + (
        "_cf = _ioc.open_code(%r); _cb = _cf.read(); _cf.close(); "
        "exec(compile(_cb, %r, 'exec'), {})\n"
        "_ef = _ioc.open_code(%r); _ef.read(1); _ef.close()\n"
        "f = open(%r, 'rb'); f.read(); f.close()\n"
        "_os.listdir(%r)\n"
        "f = open(%r, 'w', encoding='utf-8'); f.write('ran'); f.close()\n"
        "_sy.stdout.buffer.write(%r); _sy.stdout.buffer.flush()\n"
        % (code_path, code_path, executable, input_path, meta_dir, marker, stdout_bytes))
    argv = [executable, "-I", "-B", "-c", program]
    expected_inputs = {os.path.realpath(input_path): digest(input_path)}
    observed = RP.run_observed(
        argv, executable=executable, expect_executable_sha256=digest(executable),
        cwd=root, root=root, expected_inputs=expected_inputs, sidecar_path=sidecar,
        env=dict(os.environ), timeout=30,
        declared_outputs=(marker,))
    return {"result": observed, "record": result_record(observed),
            "doc": sidecar_doc(observed), "input": input_path, "code": code_path,
            "meta": meta_dir,
            "marker": marker, "sidecar": sidecar, "stdout": stdout_bytes,
            "argv": argv}


def synthetic_preflight(cls=None, **kwargs):
    """A complete clean inventory fixture; it observes no real host process."""
    def clean(source):
        return lambda: WP.Inventory(
            source, WP.STATUS_AVAILABLE,
            [WP.ProcessRecord(4, "System", "/synthetic/System", source)])

    return (cls or WP.WorkloadPreflight)(
        providers={"windows": clean("windows:synthetic"), "wsl": clean("wsl:synthetic")},
        **kwargs)


def _inner_bundle(root, name="inner"):
    bundle = os.path.join(root, name)
    w(os.path.join(bundle, "raw", "rec_1.json"),
      '{"condition":"control","replicate":1}\n')
    w(os.path.join(bundle, "manifest.json"), '{"status":"COMPLETED"}\n')
    rows = []
    for rel in ENV.walk_relpaths(bundle):
        if rel not in ("SHA256SUMS", "FINAL_SEAL.json"):
            rows.append("%s  output  %s\n" %
                        (digest(os.path.join(bundle, rel.replace("/", os.sep))), rel))
    w(os.path.join(bundle, "SHA256SUMS"), "".join(rows))
    jwrite(os.path.join(bundle, "FINAL_SEAL.json"), ENV.inner_seal_document(bundle))
    return bundle


def authorized_fixture(root, spec_id="R17_SYNTHETIC", collector_source=COLLECTOR):
    """Create a complete miniature AUTHORIZED spec and separately pinned record.

    This is test data only.  It authorizes no MeepCoin run and is deleted with ``root``.
    """
    ar = os.path.abspath(os.path.join(root, "authorized_root"))
    os.makedirs(ar, exist_ok=True)
    doc = copy.deepcopy(_DRAFT)
    doc["status"] = QS.STATUS_AUTHORIZED
    doc["spec_id"] = spec_id
    collector = w(os.path.join(ar, "collector.py"), collector_source)
    evaluators = {}
    for gate in doc["gates"]:
        path = w(os.path.join(ar, "evaluators", gate["id"] + ".py"),
                 EVALUATOR % gate["id"])
        evaluators[gate["id"]] = {
            "module": "evaluators/%s.py" % gate["id"], "sha256": digest(path)}
    doc["gates"] = [dict(g, thresholds={"limit": 1.0},
                         domain={"limit": {"min": 0.0, "max": 10.0}})
                    for g in doc["gates"]]
    interpreter = os.path.realpath(sys.executable)
    doc.update({
        "run_identity": spec_id,
        "snapshot": {"id": "SYNTHETIC_SNAPSHOT", "sha256": "a" * 64},
        "schedule": {"order": ["control", "attack"]},
        "condition_order": ["control", "attack"],
        "replicates": 1,
        "rates": {"total": 1.0},
        "durations": {"mine": 1.0, "post": 1.0},
        "ports": {"base": 41000, "count": 1},
        "namespace": "r17-synthetic",
        "refusal_policy": {"on_denied_workload": "refuse"},
        "required_envelope_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES),
        "collector_binding": {
            "path": "collector.py", "sha256": digest(collector),
            "interpreter": {"path": interpreter, "sha256": digest(interpreter)},
            "dependencies": {},
        },
        "authorization_record": "authz.json",
        "evaluators": evaluators,
    })
    doc["gate_inventory_sha256"] = QS.gate_inventory_digest(doc["gates"])
    doc["binding_sha256"] = "0" * 64
    doc["binding_sha256"] = QS.full_binding_digest(doc)
    spec_path = jwrite(os.path.join(ar, "spec.json"), doc)
    spec_sha = digest(spec_path)
    verifier_sha = digest(os.path.join(_NODE, "evidence_envelope.py"))
    bootstrap_sha = QV.bootstrap_closure_digest()
    auth = {
        "schema": QS.AUTHZ_SCHEMA,
        "authority": "ROUND-17 SYNTHETIC FIXTURE -- NOT A REAL AUTHORIZATION",
        "utc": "2026-09-05T00:00:00Z",
        "authorizes_spec_sha256": spec_sha,
        "authorizes_binding_sha256": doc["binding_sha256"],
        "authorizes_gate_inventory_sha256": doc["gate_inventory_sha256"],
        "authorizes_gate_semantics_sha256": QS.gate_semantics_digest(doc["gates"]),
        "authorized_required_envelope_roles": list(doc["required_envelope_roles"]),
        "authorized_evaluators": {k: v["sha256"] for k, v in evaluators.items()},
        "authorized_collector": {"path": doc["collector_binding"]["path"],
                                 "sha256": doc["collector_binding"]["sha256"]},
        "authorized_interpreter": dict(doc["collector_binding"]["interpreter"]),
        "authorized_launch_values": {f: doc.get(f) for f in QS.LAUNCH_BEARING_FIELDS},
        "authorized_bundled_verifier_sha256": verifier_sha,
        "authorized_bootstrap_sha256": bootstrap_sha,
    }
    auth_path = jwrite(os.path.join(ar, "authz.json"), auth)
    fx = {
        "root": ar, "spec_path": spec_path, "spec_sha256": spec_sha,
        "gate_inventory_sha256": doc["gate_inventory_sha256"],
        "gate_semantics_sha256": QS.gate_semantics_digest(doc["gates"]),
        "full_binding_sha256": doc["binding_sha256"],
        "authorization_path": auth_path,
        "authorization_record_sha256": digest(auth_path),
        "interpreter_path": interpreter, "interpreter_sha256": digest(interpreter),
        "collector_path": collector,
        "evaluator_paths": {k: os.path.join(ar, v["module"].replace("/", os.sep))
                            for k, v in evaluators.items()},
        "verifier_sha256": verifier_sha, "bootstrap_sha256": bootstrap_sha,
        "spec_doc": doc, "authorization_doc": auth,
    }
    # The fixture is meaningful only if the production authorization binder accepts it.
    fx["bound"] = QS.bind_authorized(
        spec_path, spec_sha, fx["gate_inventory_sha256"], fx["full_binding_sha256"],
        auth_path, fx["authorization_record_sha256"], ar)
    return fx


def build_envelope(root, spec_path, tag="A", skip_role=None, shadow_stdlib=False):
    inner = _inner_bundle(root, "inner_" + tag)
    src = os.path.join(root, "envelope_sources_" + tag)
    trace = w(os.path.join(src, "trace.json"),
              '{"kind":"environment_trace","rows":[]}\n')
    gates = w(os.path.join(src, "gates.json"),
              '{"pre_seal":true,"gates":[]}\n')
    source_inventory = w(os.path.join(src, "sources.json"), '{"modules":{}}\n')
    builder = ENV.EnvelopeBuilder(os.path.join(root, "stage_" + tag), "ENV_" + tag)
    builder.bind_collection(inner)
    builder.bind_trace(trace, ENV.TRACE_COMPLETE)
    if skip_role != "qualification_spec":
        builder.bind("qualification_spec", spec_path, relpath="tools/spec.json")
    if skip_role != "source_inventory":
        builder.bind("source_inventory", source_inventory, relpath="tools/sources.json")
    if skip_role != "outer_verifier":
        builder.bind("outer_verifier", os.path.join(_NODE, "evidence_envelope.py"),
                     relpath="tools/verifier.py")
    archive = w(os.path.join(src, "daemon_log_archive.tar.gz"), "archive bytes\n")
    side = w(os.path.join(src, "daemon_log_archive.tar.gz.sha256"),
             "%s  daemon_log_archive.tar.gz\n" % digest(archive))
    if skip_role != "daemon_log_archive":
        builder.bind("daemon_log_archive", archive,
                     relpath="tools/daemon_log_archive.tar.gz")
    if skip_role != "daemon_log_sidecar":
        builder.bind("daemon_log_sidecar", side,
                     relpath="tools/daemon_log_archive.tar.gz.sha256")
    for role in ENV.ROLES:
        if role in ("inner_collection", "environment_trace", "pre_seal_gate_results",
                    "qualification_spec", "source_inventory", "outer_verifier",
                    "daemon_log_archive", "daemon_log_sidecar") or role == skip_role:
            continue
        if shadow_stdlib and role == "driver_log":
            marker = os.path.join(root, "stdlib-shadow-executed.txt")
            path = w(os.path.join(src, "shutil.py"),
                     "open(%r, 'w').write('shadow executed')\n" % marker)
            builder.bind(role, path, relpath="tools/shutil.py")
        else:
            path = w(os.path.join(src, role + ".txt"), "role " + role + "\n")
            builder.bind(role, path, relpath="tools/" + role + ".txt")
    builder.mark_checked(gates)
    seal = builder.seal()
    final = os.path.join(root, "ENV_" + tag)
    builder.publish(final)
    typed = {r: v for r, v in ENV.typed_inventory(final).items()
             if r not in ENV.SELF_FILES}
    return final, {
        "outer_seal_sha256": digest(os.path.join(final, ENV.SEAL_FILE)),
        "verifier_sha256": (seal.get("roles", {}).get("outer_verifier", {})
                            .get("sha256")),
        "envelope_inventory_sha256": ENV.inventory_digest(typed),
    }


def complete_fixture(root, tag="A", envelope_spec_path=None, skip_role=None,
                     shadow_stdlib=False):
    fx = authorized_fixture(root, "R17_" + tag)
    env, ep = build_envelope(root, envelope_spec_path or fx["spec_path"], tag, skip_role,
                             shadow_stdlib=shadow_stdlib)
    fx.update(ep)
    fx["envelope"] = env
    return fx


def g17_kwargs(fx, package=None):
    return {
        "spec_path": fx["spec_path"],
        "expect_spec_sha256": fx["spec_sha256"],
        "expect_gate_inventory_sha256": fx["gate_inventory_sha256"],
        "expect_gate_semantics_sha256": fx["gate_semantics_sha256"],
        "expect_full_binding_sha256": fx["full_binding_sha256"],
        "authorization_path": fx["authorization_path"],
        "expect_authorization_record_sha256": fx["authorization_record_sha256"],
        "authorized_root": fx["root"],
        "expect_interpreter_path": fx["interpreter_path"],
        "expect_interpreter_sha256": fx["interpreter_sha256"],
        "expect_outer_seal_sha256": fx["outer_seal_sha256"],
        "expect_bundled_verifier_sha256": fx["verifier_sha256"],
        "expect_bootstrap_sha256": fx["bootstrap_sha256"],
        "expect_envelope_inventory_sha256": fx["envelope_inventory_sha256"],
        "expect_trace_status": ENV.TRACE_COMPLETE,
        "attestation_package": package,
    }


def call_g17(fx, workspace, package=None, **overrides):
    kw = g17_kwargs(fx, package)
    kw.update(overrides)
    try:
        return QV.relocate_and_verify(fx["envelope"], workspace, **kw)
    except BaseException as e:
        return {"_exception": "%s: %s" % (type(e).__name__, e),
                "failures": ["unexpected exception: %s: %s" % (type(e).__name__, e)],
                "g17_pass": False, "child_record": None}


def attestation_kwargs(fx, anchor=None):
    out = {
        "expect_authorized_spec_sha256": fx["spec_sha256"],
        "expect_gate_inventory_sha256": fx["gate_inventory_sha256"],
        "expect_gate_semantics_sha256": fx["gate_semantics_sha256"],
        "expect_full_binding_sha256": fx["full_binding_sha256"],
        "expect_authorization_record_sha256": fx["authorization_record_sha256"],
        "expect_authorized_root": fx["root"],
        "expect_interpreter_path": fx["interpreter_path"],
        "expect_interpreter_sha256": fx["interpreter_sha256"],
        "expect_outer_seal_sha256": fx["outer_seal_sha256"],
        "expect_verifier_sha256": fx["verifier_sha256"],
        "expect_bootstrap_sha256": fx["bootstrap_sha256"],
        "expect_envelope_inventory_sha256": fx["envelope_inventory_sha256"],
    }
    if anchor is not None:
        out["expect_attestation_sha256"] = anchor
    return out


def failed_before_child(result, package=None, needle=None):
    failures = result.get("failures") if isinstance(result, dict) else []
    package_absent = package is None or not os.path.exists(package)
    return (isinstance(result, dict) and not result.get("_exception")
            and result.get("g17_pass") is not True
            and not result.get("child_record") and package_absent
            and (needle is None or has(failures, needle)))


def wrong_value(name, good, root):
    if name in ("expect_authorized_root", "expect_interpreter_path"):
        return os.path.join(root, "wrong_" + name)
    return "0" * 64 if good != "0" * 64 else "1" * 64


def cli_args(fx, package=None):
    args = [
        fx["envelope"],
        "--spec=" + fx["spec_path"],
        "--spec-sha256=" + fx["spec_sha256"],
        "--gate-inventory-sha256=" + fx["gate_inventory_sha256"],
        "--gate-semantics-sha256=" + fx["gate_semantics_sha256"],
        "--full-binding-sha256=" + fx["full_binding_sha256"],
        "--authorization=" + fx["authorization_path"],
        "--authorization-sha256=" + fx["authorization_record_sha256"],
        "--authorized-root=" + fx["root"],
        "--interpreter=" + fx["interpreter_path"],
        "--interpreter-sha256=" + fx["interpreter_sha256"],
        "--outer-seal-sha256=" + fx["outer_seal_sha256"],
        "--verifier-sha256=" + fx["verifier_sha256"],
        "--bootstrap-sha256=" + fx["bootstrap_sha256"],
        "--envelope-inventory-sha256=" + fx["envelope_inventory_sha256"],
        "--trace-status=" + ENV.TRACE_COMPLETE,
    ]
    if package:
        args.append("--attestation-package=" + os.path.abspath(package))
    return args


def runner_sequence(fx, staging, timeout=30):
    """Run the exact post-bind sequence with a synthetic clean preflight.

    This is deliberately not represented as a successful public ``run_authorized`` preflight:
    that public entry point owns the real fail-closed host inventory, which this offline suite
    must not bypass.  The child process, when reached, is still owned by the production sequence.
    """
    return RUN._sequence(
        fx["spec_path"], fx["spec_sha256"], fx["gate_inventory_sha256"],
        fx["full_binding_sha256"], fx["authorization_path"],
        fx["authorization_record_sha256"], fx["root"], staging,
        synthetic_preflight(), timeout, time.time, False, False)


def test_r6_0_public_contracts_and_bootstrap():
    sig = inspect.signature(RP.run_observed)
    check("T17-0. the production provenance API is one process-owning run_observed operation",
          list(sig.parameters) == ["argv", "executable", "expect_executable_sha256", "cwd",
                                    "root", "expected_inputs", "sidecar_path", "env", "timeout",
                                    "env_policy", "declared_outputs"], str(sig))
    qsig = inspect.signature(QV.relocate_and_verify)
    forbidden = {"authorized_run", "spec_required_roles", "bundled_verifier_role", "runner",
                 "child_prelude"}
    check("T17-0b. the production G17 API exposes paths and independent pins, not caller authority",
          not (forbidden & set(qsig.parameters)) and
          {"spec_path", "authorization_path", "authorized_root",
           "expect_gate_inventory_sha256", "expect_gate_semantics_sha256",
           "expect_full_binding_sha256", "expect_authorization_record_sha256",
           "expect_envelope_inventory_sha256"} <= set(qsig.parameters), str(qsig))
    check("T17-0c. qual_spec is part of the externally pinned G17 bootstrap closure",
          set(QV.BOOTSTRAP_FILES) == {"qual_verify_v2.py", "evidence_envelope.py",
                                      "qual_spec.py", "run_provenance.py"},
          list(QV.BOOTSTRAP_FILES))

    with tempfile.TemporaryDirectory() as td:
        mod = os.path.join(td, "modules")
        os.makedirs(mod)
        for name in QV.BOOTSTRAP_FILES:
            shutil.copyfile(os.path.join(_NODE, name), os.path.join(mod, name))

        def ask(tag):
            program = RP.CHILD_SHIM_SOURCE + (
                "_sy.path.insert(0, %r)\n"
                "import qual_verify_v2 as _qv\n"
                "print(_qv.bootstrap_closure_digest())\n" % mod)
            executable = os.path.realpath(sys.executable)
            argv = [executable, "-I", "-B", "-c", program]
            side = os.path.join(td, "bootstrap_%s.json" % tag)
            expected = {os.path.realpath(os.path.join(mod, n)): digest(os.path.join(mod, n))
                        for n in QV.BOOTSTRAP_FILES}
            res = RP.run_observed(
                argv, executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs=expected, sidecar_path=side,
                env=dict(os.environ), timeout=30)
            adopt(res)
            text = getattr(res, "stdout_text", None)
            if text is None:
                text = getattr(res, "stdout", b"").decode("utf-8", "replace")
            return text.strip().splitlines()[-1], res

        before, r1 = ask("before")
        qsp = os.path.join(mod, "qual_spec.py")
        with open(qsp, "ab") as f:
            f.write(b"\n# disposable Round-17 mutation\n")
        after, r2 = ask("after")
        check("T17-0d. mutating only a disposable qual_spec.py changes the real bootstrap digest",
              before != after and not getattr(r1, "sidecar_failures", [])
              and not getattr(r2, "sidecar_failures", []),
              {"before": before, "after": after,
               "before_sidecar": getattr(r1, "sidecar_failures", []),
               "after_sidecar": getattr(r2, "sidecar_failures", [])})


def test_r6_1_real_process_ownership():
    with tempfile.TemporaryDirectory() as td:
        a = harmless_observed_child(td, "A")
        record, doc, result = a["record"], a["doc"], a["result"]
        entry = adopt(result)
        check("T17-1. BASELINE: a marker exists only after the production API really ran the child",
              os.path.isfile(a["marker"]) and open(a["marker"], encoding="utf-8").read() == "ran",
              a["marker"])
        check("T17-1b. PID, return code and completion come from the same real process record",
              isinstance(record.get("pid"), int) and record["pid"] > 0
              and doc.get("pid") == record["pid"] and record.get("exit") == 0
              and record.get("process_started") is True and record.get("process_returned") is True
              and record.get("process_proof_ok") is True, record.get("pid"))
        check("T17-1c. stdout remains exact raw bytes, with byte count and digest over those bytes",
              getattr(result, "stdout", None) == a["stdout"]
              and record.get("stdout_bytes") == len(a["stdout"])
              and record.get("stdout_sha256") == hashlib.sha256(a["stdout"]).hexdigest(),
              (record.get("stdout_bytes"), record.get("stdout_sha256")))
        check("T17-1d. valid sidecar closure is required for execution proof and CHILD_OBSERVED",
              not getattr(result, "sidecar_failures", [])
              and record.get("execution_proof_ok") is True
              and entry.get("child_closure") == RP.CHILD_OBSERVED,
              (getattr(result, "sidecar_failures", []), entry.get("child_closure")))
        classes = record.get("sidecar_path_classes") or []
        check("T17-1d2. child paths are explicitly classified as root, bound, external or invalid",
              any(x.get("scope") == "root" for x in classes)
              and any(x.get("scope") == "external" for x in classes)
              and all(x.get("scope") in {"root", "bound_input", "external", "invalid"}
                      for x in classes), classes[:5])

        hit, msg = refusal(lambda: RP.begin_launch(a["argv"], executable=a["argv"][0],
                                                   cwd=td, root=td,
                                                   sidecar_path=os.path.join(td, "legacy.json")),
                           "caller-driven starting()/completed() calls cannot prove a process ran",
                           RP.LaunchObserverError)
        check("T17-1e. the exact R6-1 split lifecycle is unsupported before it can create a marker",
              hit, msg)

        copied = copy.deepcopy(record)
        hit_copy, msg_copy = refusal(lambda: RECORDER.adopt_child_record(copied),
                                     "already been adopted", ValueError)
        later = RP.ProvenanceRecorder(td, local_dir=td, strict=False)
        hit_again, msg_again = refusal(lambda: later.adopt_child_record(record),
                                       "already been adopted", ValueError)
        fake = dict(copied, record_token="f" * 32)
        hit_fake, msg_fake = refusal(lambda: RECORDER.adopt_child_record(fake),
                                     "not produced", ValueError)
        check("T17-1f. copied, caller-manufactured and second-recorder adoptions all fail",
              hit_copy and hit_again and hit_fake,
              (msg_copy[:70], msg_again[:70], msg_fake[:70]))

        b = harmless_observed_child(td, "B", b"second-child")
        adopt(b["result"])
        swapped = sidecar_probe(record, b["doc"], "swapped_sidecar")
        wrong_pid = copy.deepcopy(doc)
        wrong_pid["pid"] = record["pid"] + 1
        pid_fail = sidecar_probe(record, wrong_pid, "wrong_pid")
        check("T17-1g. a sidecar from another real child is rejected by nonce/identity/PID binding",
              swapped and (has(swapped, "nonce") or has(swapped, "command identity")),
              swapped[:3])
        check("T17-1h. a positive but wrong PID is rejected against the parent's Popen.pid",
              has(pid_fail, "pid") and has(pid_fail, "parent"), pid_fail[:3])


def test_r6_1_recorder_lifecycle_boundaries():
    with tempfile.TemporaryDirectory() as td:
        once = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        once.finish()
        begin_hit, begin_msg = refusal(once.begin, "single-use", RuntimeError)
        finish_hit, finish_msg = refusal(once.finish, "active", RuntimeError)
        check("T17-1p. a recorder is single-use: repeat begin and repeat finish both refuse",
              begin_hit and finish_hit, (begin_msg, finish_msg))

    with tempfile.TemporaryDirectory() as td:
        visible = w(os.path.join(td, "visible.txt"), "visible\n")
        outer = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        inner = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        lifo_hit, lifo_msg = refusal(outer.finish, "LIFO", RuntimeError)
        with open(visible, encoding="utf-8") as f:
            f.read()
        inner_saw_read = "visible.txt" in inner.undeclared
        inner.finish()
        outer.finish()
        check("T17-1q. out-of-order nested finish refuses without removing the inner read hooks",
              lifo_hit and inner_saw_read, (lifo_msg, sorted(inner.undeclared)))

    with tempfile.TemporaryDirectory() as td:
        child = harmless_observed_child(td, "BEFORE_LATE", b"before-late-recorder")
        late = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        late_hit, late_msg = refusal(
            lambda: late.adopt_child_record(child["record"]), "not active", ValueError)
        late.finish()
        adopt(child["result"])
        check("T17-1r. a recorder begun after a real child returned cannot adopt that history",
              late_hit and late.declared_subprocesses == [], late_msg)

    with tempfile.TemporaryDirectory() as td:
        local = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        executable = os.path.realpath(sys.executable)
        sidecar = os.path.join(td, "crossing.provenance.json")
        argv = [executable, "-I", "-B", "-c",
                RP.CHILD_SHIM_SOURCE + "import time as _t; _t.sleep(0.8)\n"]
        holder = {}

        def run_crossing_child():
            holder["result"] = RP.run_observed(
                argv, executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs={}, sidecar_path=sidecar,
                env=dict(os.environ), timeout=30)

        worker = threading.Thread(target=run_crossing_child)
        worker.start()
        deadline = time.time() + 10
        while time.time() < deadline and not any(
                d.get("observation_pending") for d in local.declared_subprocesses):
            time.sleep(0.01)
        inflight_hit, inflight_msg = refusal(local.finish, "in-flight", RuntimeError)
        remained_active = local._active and local.end is None
        worker.join(10)
        if "result" in holder:
            adopt(holder["result"])
        local.finish()
        check("T17-1s. finish refuses across a real in-flight child and leaves the recorder "
              "active until finalization and adoption",
              inflight_hit and remained_active and not worker.is_alive()
              and local.finish_boundary_failures == [], inflight_msg)

    with tempfile.TemporaryDirectory() as td:
        local = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        child = harmless_observed_child(td, "PENDING_FINISH", b"pending-finish")
        pending_hit, pending_msg = refusal(local.finish, "unadopted", RuntimeError)
        still_active = local._active and local.end is None
        adopt(child["result"])
        local.finish()
        check("T17-1t. finish likewise refuses a completed but unadopted real child",
              pending_hit and still_active and local.finish_boundary_failures == [], pending_msg)

    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=()).begin()
        r.pin_test_inventory(["one"], 1, 0)
        r.finish()
        def promoted():
            return r.report("extra", ["x"], canonical=False,
                            actual_test_ids=["one"], actual_check_count=1,
                            extra={"canonical": True, "live": True,
                                   "non_evidence": False})
        core_hit, core_msg = refusal(promoted, "reserved", ValueError)
        check("T17-1u. extra fields cannot promote a noncanonical report, conceal live work, or "
              "erase its non-evidence classification", core_hit, core_msg)
        doc = r.report("extra", ["x"], canonical=False,
                       actual_test_ids=["one"], actual_check_count=1,
                       extra={"canonical": False, "live": False, "non_evidence": True,
                              "label": "matching duplicates are inert"})
        check("T17-1v. identical duplicates of reserved core fields are ignored, while ordinary "
              "extra labels remain available",
              doc.get("canonical") is False and doc.get("live") is False
              and doc.get("non_evidence") is True
              and doc.get("label") == "matching duplicates are inert", doc)

        guarded = RUN.RefusalOnlyRunner(None).refusal(
            "SYNTHETIC", "plain refusal",
            {"child_record": {"attack_confirmed": True}})
        check("T17-1w. only the exact top-level raw child record bypasses prose inspection; a "
              "nested look-alike is redacted",
              guarded.get("detail") == {
                  "redacted": True,
                  "why": "reserved scientific vocabulary in untrusted diagnostics"}
              and "attack_confirmed" not in json.dumps(guarded, sort_keys=True), guarded)


def test_r6_1_prelaunch_refusals():
    with tempfile.TemporaryDirectory() as td:
        executable = os.path.realpath(sys.executable)
        marker = os.path.join(td, "must_not_exist.txt")
        inp = wb(os.path.join(td, "input.bin"), b"before")
        old = digest(inp)
        wb(inp, b"after")
        program = RP.CHILD_SHIM_SOURCE + "open(%r, 'w').write('bad')\n" % marker
        argv = [executable, "-I", "-B", "-c", program]
        hit, msg = refusal(
            lambda: RP.run_observed(
                argv, executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs={os.path.realpath(inp): old},
                sidecar_path=os.path.join(td, "input_sidecar.json"), env=dict(os.environ)),
            "launch input", RP.LaunchObserverError)
        check("T17-1i. a staged input changed before run_observed refuses with launch count zero",
              hit and not os.path.exists(marker)
              and not os.path.exists(os.path.join(td, "input_sidecar.json")), msg)

        copied_exe = os.path.join(td, "python-copy")
        shutil.copy2(executable, copied_exe)
        old_exe = digest(copied_exe)
        with open(copied_exe, "ab") as f:
            f.write(b"\x00")
        os.chmod(copied_exe, os.stat(executable).st_mode)
        hit2, msg2 = refusal(
            lambda: RP.run_observed(
                [copied_exe, "-c", "open(%r, 'w').write('bad')" % marker],
                executable=copied_exe, expect_executable_sha256=old_exe,
                cwd=td, root=td, expected_inputs={},
                sidecar_path=os.path.join(td, "exe_sidecar.json"), env=dict(os.environ)),
            "executable", RP.LaunchObserverError)
        check("T17-1j. an executable changed before run_observed also refuses before process start",
              hit2 and "hash" in msg2.lower() and not os.path.exists(marker), msg2)

        relative_argv = [os.path.basename(executable), "-c",
                         "open(%r, 'w').write('bad')" % marker]
        hit3, msg3 = refusal(
            lambda: RP.run_observed(
                relative_argv, executable=executable,
                expect_executable_sha256=digest(executable), cwd=td, root=td,
                expected_inputs={}, sidecar_path=os.path.join(td, "relative_argv.json"),
                env=dict(os.environ)), "absolute", RP.LaunchObserverError)
        check("T17-1k. relative argv[0] is refused before the process-owning call can launch",
              hit3 and not os.path.exists(marker), msg3)

        alias = os.path.join(td, "python-symlink")
        os.symlink(executable, alias)
        hit4, msg4 = refusal(
            lambda: RP.run_observed(
                [alias, "-c", "open(%r, 'w').write('bad')" % marker],
                executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs={},
                sidecar_path=os.path.join(td, "alias_argv.json"), env=dict(os.environ)),
            "alias", RP.LaunchObserverError)
        check("T17-1l. symlink-alias argv[0] is refused before process start",
              hit4 and not os.path.exists(marker), msg4)

        bad_env = dict(os.environ)
        bad_env["R6_REVIEW_FORBIDDEN"] = "present"
        mismatched_policy = RP.environment_policy({})
        hit5, msg5 = refusal(
            lambda: RP.run_observed(
                argv, executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs={},
                sidecar_path=os.path.join(td, "bad_env_policy.json"), env=bad_env,
                env_policy=mismatched_policy),
            "environment policy", RP.LaunchObserverError)
        check("T17-1l2. a caller policy that omits a real environment key refuses before launch",
              hit5 and not os.path.exists(marker)
              and not os.path.exists(os.path.join(td, "bad_env_policy.json")), msg5)


def test_r6_1_runner_source_deleted_at_prelaunch():
    """The injected diagnostic preflight deletes only a disposable synthetic collector."""
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td, "R17_RUNNER_DELETE")

        class DeleteCollectorAtPreLaunch(WP.WorkloadPreflight):
            def check(self, stage, spec=None):
                result = super().check(stage, spec)
                if stage == "pre_launch" and os.path.isfile(fx["collector_path"]):
                    os.unlink(fx["collector_path"])
                return result

        staging = os.path.join(td, "runner_staging")
        result = RUN.diagnostic_dry_run(
            fx["spec_path"], fx["spec_sha256"], fx["gate_inventory_sha256"],
            fx["full_binding_sha256"], fx["authorization_path"],
            fx["authorization_record_sha256"], fx["root"], staging,
            synthetic_preflight(DeleteCollectorAtPreLaunch), guard_requires_absent=False)
        check("T17-1m. collector deletion after preflight is a structured zero-launch refusal",
              isinstance(result, dict) and result.get("refused") is True
              and result.get("code") == "STAGED_CODE_MISMATCH"
              and result.get("launch_callback_invocations") == 0
              and "launch_and_collect" not in result.get("event_sequence", []), result)

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td, "R17_RUNNER_ROOT_ALIAS")
        staging = os.path.join(td, "must_not_exist")
        result = RUN.diagnostic_dry_run(
            fx["spec_path"], fx["spec_sha256"], fx["gate_inventory_sha256"],
            fx["full_binding_sha256"], fx["authorization_path"],
            fx["authorization_record_sha256"], fx["root"] + os.sep + ".", staging,
            synthetic_preflight(), guard_requires_absent=False)
        check("T17-1m2. MUTATION: the runner refuses a noncanonical authorization root before "
              "staging or child creation",
              isinstance(result, dict) and result.get("code") == "SPEC_REFUSED"
              and result.get("launch_callback_invocations") == 0
              and not os.path.exists(staging)
              and has([result.get("reason")], "canonical"), result)

    # staging_dir is the runner's first filesystem side effect.  Ambiguous spellings must refuse
    # before even an empty directory appears at the caller-dependent destination.
    for label in ("relative", "dotdot", "nul", "wrong-type"):
        with tempfile.TemporaryDirectory() as td:
            fx = authorized_fixture(td, "R17_STAGE_" + label.upper().replace("-", "_"))
            os.makedirs(os.path.join(td, "parent"), exist_ok=True)
            if label == "relative":
                staging, would_create = "relative_stage", os.path.join(td, "relative_stage")
            elif label == "dotdot":
                staging = os.path.join(td, "parent", "..", "escaped_stage")
                would_create = os.path.join(td, "escaped_stage")
            elif label == "nul":
                staging, would_create = os.path.join(td, "stage\x00bad"), None
            else:
                staging, would_create = None, None
            before = os.getcwd()
            try:
                os.chdir(td)
                result = RUN.diagnostic_dry_run(
                    fx["spec_path"], fx["spec_sha256"], fx["gate_inventory_sha256"],
                    fx["full_binding_sha256"], fx["authorization_path"],
                    fx["authorization_record_sha256"], fx["root"], staging,
                    synthetic_preflight(), guard_requires_absent=False)
            finally:
                os.chdir(before)
            check("T17-1n. MUTATION: %-10s staging path refuses before mkdir or child" % label,
                  isinstance(result, dict) and result.get("code") == "STAGING_PATH_REFUSED"
                  and result.get("launch_callback_invocations") == 0
                  and (would_create is None or not os.path.exists(would_create)), result)

    with tempfile.TemporaryDirectory() as td:
        minimum = {"raw_records": 1, "branch_observations": 1,
                   "collection_seconds": 0.01}
        nul = dict(minimum, staging_dir=td + "\x00elsewhere")
        dotted = dict(minimum, staging_dir=os.path.join(td, "."))
        _kept_nul, _opaque_nul, nul_fails = RUN.coerce_retained(nul, staging_dir=td)
        _kept_dot, _opaque_dot, dot_fails = RUN.coerce_retained(dotted, staging_dir=td)
        _ki, _oi, huge_int_fails = RUN.coerce_retained(
            dict(minimum, raw_records=10 ** 400), staging_dir=td)
        _kf, _of, huge_float_fails = RUN.coerce_retained(
            dict(minimum, collection_seconds=10 ** 400), staging_dir=td)
        check("T17-1o. MUTATION: untrusted collector staging paths with NUL or noncanonical "
              "spelling and huge integers return deterministic failures, not tracebacks",
              has(nul_fails, "NUL") and has(dot_fails, "canonical")
              and has(huge_int_fails, "outside") and has(huge_float_fails, "finite"),
              {"nul": nul_fails, "dot": dot_fails,
               "huge_int": huge_int_fails, "huge_float": huge_float_fails})


def test_r6_2_diagnostics_never_complete_closure():
    with tempfile.TemporaryDirectory() as td:
        readp = w(os.path.join(td, "undeclared.txt"), "read\n")
        codep = w(os.path.join(td, "outside.py"), "X = 1\n")
        recorder = RP.ProvenanceRecorder(td, local_dir=td, strict=False,
                                         doc_dirs=()).begin()
        argv = [os.path.realpath(sys.executable), "-c", "synthetic closure entry"]
        entry = {
            "argv_key": RP.argv_key(argv), "argv": argv,
            "command_identity": RP.command_identity(argv),
            "command_display": RP.argv_display(argv),
            "process_started": True, "process_returned": True, "exit": 0,
            "child_closure": RP.CHILD_NOT_OBSERVED,
            "sidecar_failures": ["deliberately corrupt sidecar"],
            "input_drift": ["bound.txt"],
            "child_provenance": {
                "reads": [{"path": readp, "how": "builtins.open", "sha256": digest(readp)}],
                "code_reads": [{"path": codep, "how": "open_code", "sha256": digest(codep)}],
                "metadata": [{"path": td, "how": ["os.listdir"], "kind": "directory",
                              "entries": sorted(os.listdir(td)),
                              "entry_count": len(os.listdir(td)), "size": None}],
                "grandchildren": [{"argv": ["python", "-c", "pass"],
                                    "command_identity": RP.command_identity(
                                        ["python", "-c", "pass"])}],
            },
        }
        recorder.declared_subprocesses.append(entry)
        empty_hit, empty_msg = refusal(lambda: recorder.note_diagnostic_child(argv, "  "),
                                       "reason", ValueError)
        check("T17-2. an empty diagnostic disclosure reason remains invalid",
              empty_hit, empty_msg)
        recorder.note_diagnostic_child(argv, "intentional pure closure mutation")
        complete, reasons = recorder._closure_completeness()
        check("T17-2b. a diagnostic label cannot erase sidecar, closure, grandchild or drift faults",
              not complete and has(reasons, "sidecar") and has(reasons, "not an observed child")
              and has(reasons, "grandchild") and has(reasons, "changed while"), reasons)
        undeclared, outside, metadata = recorder.child_inputs({})
        check("T17-2c. diagnostic reads, code and metadata enter the same accounting as any child",
              bool(undeclared) and bool(outside) and bool(metadata),
              (sorted(undeclared), sorted(outside), sorted(metadata)))
        recorder.pin_test_inventory(["synthetic_diagnostic"], 1)
        recorder.finish()
        report = recorder.report(
            "round17_synthetic_diagnostic", ["synthetic"], canonical=True,
            actual_test_ids=["synthetic_diagnostic"], actual_check_count=1)
        check("T17-2d. a canonical report containing that child is provenance-incomplete, never green",
              report["api_observed_closure_complete"] is False
              and report["provenance_ok"] is False
              and report["closure_incomplete_reasons"],
              report["provenance_problems"][:2])


def test_r6_3_real_authorization_positive():
    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "POS")
        out_parent = os.path.join(td, "published")
        os.makedirs(out_parent)
        package = os.path.join(out_parent, ENV.CANONICAL_ATTESTATION_DIR)
        result = call_g17(fx, os.path.join(td, "workspace"), package)
        entry = adopt(result) if result.get("child_record") else None
        binding = result.get("authorization_binding") or {}
        check("T17-3. a complete spec and separately pinned authorization reach one harmless G17 child",
              not result.get("_exception") and result.get("authorization_verified") is True
              and result.get("g17_pass") is True and entry is not None
              and entry.get("child_closure") == RP.CHILD_OBSERVED,
              result.get("failures", [])[:3])
        check("T17-3b. the result binds spec, inventory, semantics, full binding, record and runtime",
              binding.get("authorized_spec_sha256") == fx["spec_sha256"]
              and binding.get("gate_inventory_sha256") == fx["gate_inventory_sha256"]
              and binding.get("gate_semantics_sha256") == fx["gate_semantics_sha256"]
              and binding.get("full_binding_sha256") == fx["full_binding_sha256"]
              and binding.get("authorization_record_sha256") ==
                  fx["authorization_record_sha256"]
              and binding.get("interpreter_sha256") == fx["interpreter_sha256"], binding)
        check("T17-3c. collector/evaluator identities are transitively fixed by that verified binding",
              binding.get("authorized_collector") ==
                  fx["bound"].authorization_binding_plain().get("authorized_collector")
              and binding.get("authorized_evaluators") ==
                  fx["bound"].authorization_binding_plain().get("authorized_evaluators"),
              {"collector": binding.get("authorized_collector"),
               "evaluator_count": len(binding.get("authorized_evaluators") or {})})
        check("T17-3d. canonical publication follows G17 and yields an external attestation anchor",
              os.path.isdir(package) and ENV._is_hex64(result.get("attestation_sha256") or ""),
              result.get("attestation_publication_error"))

    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "STDLIB_SHADOW", shadow_stdlib=True)
        marker = os.path.join(td, "stdlib-shadow-executed.txt")
        package = os.path.join(td, "published", ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(os.path.dirname(package))
        result = call_g17(fx, os.path.join(td, "workspace"), package)
        if result.get("child_record"):
            adopt(result)
        check("T17-3e. a sealed sibling named like a standard-library module is data, not an "
              "implicit child import path",
              result.get("g17_pass") is True and not os.path.exists(marker),
              {"failures": result.get("failures", [])[:3], "marker": os.path.exists(marker)})


def _invalid_spec_case(root, doc, name):
    path = jwrite(os.path.join(root, name + ".json"), doc)
    return path, digest(path)


def test_r6_3_authorization_refusal_matrix():
    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(os.path.join(td, "pins"), "PINS")
        mutations = (
            ("wrong spec bytes", "expect_spec_sha256", "0" * 64, "spec"),
            ("wrong gate inventory", "expect_gate_inventory_sha256", "0" * 64, "inventory"),
            ("wrong gate semantics", "expect_gate_semantics_sha256", "0" * 64, "semantics"),
            ("wrong full binding", "expect_full_binding_sha256", "0" * 64, "binding"),
            ("wrong authorization record", "expect_authorization_record_sha256", "0" * 64,
             "authorization"),
            ("wrong authorized root", "authorized_root", os.path.join(td, "wrong-root"), "root"),
            ("noncanonical authorized root", "authorized_root", fx["root"] + os.sep + ".",
             "canonical"),
            ("wrong interpreter path", "expect_interpreter_path", fx["collector_path"],
             "interpreter"),
            ("wrong interpreter bytes", "expect_interpreter_sha256", "0" * 64, "interpreter"),
        )
        for i, (label, key, value, needle) in enumerate(mutations):
            package = os.path.join(td, "packages", "p%d" % i,
                                   ENV.CANONICAL_ATTESTATION_DIR)
            os.makedirs(os.path.dirname(package), exist_ok=True)
            result = call_g17(fx, os.path.join(td, "work_%d" % i), package,
                              **{key: value})
            check("T17-3e. MUTATION: %-28s fails before child/package" % label,
                  failed_before_child(result, package, needle),
                  result.get("failures", result.get("_exception"))[:3]
                  if isinstance(result.get("failures"), list) else result.get("_exception"))

    publication_cases = {}
    for index, (label, package_value) in enumerate((
            ("missing", None), ("wrong type", 42),
            ("relative", os.path.join("relative", ENV.CANONICAL_ATTESTATION_DIR)))):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "PUBLISH_PATH_%d" % index)
            result = call_g17(fx, os.path.join(td, "work"), package_value)
            publication_cases[label] = result
    check("T17-3e2. production G17 requires a canonical absolute detached-attestation target "
          "before it can start a child",
          all(not r.get("_exception") and not r.get("child_record")
              and r.get("g17_pass") is False
              and has(r.get("failures", []), "attestation_package")
              for r in publication_cases.values()),
          {k: v.get("failures", v.get("_exception"))
           for k, v in publication_cases.items()})

    for label, mutate in (
            ("collector bytes", "collector"), ("evaluator bytes", "evaluator"),
            ("authorization roles", "roles")):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, label.replace(" ", "_").upper())
            if mutate == "collector":
                with open(fx["collector_path"], "ab") as f:
                    f.write(b"\n# changed\n")
            elif mutate == "evaluator":
                first = fx["evaluator_paths"][sorted(fx["evaluator_paths"])[0]]
                with open(first, "ab") as f:
                    f.write(b"\n# changed\n")
            else:
                rec = copy.deepcopy(fx["authorization_doc"])
                rec["authorized_required_envelope_roles"] = \
                    rec["authorized_required_envelope_roles"][:-1]
                jwrite(fx["authorization_path"], rec)
                fx["authorization_record_sha256"] = digest(fx["authorization_path"])
            package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
            os.makedirs(os.path.dirname(package), exist_ok=True)
            result = call_g17(fx, os.path.join(td, "work"), package)
            check("T17-3f. MUTATION: changed %-20s fails before child/package" % label,
                  failed_before_child(result, package), result.get("failures", [])[:3])

    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "UNSAFE_AUTH_PATH")
        wrong_path = os.path.join(td, "outside_authz.json")
        shutil.copyfile(fx["authorization_path"], wrong_path)
        package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(os.path.dirname(package), exist_ok=True)
        result = call_g17(fx, os.path.join(td, "work"), package,
                          authorization_path=wrong_path,
                          expect_authorization_record_sha256=digest(wrong_path))
        check("T17-3g. MUTATION: an auth record outside the safe spec-named path is refused",
              failed_before_child(result, package, "authorization"), result.get("failures", [])[:3])

    status_only = copy.deepcopy(_DRAFT)
    status_only["status"] = QS.STATUS_AUTHORIZED
    status_only["spec_id"] = "R17_STATUS_ONLY"
    status_only["gate_inventory_sha256"] = QS.gate_inventory_digest(status_only["gates"])
    status_only["binding_sha256"] = QS.full_binding_digest(status_only)
    for label, doc in (
            ("trivial spec", {"spec_id": "X"}),
            ("status-only AUTHORIZED", status_only),
            ("committed DRAFT_NO_LAUNCH", copy.deepcopy(_DRAFT))):
        with tempfile.TemporaryDirectory() as td:
            fx = authorized_fixture(td, "R17_INVALID_BASE")
            bad_spec, bad_sha = _invalid_spec_case(td, doc, "bad_spec")
            env, ep = build_envelope(td, bad_spec, "BAD")
            fx.update(ep)
            fx.update({"envelope": env, "spec_path": bad_spec, "spec_sha256": bad_sha,
                       "gate_inventory_sha256": (doc.get("gate_inventory_sha256")
                                                  or "0" * 64),
                       "gate_semantics_sha256": (QS.gate_semantics_digest(doc.get("gates") or [])
                                                   if isinstance(doc.get("gates"), list)
                                                   else "0" * 64),
                       "full_binding_sha256": doc.get("binding_sha256") or "0" * 64})
            package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
            os.makedirs(os.path.dirname(package), exist_ok=True)
            result = call_g17(fx, os.path.join(td, "work"), package)
            check("T17-3h. MUTATION: %-25s cannot create authority" % label,
                  failed_before_child(result, package), result.get("failures", [])[:3])

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td, "R17_ENVELOPE_MISMATCH")
        other = jwrite(os.path.join(td, "other_spec.json"), {"spec_id": "OTHER"})
        env, ep = build_envelope(td, other, "MISMATCH")
        fx.update(ep)
        fx["envelope"] = env
        package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(os.path.dirname(package), exist_ok=True)
        result = call_g17(fx, os.path.join(td, "work"), package)
        check("T17-3i. MUTATION: the envelope spec must be the exact externally bound spec",
              failed_before_child(result, package, "spec"), result.get("failures", [])[:3])

    sig = inspect.signature(QV.relocate_and_verify)
    old_authority = {"authorized_run", "spec_required_roles", "bundled_verifier_role"}
    check("T17-3j. caller booleans and role labels are absent from the production signature",
          not (old_authority & set(sig.parameters)), str(sig))


def test_r6_3_malformed_nested_authority_inputs():
    """Untrusted JSON must become a structured refusal, never a raw Python type error."""
    auth_cases = (
        "mixed role type", "duplicate role", "bad evaluator digest", "collector extra key",
        "nul collector", "relative interpreter", "nul interpreter", "launch extra key",
        "non-string authority", "inert outer-seal claim",
    )
    for index, label in enumerate(auth_cases):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "AUTH_SCHEMA_%d" % index)
            rec = copy.deepcopy(fx["authorization_doc"])
            if label == "mixed role type":
                rec["authorized_required_envelope_roles"].append(1)
            elif label == "duplicate role":
                rec["authorized_required_envelope_roles"].append(
                    rec["authorized_required_envelope_roles"][0])
            elif label == "bad evaluator digest":
                rec["authorized_evaluators"][sorted(rec["authorized_evaluators"])[0]] = "A" * 64
            elif label == "collector extra key":
                rec["authorized_collector"]["claim"] = True
            elif label == "nul collector":
                rec["authorized_collector"]["path"] = "collector\x00.py"
            elif label == "relative interpreter":
                rec["authorized_interpreter"]["path"] = "python3"
            elif label == "nul interpreter":
                rec["authorized_interpreter"]["path"] = "/tmp/x\x00y"
            elif label == "launch extra key":
                rec["authorized_launch_values"]["unreviewed"] = True
            elif label == "non-string authority":
                rec["authority"] = 17
            else:
                # This field used to be allowlisted but never validated, retained, or compared.
                rec["authorized_outer_seal_sha256"] = "0" * 64
            jwrite(fx["authorization_path"], rec)
            fx["authorization_record_sha256"] = digest(fx["authorization_path"])
            package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
            result = call_g17(fx, os.path.join(td, "work"), package)

            cli_ok = True
            cli_detail = None
            if label in ("mixed role type", "nul collector", "nul interpreter"):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        rc = QV.main(cli_args(fx, package))
                        raised = None
                    except BaseException as e:
                        rc, raised = None, "%s: %s" % (type(e).__name__, e)
                emitted = stdout.getvalue() + stderr.getvalue()
                cli_ok = raised is None and isinstance(rc, int) and rc != 0 \
                    and "traceback" not in emitted.lower()
                cli_detail = {"return": rc, "raised": raised, "output": emitted[-180:]}
            check("T17-3l. MALFORMED AUTH: %-22s is a structured zero-child refusal" % label,
                  failed_before_child(result, package) and cli_ok,
                  {"api": result.get("failures", result.get("_exception")), "cli": cli_detail})

    for index, label in enumerate(("object gate id", "boolean gate index",
                                   "nul evaluator path")):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "SPEC_SCHEMA_%d" % index)
            doc = copy.deepcopy(fx["spec_doc"])
            if label == "object gate id":
                doc["gates"][0]["id"] = {}
            elif label == "boolean gate index":
                doc["gates"][1]["index"] = True
            else:
                first_gate = sorted(doc["evaluators"])[0]
                doc["evaluators"][first_gate]["module"] = "evaluators/bad\x00.py"
            doc["gate_inventory_sha256"] = QS.gate_inventory_digest(doc["gates"])
            doc["binding_sha256"] = "0" * 64
            doc["binding_sha256"] = QS.full_binding_digest(doc)
            jwrite(fx["spec_path"], doc)
            fx["spec_sha256"] = digest(fx["spec_path"])
            fx["gate_inventory_sha256"] = doc["gate_inventory_sha256"]
            fx["gate_semantics_sha256"] = QS.gate_semantics_digest(doc["gates"])
            fx["full_binding_sha256"] = doc["binding_sha256"]
            package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
            result = call_g17(fx, os.path.join(td, "work"), package)

            cli_ok = True
            cli_detail = None
            if label in ("object gate id", "nul evaluator path"):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        rc = QV.main(cli_args(fx, package))
                        raised = None
                    except BaseException as e:
                        rc, raised = None, "%s: %s" % (type(e).__name__, e)
                emitted = stdout.getvalue() + stderr.getvalue()
                cli_ok = raised is None and isinstance(rc, int) and rc != 0 \
                    and "traceback" not in emitted.lower()
                cli_detail = {"return": rc, "raised": raised, "output": emitted[-180:]}
            check("T17-3m. MALFORMED SPEC: %-18s is a structured zero-child refusal" % label,
                  failed_before_child(result, package) and cli_ok,
                  {"api": result.get("failures", result.get("_exception")), "cli": cli_detail})


def test_r6_3_missing_unreadable_authority_inputs():
    cases = (
        ("missing specification", "spec_path", False),
        ("unreadable specification", "spec_path", True),
        ("missing authorization record", "authorization_path", False),
        ("unreadable authorization record", "authorization_path", True),
    )
    for index, (label, key, make_directory) in enumerate(cases):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "IO_%d" % index)
            target = fx[key]
            os.unlink(target)
            if make_directory:
                os.mkdir(target)

            direct_package = os.path.join(td, "direct", ENV.CANONICAL_ATTESTATION_DIR)
            direct = call_g17(fx, os.path.join(td, "direct_work"), direct_package)

            cli_package = os.path.abspath(
                os.path.join(td, "cli", ENV.CANONICAL_ATTESTATION_DIR))
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    rc = QV.main(cli_args(fx, cli_package))
                    raised = None
                except BaseException as e:
                    rc, raised = None, "%s: %s" % (type(e).__name__, e)
            emitted = stdout.getvalue() + stderr.getvalue()
            check("T17-3k. %-31s is a structured API/CLI zero-child refusal" % label,
                  failed_before_child(direct, direct_package)
                  and raised is None and isinstance(rc, int) and rc != 0
                  and "traceback" not in emitted.lower()
                  and not os.path.exists(cli_package),
                  {"api": direct.get("failures", direct.get("_exception")),
                   "cli_return": rc, "cli_raised": raised, "cli_output": emitted[-240:]})

    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "NUL_PATHS")
        direct_results, parser_results = {}, {}
        for index, (api_key, cli_flag) in enumerate((
                ("spec_path", "--spec="),
                ("authorization_path", "--authorization="),
                ("authorized_root", "--authorized-root="),
                ("expect_interpreter_path", "--interpreter="))):
            malformed = os.path.abspath(td) + "\x00malformed"
            package = os.path.join(td, "nul_%d" % index,
                                   ENV.CANONICAL_ATTESTATION_DIR)
            direct_results[api_key] = call_g17(
                fx, os.path.join(td, "nul_work_%d" % index), package,
                **{api_key: malformed})
            args = [cli_flag + malformed if a.startswith(cli_flag) else a
                    for a in cli_args(fx, package)]
            try:
                QV.parse_cli_args(args)
                parser_results[cli_flag] = "accepted"
            except QV.CLIRefusal as e:
                parser_results[cli_flag] = str(e)
            except BaseException as e:
                parser_results[cli_flag] = "RAW %s: %s" % (type(e).__name__, e)
        try:
            direct_results["envelope_path"] = QV.relocate_and_verify(
                None, os.path.join(td, "null_envelope_work"), **g17_kwargs(fx))
            direct_results["workspace"] = QV.relocate_and_verify(
                fx["envelope"], None, **g17_kwargs(fx))
        except BaseException as e:
            direct_results["positional_raw_exception"] = {
                "_exception": "%s: %s" % (type(e).__name__, e)}
        for label, bad_envelope in (("relative-envelope", "relative-envelope"),
                                    ("nul-envelope", fx["envelope"] + "\x00tail")):
            try:
                QV.parse_cli_args([
                    bad_envelope if a == fx["envelope"] else a
                    for a in cli_args(fx, os.path.join(
                        td, label, ENV.CANONICAL_ATTESTATION_DIR))])
                parser_results[label] = "accepted"
            except QV.CLIRefusal as e:
                parser_results[label] = str(e)
            except BaseException as e:
                parser_results[label] = "RAW %s: %s" % (type(e).__name__, e)
        check("T17-3k2. NUL in every mandatory external path is a deterministic API/CLI "
              "zero-child refusal, including both positional paths",
              all(failed_before_child(v) for v in direct_results.values())
              and all(("NUL-free" in v or "absolute path" in v)
                      and not v.startswith("RAW")
                      for v in parser_results.values()),
              {"api": {k: v.get("failures", v.get("_exception"))
                       for k, v in direct_results.items()}, "cli": parser_results})


def test_r6_3_malformed_bootstrap_and_numeric_inputs():
    bootstrap_results = {}
    for index, label in enumerate(("seal-list", "non-utf8-sums",
                                   "required-roles-integer", "oversized-size")):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "BOOTSTRAP_%d" % index)
            seal_path = os.path.join(fx["envelope"], ENV.SEAL_FILE)
            sums_path = os.path.join(fx["envelope"], ENV.SUMS_FILE)
            if label == "seal-list":
                jwrite(seal_path, [])
            else:
                seal = json.load(open(seal_path, encoding="utf-8"))
                if label == "non-utf8-sums":
                    wb(sums_path, b"\xff\xfe\n")
                    seal["sums_sha256"] = digest(sums_path)
                elif label == "required-roles-integer":
                    seal["required_roles"] = 7
                else:
                    lines = open(sums_path, encoding="utf-8").read().splitlines()
                    parts = lines[0].split("  ")
                    parts[1] = "9" * 5000
                    lines[0] = "  ".join(parts)
                    w(sums_path, "\n".join(lines) + "\n")
                    seal["sums_sha256"] = digest(sums_path)
                jwrite(seal_path, seal)
            fx["outer_seal_sha256"] = digest(seal_path)
            package = os.path.join(td, "direct", ENV.CANONICAL_ATTESTATION_DIR)
            direct = call_g17(fx, os.path.join(td, "work"), package)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    rc = QV.main(cli_args(fx, os.path.join(
                        td, "cli", ENV.CANONICAL_ATTESTATION_DIR)))
                    raised = None
                except BaseException as e:
                    rc, raised = None, "%s: %s" % (type(e).__name__, e)
            emitted = stdout.getvalue() + stderr.getvalue()
            bootstrap_results[label] = {
                "direct_ok": failed_before_child(direct, package),
                "direct": direct.get("failures", direct.get("_exception")),
                "cli_ok": raised is None and isinstance(rc, int) and rc != 0
                          and "traceback" not in emitted.lower(),
                "cli": {"return": rc, "raised": raised, "tail": emitted[-180:]},
            }

    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "HUGE_NUMBER")
        spec = copy.deepcopy(fx["spec_doc"])
        spec["rates"]["total"] = 10 ** 400
        jwrite(fx["spec_path"], spec)
        fx["spec_sha256"] = digest(fx["spec_path"])
        package = os.path.join(td, "qv", ENV.CANONICAL_ATTESTATION_DIR)
        direct = call_g17(fx, os.path.join(td, "qv_work"), package)
        staging = os.path.join(td, "runner_staging")
        try:
            runner = RUN.diagnostic_dry_run(
                fx["spec_path"], fx["spec_sha256"], fx["gate_inventory_sha256"],
                fx["full_binding_sha256"], fx["authorization_path"],
                fx["authorization_record_sha256"], fx["root"], staging,
                synthetic_preflight(), guard_requires_absent=False)
            runner_raised = None
        except BaseException as e:
            runner, runner_raised = None, "%s: %s" % (type(e).__name__, e)
        numeric_ok = (failed_before_child(direct, package)
                      and runner_raised is None and isinstance(runner, dict)
                      and runner.get("code") == "SPEC_REFUSED"
                      and runner.get("process_start_count") == 0
                      and not os.path.exists(staging))

    check("T17-3n. malformed sealed bootstrap bytes and enormous numeric fields are total, "
          "structured zero-child refusals through API, CLI and runner",
          all(v["direct_ok"] and v["cli_ok"] for v in bootstrap_results.values())
          and numeric_ok,
          {"bootstrap": bootstrap_results,
           "numeric": {"api": direct.get("failures", direct.get("_exception")),
                       "runner": runner, "raised": runner_raised}})


def test_r6_4_cli_parser_and_refusal():
    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "CLI")
        package = os.path.abspath(os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR))
        args = cli_args(fx, package)
        parsed = QV.parse_cli_args(args)
        expected = g17_kwargs(fx, package)
        check("T17-4. the real CLI parser produces the exact Python-API path and pin values",
              parsed.get("envelope_path") == fx["envelope"]
              and parsed.get("kwargs") == expected, parsed)

        os.makedirs(os.path.dirname(package), exist_ok=True)
        captured = []
        real_relocate = QV.relocate_and_verify

        def capture_relocation(*a, **kw):
            result = real_relocate(*a, **kw)
            captured.append(result)
            # main() owns a TemporaryDirectory. Adopt while that workspace still exists so the
            # recorder can re-derive the frozen child paths before main removes the directory.
            if result.get("child_record"):
                adopt(result)
            return result

        stdout, stderr = io.StringIO(), io.StringIO()
        QV.relocate_and_verify = capture_relocation
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc_full = QV.main(args)
        finally:
            QV.relocate_and_verify = real_relocate
        emitted_full = stdout.getvalue() + stderr.getvalue()
        check("T17-4a. fully pinned real main reaches the same harmless G17 path without traceback",
              rc_full == 0 and len(captured) == 1 and captured[0].get("g17_pass") is True
              and os.path.isdir(package) and "traceback" not in emitted_full.lower(),
              {"return": rc_full, "captured": len(captured),
               "failures": captured[0].get("failures", [])[:3] if captured else None,
               "output": emitted_full[-240:]})

        for label, mutated, needle in (
                ("missing pin", [a for a in args if not a.startswith("--interpreter-sha256=")],
                 "interpreter-sha256"),
                ("missing positional", [a for a in args if a != fx["envelope"]],
                 "exactly one envelope path"),
                ("malformed digest",
                 ["--spec-sha256=xyz" if a.startswith("--spec-sha256=") else a for a in args],
                 "sha256"),
                ("missing value",
                 ["--spec-sha256" if a.startswith("--spec-sha256=") else a for a in args],
                 "must use --name=value"),
                ("empty value",
                 ["--spec-sha256=" if a.startswith("--spec-sha256=") else a for a in args],
                 "empty value"),
                ("relative path",
                 ["relative" if a == fx["envelope"] else a for a in args],
                 "absolute path"),
                ("duplicate flag", args + ["--spec-sha256=" + fx["spec_sha256"]], "duplicate"),
                ("unknown flag", args + ["--caller-authorized=true"], "unknown"),
                ("extra positional", args + [os.path.join(td, "extra")],
                 "exactly one envelope path")):
            hit, msg = refusal(lambda m=mutated: QV.parse_cli_args(m), needle)
            check("T17-4b. MUTATION: %-16s is a deterministic parser refusal" % label,
                  hit and "traceback" not in msg.lower(), msg)

        missing_package = os.path.abspath(
            os.path.join(td, "missing", ENV.CANONICAL_ATTESTATION_DIR))
        minimal = [fx["envelope"], "--spec=" + fx["spec_path"],
                   "--attestation-package=" + missing_package]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = QV.main(minimal)
                raised = None
            except BaseException as e:
                rc, raised = None, "%s: %s" % (type(e).__name__, e)
        emitted = stdout.getvalue() + stderr.getvalue()
        check("T17-4c. main reports ordinary missing pins without a traceback, child or package",
              raised is None and isinstance(rc, int) and rc != 0
              and "traceback" not in emitted.lower() and not os.path.exists(missing_package),
              {"return": rc, "raised": raised, "output": emitted[-300:]})


def test_r6_5_complete_attestation_pins():
    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "ATTEST")
        out = os.path.join(td, "out")
        os.makedirs(out)
        package = os.path.join(out, ENV.CANONICAL_ATTESTATION_DIR)
        result = call_g17(fx, os.path.join(td, "work"), package)
        if result.get("child_record"):
            adopt(result)
        anchor = result.get("attestation_sha256")
        pins = attestation_kwargs(fx, anchor)
        failures = ENV.authenticate_canonical_attestation(package, fx["envelope"], **pins)
        check("T17-5. BASELINE: all authorization, runtime, envelope and retained pins authenticate",
              result.get("g17_pass") is True and failures == [], failures[:3])

        doc = json.load(open(os.path.join(package, ENV.CANONICAL_ATTESTATION_NAME),
                             encoding="utf-8"))
        expected_keys = {
            "authorized_spec_sha256", "gate_inventory_sha256", "gate_semantics_sha256",
            "full_binding_sha256", "authorization_record_sha256", "authorized_root",
            "interpreter_path", "interpreter_sha256", "outer_seal_sha256",
            "bundled_verifier_sha256", "bootstrap_closure_sha256",
            "envelope_typed_inventory_sha256",
        }
        check("T17-5b. the serialized external_pins inventory is complete and unambiguous",
              set(doc.get("external_pins") or {}) == expected_keys,
              sorted((doc.get("external_pins") or {}).keys()))

        mutation_names = [k for k in pins if k != "expect_attestation_sha256"]
        for key in mutation_names:
            wrong = dict(pins)
            wrong[key] = wrong_value(key, wrong[key], td)
            f = ENV.authenticate_canonical_attestation(package, fx["envelope"], **wrong)
            check("T17-5c. MUTATION: wrong %-39s fails authentication" % key,
                  bool(f), f[:2])
        for key in mutation_names:
            missing = dict(pins)
            missing.pop(key)
            f = ENV.authenticate_canonical_attestation(package, fx["envelope"], **missing)
            check("T17-5d. MUTATION: omitted %-37s fails authentication" % key,
                  bool(f), f[:2])
        nul_path_results = {}
        for key in ("expect_authorized_root", "expect_interpreter_path"):
            malformed = dict(pins)
            malformed[key] = os.path.abspath(td) + "\x00malformed"
            try:
                f = ENV.authenticate_canonical_attestation(
                    package, fx["envelope"], **malformed)
                raised = None
            except BaseException as e:
                f, raised = [], "%s: %s" % (type(e).__name__, e)
            nul_path_results[key] = {"failures": f, "raised": raised}
        check("T17-5d2. MUTATION: NUL in either external path pin is a deterministic "
              "authentication failure, never a path-library traceback",
              all(v["raised"] is None and has(v["failures"], "canonical absolute")
                  for v in nul_path_results.values()), nul_path_results)
        no_anchor = dict(pins)
        no_anchor.pop("expect_attestation_sha256")
        f = ENV.authenticate_canonical_attestation(package, fx["envelope"], **no_anchor)
        check("T17-5e. omitting the separately retained attestation digest remains an explicit fail",
              has(f, "retained") or has(f, "attestation"), f[:2])
        structural = ENV.inspect_canonical_attestation_structure(package)
        check("T17-5f. structure-only inspection remains diagnostic and never authenticated",
              structural.get("diagnostic_only") is True
              and structural.get("authenticated") is False,
              structural)
        inner = os.path.join(package, ENV.CANONICAL_ATTESTATION_NAME)
        side = os.path.join(package, ENV.CANONICAL_ATTESTATION_SIDECAR)
        original_inner = open(inner, "rb").read()
        original_side = open(side, "rb").read()
        malformed_results = {}
        wb(side, b"\xff\xfe\n")
        try:
            malformed_results["non_utf8_sidecar"] = {
                "structure": ENV.inspect_canonical_attestation_structure(package),
                "authenticate": ENV.authenticate_canonical_attestation(
                    package, fx["envelope"], **pins),
                "raised": None,
            }
        except BaseException as e:
            malformed_results["non_utf8_sidecar"] = {
                "raised": "%s: %s" % (type(e).__name__, e)}
        wb(inner, b"[]\n")
        w(side, "%s  %s\n" % (digest(inner), ENV.CANONICAL_ATTESTATION_NAME))
        list_pins = attestation_kwargs(fx, digest(inner))
        try:
            malformed_results["list_document"] = {
                "structure": ENV.inspect_canonical_attestation_structure(package),
                "authenticate": ENV.authenticate_canonical_attestation(
                    package, fx["envelope"], **list_pins),
                "raised": None,
            }
        except BaseException as e:
            malformed_results["list_document"] = {
                "raised": "%s: %s" % (type(e).__name__, e)}
        wb(inner, original_inner)
        wb(side, original_side)
        check("T17-5f1. malformed canonical attestation bytes are structured failures, never "
              "reader tracebacks",
              all(v.get("raised") is None
                  and (v.get("structure") or {}).get("structural_failures")
                  and v.get("authenticate")
                  for v in malformed_results.values()), malformed_results)
        os.unlink(os.path.join(fx["envelope"], ENV.SEAL_FILE))
        try:
            missing_seal_failures = ENV.authenticate_canonical_attestation(
                package, fx["envelope"], **pins)
            missing_seal_exception = None
        except BaseException as e:
            missing_seal_failures = []
            missing_seal_exception = "%s: %s" % (type(e).__name__, e)
        check("T17-5f2. deleted source ENVELOPE_SEAL is an authentication failure, not traceback",
              missing_seal_exception is None and bool(missing_seal_failures)
              and has(missing_seal_failures, "seal"),
              {"exception": missing_seal_exception, "failures": missing_seal_failures[:3]})

    with tempfile.TemporaryDirectory() as td:
        fx = complete_fixture(td, "NOPUBLISH")
        package = os.path.join(td, "out", ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(os.path.dirname(package))
        result = call_g17(fx, os.path.join(td, "work"), package,
                          expect_authorization_record_sha256="0" * 64)
        leftovers = [p for p in os.listdir(os.path.dirname(package))
                     if p == ENV.CANONICAL_ATTESTATION_DIR or ".partial" in p]
        check("T17-5g. failed authorization/publication leaves no final or partial package",
              failed_before_child(result, package) and leftovers == [], leftovers)

    for label, preexisting in (("wrong package basename", False),
                               ("pre-existing package", True)):
        with tempfile.TemporaryDirectory() as td:
            fx = complete_fixture(td, "PUBLISH_" + label.replace(" ", "_").upper())
            out = os.path.join(td, "out")
            os.makedirs(out)
            package = os.path.join(out, ENV.CANONICAL_ATTESTATION_DIR
                                   if preexisting else "WRONG_PACKAGE_NAME")
            sentinel = None
            if preexisting:
                os.mkdir(package)
                sentinel = w(os.path.join(package, "preexisting.txt"), "do not replace\n")
            result = call_g17(fx, os.path.join(td, "work"), package)
            if result.get("child_record"):
                adopt(result)
            partials = [name for name in os.listdir(out) if ".partial" in name]
            package_state_ok = (not os.path.exists(package) if not preexisting else
                                open(sentinel, encoding="utf-8").read() == "do not replace\n")
            expected_failure = (
                failed_before_child(result, package, "canonical basename")
                if not preexisting else
                (not result.get("_exception") and result.get("passed") is False
                 and result.get("g17_pass") is False
                 and result.get("attestation_package") is None
                 and result.get("attestation_publication_error")))
            check("T17-5h. %-22s makes both relocation verdicts false without partial output"
                  % label,
                  expected_failure and partials == [] and package_state_ok,
                  {"passed": result.get("passed"), "g17": result.get("g17_pass"),
                   "error": result.get("attestation_publication_error"),
                   "partials": partials, "package_state_ok": package_state_ok})


def test_r6_6_strict_sidecar_schema():
    with tempfile.TemporaryDirectory() as td:
        a = harmless_observed_child(td, "SCHEMA")
        adopt(a["result"])
        record, base = a["record"], a["doc"]
        check("T17-6. BASELINE: the exact nested sidecar schema validates",
              sidecar_probe(record, base, "baseline") == [],
              sidecar_probe(record, base, "baseline_again")[:3])

        def mutate(field, fn):
            d = copy.deepcopy(base)
            fn(d[field])
            return sidecar_probe(record, d, "%s_%d" % (field, len(RESULTS)))

        for field in ("reads", "code_reads"):
            sample = {"path": os.path.realpath(a["input"]), "how":
                      ("builtins.open" if field == "reads" else "open_code"),
                      "sha256": digest(a["input"])}
            for label, change, needle in (
                    ("unknown key", lambda rows, s=sample: rows.append(dict(s, extra=True)),
                     "contain exactly"),
                    ("missing key", lambda rows, s=sample: rows.append(
                        {k: v for k, v in s.items() if k != "sha256"}), "contain exactly"),
                    ("unknown observation API", lambda rows, s=sample:
                        rows.append(dict(s, how="not.an.observation.api")), "unknown observation"),
                    ("relative path", lambda rows, s=sample: rows.append(dict(s, path="relative")),
                     "absolute"),
                    ("NUL path", lambda rows, s=sample: rows.append(
                        dict(s, path=s["path"] + "\x00tail")), "NUL byte"),
                    ("noncanonical path", lambda rows, s=sample: rows.__setitem__(
                        slice(None), [dict(s, path=os.path.join(
                            os.path.dirname(s["path"]), ".", os.path.basename(s["path"]))) ]),
                     "canonical lexical form"),
                    ("uppercase digest", lambda rows, s=sample: rows.append(
                        dict(s, sha256=s["sha256"].upper())), "lowercase"),
                    ("duplicate/case collision", lambda rows, s=sample:
                        rows.extend([dict(s), dict(s, path=s["path"].swapcase())]), "collid")):
                failures = mutate(field, change)
                check("T17-6b. MUTATION: %s %-24s is rejected" % (field, label),
                      has(failures, needle), failures[:3])

        metadata_sample = {"path": os.path.realpath(a["meta"]), "how": ["os.listdir"],
                           "kind": "directory", "entries": sorted(os.listdir(a["meta"])),
                           "entry_count": len(os.listdir(a["meta"])), "size": None}
        for missing in ("entries", "entry_count", "size"):
            failures = mutate("metadata", lambda rows, k=missing:
                              rows.append({x: y for x, y in metadata_sample.items() if x != k}))
            check("T17-6c. MUTATION: metadata missing %-11s is rejected" % missing,
                  has(failures, "contain exactly"), failures[:3])
        for label, change, needle in (
                ("unknown key", lambda rows: rows.append(dict(metadata_sample, extra=True)),
                 "contain exactly"),
                ("how has wrong type", lambda rows: rows.append(
                    dict(metadata_sample, how="os.listdir")), "how"),
                ("entries has wrong type", lambda rows: rows.append(
                    dict(metadata_sample, entries=tuple(metadata_sample["entries"]))),
                 "invalid entries"),
                ("entry_count is bool", lambda rows: rows.append(
                    dict(metadata_sample, entry_count=True)), "entry_count"),
                ("relative path", lambda rows: rows.append(dict(metadata_sample, path="relative")),
                 "absolute"),
                ("NUL path", lambda rows: rows.append(dict(
                    metadata_sample, path=metadata_sample["path"] + "\x00tail")), "NUL byte"),
                ("duplicate/case collision", lambda rows: rows.extend(
                    [dict(metadata_sample), dict(metadata_sample,
                                                 path=metadata_sample["path"].swapcase())]),
                 "collid"),
                ("file with directory values", lambda rows: rows.append(
                    dict(metadata_sample, kind="file", size=1)), "metadata"),
                ("file size is bool", lambda rows: rows.append(dict(
                    metadata_sample, kind="file", entries=None, entry_count=None, size=True)),
                 "nonnegative integer"),
                ("directory with size", lambda rows: rows.append(
                    dict(metadata_sample, size=1)), "metadata"),
                ("unreadable with values", lambda rows: rows.append(
                    dict(metadata_sample, kind="unreadable")), "metadata"),
                ("unknown kind", lambda rows: rows.append(dict(
                    metadata_sample, kind="socket", entries=None, entry_count=None, size=None)),
                 "kind")):
            failures = mutate("metadata", change)
            check("T17-6d. MUTATION: metadata %-26s is rejected" % label,
                  has(failures, needle), failures[:3])

        g = {"argv": [sys.executable, "-c", "pass"],
             "command_identity": RP.command_identity([sys.executable, "-c", "pass"])}
        for label, item, needle in (
                ("unknown key", dict(g, extra=True), "contain exactly"),
                ("missing key", {"argv": list(g["argv"])}, "contain exactly"),
                ("empty argv", dict(g, argv=[]), "non-empty"),
                ("wrong command identity", dict(g, command_identity="0" * 64),
                 "does not match")):
            failures = mutate("grandchildren", lambda rows, x=item: rows.append(x))
            check("T17-6e. MUTATION: grandchild %-22s is rejected" % label,
                  has(failures, needle), failures[:3])
        failures = mutate("grandchildren", lambda rows: rows.append(g))
        check("T17-6e2. a syntactically exact grandchild is still unobserved and rejected",
              has(failures, "grandchild"), failures[:3])


def test_r6_6_parent_rederivation_and_limits():
    with tempfile.TemporaryDirectory() as td:
        a = harmless_observed_child(td, "REDERIVE")
        adopt(a["result"])
        record, doc = a["record"], a["doc"]
        original_input = open(a["input"], "rb").read()
        original_code = open(a["code"], "rb").read()
        wb(a["input"], b"changed after the child")
        changed = sidecar_probe(record, doc, "changed_local_read")
        check("T17-6f. a changed project-local child read is re-derived and rejected",
              has(changed, "re-derived") or has(changed, "hashes to"), changed[:4])
        wb(a["input"], original_input)
        os.unlink(a["input"])
        deleted = sidecar_probe(record, doc, "deleted_local_read")
        check("T17-6g. a deleted project-local child read fails explicitly",
              has(deleted, "missing") or has(deleted, "deleted") or has(deleted, "unreadable"),
              deleted[:4])
        wb(a["input"], original_input)
        wb(a["code"], original_code + b"# changed after execution\n")
        code_changed = sidecar_probe(record, doc, "changed_local_code")
        check("T17-6g2. changed project-local child code is re-derived and rejected",
              has(code_changed, "code_reads") and has(code_changed, "re-derived"),
              code_changed[:4])
        wb(a["code"], original_code)
        w(os.path.join(a["meta"], "later.txt"), "later\n")
        meta_changed = sidecar_probe(record, doc, "changed_metadata")
        check("T17-6h. changed project-local metadata is re-derived and rejected",
              has(meta_changed, "metadata") or has(meta_changed, "entries"),
              meta_changed[:4])

    model = getattr(RP, "OBSERVATION_MODEL", "")
    limitations = inspect.getdoc(RP.run_observed) or ""
    check("T17-6i. the claim remains scoped to cooperative Python API observation",
          model == "python-api-observed"
          and ("not an operating-system tracer" in limitations.lower()
               or "hostile" in limitations.lower()),
          {"model": model, "limitations": limitations[:300]})


def test_r6_diagnostic_runner_untrusted_output():
    """Real harmless collector children; deliberately noncanonical because one exits invalidly."""
    programs = {
        "huge": RP.CHILD_SHIM_SOURCE + '''import json
print(json.dumps({"raw_records": 10 ** 400, "branch_observations": 1,
                  "collection_seconds": 0.01}))
''',
        "reserved": RP.CHILD_SHIM_SOURCE + '''import json
print(json.dumps({"raw_records": 1, "branch_observations": 1,
                  "collection_seconds": 0.01, "note": "series is valid"}))
''',
        "nonzero": RP.CHILD_SHIM_SOURCE + '''import sys
sys.stderr.write("series is valid\\n")
raise SystemExit(7)
''',
    }
    outcomes = {}
    for index, (label, program) in enumerate(programs.items()):
        with tempfile.TemporaryDirectory() as td:
            fx = authorized_fixture(td, "R17_RUNNER_%s" % label.upper(),
                                    collector_source=program)
            try:
                result = runner_sequence(fx, os.path.join(td, "staging"))
                raised = None
            except BaseException as e:
                result, raised = {}, "%s: %s" % (type(e).__name__, e)
            entry = adopt(result) if result.get("child_record") else None
            if label == "nonzero" and result.get("child_record"):
                RECORDER.note_diagnostic_child(
                    result["child_record"]["argv"],
                    "deliberate Round-17 runner refusal with a nonzero synthetic child")
            outcomes[label] = {"result": result, "raised": raised, "entry": entry}

    huge = outcomes["huge"]
    check("T17-R1. an enormous collector integer yields a structured post-launch refusal with "
          "its exact child retained and adopted",
          huge["raised"] is None
          and huge["result"].get("code") == "COLLECTOR_RESULT_REJECTED"
          and huge["result"].get("process_start_count") == 1
          and huge["entry"] is not None,
          {"raised": huge["raised"], "code": huge["result"].get("code")})
    reserved = outcomes["reserved"]
    check("T17-R2. reserved scientific prose in otherwise valid collector output cannot escape "
          "as an engineering result or raw exception",
          reserved["raised"] is None
          and reserved["result"].get("code") == "COLLECTOR_RESULT_REJECTED"
          and reserved["result"].get("process_start_count") == 1
          and reserved["entry"] is not None
          and "series is valid" not in str(reserved["result"].get("reason", "")).lower(),
          {"raised": reserved["raised"], "code": reserved["result"].get("code")})
    nonzero = outcomes["nonzero"]
    check("T17-R3. forbidden stderr from a nonzero collector is redacted without losing the "
          "real child record or pretending its invalid sidecar closed provenance",
          nonzero["raised"] is None
          and nonzero["result"].get("code") == "COLLECTOR_FAILED"
          and nonzero["result"].get("process_start_count") == 1
          and isinstance(nonzero["result"].get("child_record"), dict)
          and (nonzero["result"].get("detail") or {}).get("redacted") is True
          and nonzero["entry"] is not None
          and nonzero["entry"].get("child_closure") != RP.CHILD_OBSERVED,
          {"raised": nonzero["raised"], "code": nonzero["result"].get("code"),
           "detail": nonzero["result"].get("detail"),
           "closure": (nonzero["entry"] or {}).get("child_closure")})


def test_r6_diagnostic_actual_concurrent_input_drift():
    """A real invalid child belongs only in the explicit noncanonical diagnostic run."""
    with tempfile.TemporaryDirectory() as td:
        inp = wb(os.path.join(td, "bound.bin"), b"before")
        started = os.path.join(td, "started.txt")
        marker = os.path.join(td, "finished.txt")
        sidecar = os.path.join(td, "drift.provenance.json")
        executable = os.path.realpath(sys.executable)
        program = RP.CHILD_SHIM_SOURCE + (
            "f=open(%r,'rb'); f.read(); f.close()\n"
            "f=open(%r,'w'); f.write('started'); f.close()\n"
            "import time as _t; _t.sleep(0.8)\n"
            "f=open(%r,'w'); f.write('finished'); f.close()\n" % (inp, started, marker))
        argv = [executable, "-I", "-B", "-c", program]
        original = digest(inp)

        def change_while_alive():
            deadline = time.time() + 10
            while time.time() < deadline and not os.path.exists(started):
                time.sleep(0.01)
            if os.path.exists(started):
                wb(inp, b"changed while child alive")

        thread = threading.Thread(target=change_while_alive, daemon=True)
        thread.start()
        result = RP.run_observed(
            argv, executable=executable, expect_executable_sha256=digest(executable),
            cwd=td, root=td, expected_inputs={os.path.realpath(inp): original},
            sidecar_path=sidecar, env=dict(os.environ), timeout=30,
            declared_outputs=(started, marker))
        thread.join(10)
        entry = adopt(result)
        RECORDER.note_diagnostic_child(argv, "actual concurrent input-drift negative control")
        complete, reasons = RECORDER._closure_completeness()
        check("T17-D1. the child really ran while the bound input changed",
              os.path.exists(started) and os.path.exists(marker)
              and digest(inp) != original, (started, marker))
        record = result_record(result) or {}
        check("T17-D2. the production record reports drift and cannot claim execution proof",
              record.get("declared_inputs", {}).get(os.path.realpath(inp)) == original
              and record.get("inputs_after", {}).get(os.path.realpath(inp)) == digest(inp)
              and record.get("inputs_after", {}).get(os.path.realpath(inp)) != original
              and record.get("process_proof_ok") is False
              and record.get("execution_proof_ok") is False
              and has(record.get("sidecar_failures"), "changed while"),
              {"before": record.get("declared_inputs", {}).get(os.path.realpath(inp)),
               "after": record.get("inputs_after", {}).get(os.path.realpath(inp)),
               "sidecar_failures": record.get("sidecar_failures")})
        check("T17-D3. diagnostic disclosure does not restore complete closure",
              entry.get("diagnostic_reason") and not complete and has(reasons, "changed while"),
              reasons)


def test_r6_diagnostic_unadopted_real_child():
    """Dropping run_observed's return must leave the active recorder truthfully red."""
    with tempfile.TemporaryDirectory() as td:
        child = harmless_observed_child(td, "UNADOPTED", b"unadopted-real-child")
        token = child["record"].get("record_token")
        pending = [d for d in RECORDER.declared_subprocesses
                   if d.get("record_token") == token]
        complete, reasons = RECORDER._closure_completeness()
        check("T17-U1. the deliberately unadopted child really ran and was synchronously reaped",
              os.path.isfile(child["marker"])
              and child["record"].get("process_started") is True
              and child["record"].get("process_returned") is True
              and child["record"].get("exit") == 0,
              {"marker": child["marker"], "pid": child["record"].get("pid")})
        check("T17-U2. run_observed automatically leaves one pending ledger entry on every "
              "recorder active at launch even when its return value is dropped",
              len(pending) == 1 and pending[0].get("adoption_pending") is True
              and pending[0].get("child_closure") == RP.CHILD_NOT_OBSERVED,
              pending)
        check("T17-U3. the pending real child makes closure incomplete with an explicit adoption "
              "reason instead of disappearing from the report",
              not complete and has(reasons, "never adopted"), reasons)


def test_r6_diagnostic_post_popen_exception():
    """A failure after real Popen must remain in the active recorder's ledger."""
    with tempfile.TemporaryDirectory() as td:
        executable = os.path.realpath(sys.executable)
        sidecar = os.path.join(td, "aborted.provenance.json")
        argv = [executable, "-I", "-B", "-c",
                RP.CHILD_SHIM_SOURCE + "import time as _t; _t.sleep(10)\n"]
        before = len(RECORDER.declared_subprocesses)
        try:
            RP.run_observed(
                argv, executable=executable, expect_executable_sha256=digest(executable),
                cwd=td, root=td, expected_inputs={}, sidecar_path=sidecar,
                env=dict(os.environ), timeout="not-a-number")
            raised = None
        except BaseException as e:
            raised = "%s: %s" % (type(e).__name__, e)
        entries = RECORDER.declared_subprocesses[before:]
        entry = entries[0] if len(entries) == 1 else {}
        complete, reasons = RECORDER._closure_completeness()
        check("T17-A1. the induced post-Popen communicate failure is surfaced to the caller",
              raised is not None and "TypeError" in raised, raised)
        check("T17-A2. the real child is killed/reaped and remains as one permanently aborted "
              "non-adoptable ledger entry",
              len(entries) == 1 and entry.get("process_started") is True
              and entry.get("process_returned") is True
              and isinstance(entry.get("pid"), int) and entry.get("pid") > 0
              and entry.get("exit") is not None
              and entry.get("observation_aborted") is True
              and entry.get("observation_pending") is False
              and RP._ADOPTABLE.get(entry.get("record_token")) is None,
              entry)
        check("T17-A3. catching that internal failure cannot produce a clean provenance report",
              not complete and has(reasons, "run_observed aborted"), reasons)


def main():
    if DIAGNOSTIC_MODE not in (("",) + tuple(sorted(DIAGNOSTIC_TESTS))):
        print("unknown --diagnostic mode %r" % DIAGNOSTIC_MODE)
        return 2
    tests = DIAGNOSTIC_TESTS[DIAGNOSTIC_MODE] if DIAGNOSTIC_MODE else ORDINARY_TESTS
    expected_functional = (DIAGNOSTIC_FUNCTIONAL_CHECK_COUNTS[DIAGNOSTIC_MODE]
                           if DIAGNOSTIC_MODE else ORDINARY_FUNCTIONAL_CHECK_COUNT)
    for name in tests:
        print("[%s]" % name)
        globals()[name]()
    functional = len(RESULTS)
    check("T17-INV. functional check count equals the pinned figure",
          functional == expected_functional,
          "%d functional checks, pinned at %d" % (functional, expected_functional))
    RECORDER.pin_test_inventory(tests, expected_functional, META_CHECK_COUNT)
    RECORDER.finish(allow_incomplete_diagnostic=bool(DIAGNOSTIC_MODE))
    failed = [r for r in RESULTS if not r["passed"]]
    canonical = bool(ARG.get("--commit")) and not DIAGNOSTIC_MODE
    doc = RECORDER.report(
        "round17" if not DIAGNOSTIC_MODE else "round17_diagnostic_" + DIAGNOSTIC_MODE,
        sys.argv, tested_commit=ARG.get("--commit"), canonical=canonical,
        actual_test_ids=list(tests), actual_check_count=len(RESULTS),
        allow_invalid_diagnostic=bool(DIAGNOSTIC_MODE),
        extra={
            "label": ("ROUND 17 -- sixth corrective audit behavioural closures"
                      if not DIAGNOSTIC_MODE else
                      "ROUND 17 -- explicit noncanonical %s negative control"
                      % DIAGNOSTIC_MODE),
            "non_evidence": True, "live": False, "authorises_no_live_run": True,
            "diagnostic_mode": DIAGNOSTIC_MODE or None,
            "expected_provenance_incomplete": bool(DIAGNOSTIC_MODE),
            "results": RESULTS, "total": len(RESULTS),
            "passed": len(RESULTS) - len(failed),
            "functional_check_count": functional, "meta_check_count": META_CHECK_COUNT,
        })
    if OUT:
        os.makedirs(os.path.dirname(os.path.abspath(OUT)) or ".", exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
    print("\nROUND 17%s: %d/%d passed%s" %
          ((" " + DIAGNOSTIC_MODE.upper()) if DIAGNOSTIC_MODE else "",
           len(RESULTS) - len(failed), len(RESULTS), (" -> " + OUT) if OUT else ""))
    print("provenance_ok: %s; closure_complete: %s" %
          (doc.get("provenance_ok"), doc.get("api_observed_closure_complete")))
    if not doc.get("provenance_ok"):
        for problem in doc.get("provenance_problems", []):
            print("  provenance problem:", problem)
    if not doc.get("api_observed_closure_complete"):
        for reason in doc.get("closure_incomplete_reasons", []):
            print("  closure problem:", reason)
    if DIAGNOSTIC_MODE:
        honest = (doc.get("provenance_ok") is False
                  and doc.get("api_observed_closure_complete") is False)
        return 0 if not failed and honest else 1
    return 0 if not failed and doc.get("provenance_ok") else 1


if __name__ == "__main__":
    sys.exit(main())
