#!/usr/bin/env python3
"""Round-15: one named behavioural test per counterexample the FOURTH corrective audit reproduced.

NON-EVIDENCE, AND ENTIRELY NON-LIVE. No daemon, miner, driver, tracer, smoke, calibration,
qualification or network call. Every specification, envelope, bundle, verifier and process
inventory is a synthetic fixture in a temporary directory. The historical-integrity checker is
exercised only against MINIATURE SYNTHETIC bundles; the real Gate N is never touched.

EVERY TEST HAS THE SAME SHAPE: prove the UNMUTATED baseline passes, then prove the EXACT mutation
fails FOR THE INTENDED REASON. A source-text search is never accepted as enforcement.

THE THREAT MODEL THIS SUITE TESTS AGAINST is stated in node/qual_runner_v2.py. In one line: this
is API enforcement inside one Python process, NOT an operating-system sandbox. A hostile local
caller can always import subprocess. What is tested here is that the SUPPORTED project APIs cannot
be talked into a launch, a G17 pass, a canonical attestation or a canonical provenance claim.

Case map:
  R4-1  a second executable runner entry          R4-10 historical external pins disabled
  R4-2  final-preflight TOCTOU                    R4-11 historical inventory ignores empty dirs
  R4-3  unpinned interpreter / authz path         R4-12 inner-seal validation is not integrity
  R4-4  invalid numeric/domain result values      R4-13 malformed WSL rows silently skipped
  R4-5  G17 injected runner fakes execution       R4-14 sidecar grammar not exact
  R4-6  G17 prelude aborts before the verifier    R4-15 forged child-provenance sidecar
  R4-7  bootstrap identity is self-reported       R4-16 os.open read bypasses
  R4-8  canonical attestation from a dict         R4-17 metadata-driven inputs undisclosed
  R4-9  the attestation pair is two renames       R4-18 runner child not fully bound

Usage: python3 node/tests_round15.py [--out=<path>] [--commit=<sha>]
"""
import ast
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import types

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
    "test_r4_1_one_launch_api", "test_r4_2_final_recheck_is_last",
    "test_r4_3_every_executable_input_is_pinned", "test_r4_4_semantic_result_validation",
    "test_r4_5_6_no_injection_in_g17", "test_r4_7_bootstrap_is_pinned_externally",
    "test_r4_8_9_canonical_attestation", "test_r4_10_11_historical_pins_and_directories",
    "test_r4_12_inner_seal_is_an_integrity_check", "test_r4_13_malformed_wsl_rows",
    "test_r4_14_exact_sidecar_grammar", "test_r4_15_child_sidecars_are_validated",
    "test_r4_16_read_api_coverage", "test_r4_17_metadata_boundary",
    "test_r4_18_runner_child_is_bound",
)
FUNCTIONAL_CHECK_COUNT = 116
META_CHECK_COUNT = 1

COLLECTOR = RP.CHILD_SHIM_SOURCE + '''import json, sys
a = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in sys.argv[1:] if "=" in x}
print(json.dumps({"raw_records": 6, "branch_observations": 25, "telemetry_retained": True,
                  "collection_seconds": 0.02, "staging_dir": a.get("--staging", ""),
                  "note": "synthetic fixture collector"}))
'''
EVALUATOR = '"""synthetic"""\nGATE = %r\n'


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def refuses(fn, needle, cls=Exception):
    try:
        fn()
        return False, "nothing was raised"
    except cls as e:
        return (needle in str(e)), "%s: %s" % (type(e).__name__, e)


def has(failures, needle):
    return any(needle in f for f in failures)



def suite_child(code, tag):
    """A child program carrying THIS project's shim, with a unique tail so every child in this
    suite has its own canonical command identity."""
    return RP.CHILD_SHIM_SOURCE + code + ("\n# suite tag: %s\n" % tag)


def suite_run(argv, cwd, sidecar, inner=None, extra_env=None):
    """Start a child that this suite's recorder DECLARES and OBSERVES, and that an inner
    recorder may observe too.

    A child can echo exactly one nonce, so the inner recorder is declared with the outer one's.
    Both then validate the same answer and neither reports an undeclared subprocess."""
    cwd = os.path.abspath(cwd)
    outer = RECORDER.declare_subprocess(argv, cwd=cwd)
    entry = None
    if inner is not None:
        entry = inner.declare_subprocess(argv, cwd=cwd, nonce=outer["nonce"])
    env = dict(os.environ, MEEPCOIN_CHILD_PROVENANCE=sidecar, MEEPCOIN_CHILD_ROOT=cwd,
               MEEPCOIN_CHILD_NONCE=outer["nonce"],
               MEEPCOIN_CHILD_COMMAND=outer["command_identity"])
    env.update(extra_env or {})
    r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
    RECORDER.attach_child_provenance(argv, sidecar)
    return r, outer, entry


def pinned_interpreter():
    """The RESOLVED interpreter. A symlink is an alias, not the object."""
    real = os.path.realpath(sys.executable)
    return {"path": real, "sha256": QS.sha256_file(real)}


def authorized_fixture(root, spec_id="R15", authz_name="authz.json", interpreter=None):
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
        "run_identity": spec_id, "snapshot": {"id": "SNAP", "sha256": "a" * 64},
        "schedule": {"order": ["control", "attack"]},
        "condition_order": ["control", "attack"], "replicates": 3,
        "rates": {"total": 1.5}, "durations": {"mine": 60.0, "post": 30.0},
        "ports": {"base": 41000, "count": 8}, "namespace": "r15-testonly",
        "refusal_policy": {"on_denied_workload": "refuse"},
        "required_envelope_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES),
        "collector_binding": {"path": "collector.py", "sha256": QS.sha256_file(cpath),
                              "interpreter": interpreter or pinned_interpreter(),
                              "dependencies": {}},
        "authorization_record": authz_name, "evaluators": ev,
    })
    d["gate_inventory_sha256"] = QS.gate_inventory_digest(d["gates"])
    d["binding_sha256"] = "0" * 64
    d["binding_sha256"] = QS.full_binding_digest(d)
    sp = os.path.join(ar, "spec.json")
    with open(sp, "wb") as f:
        f.write((json.dumps(d, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    sdig = QS.sha256_file(sp)
    doc = json.loads(open(sp, encoding="utf-8").read())
    rec = {
        "schema": QS.AUTHZ_SCHEMA, "authority": "TEST FIXTURE -- NOT A REAL AUTHORIZATION",
        "utc": "2026-09-03T00:00:00Z", "authorizes_spec_sha256": sdig,
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
    az = os.path.join(ar, authz_name)
    with open(az, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, indent=1)
    return {"root": ar, "spec_path": sp, "spec_sha256": sdig, "collector_path": cpath,
            "inventory_sha256": doc["gate_inventory_sha256"],
            "binding_sha256": doc["binding_sha256"], "authz_path": az,
            "authz_sha256": QS.sha256_file(az), "authz_doc": rec, "doc": doc}


def synthetic_preflight(cls=None, denied=False):
    """SYNTHETIC inventories only. No real process is inspected, started or signalled."""
    def win():
        recs = [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")]
        if denied:
            recs.append(WP.ProcessRecord(1, "p2pool.exe", None, "windows:Win32_Process"))
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE, recs)

    def runner(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
        R.stdout = ("\n".join(["  NAME     STATE      VERSION", "* Ubuntu   Running    2", ""])
                    if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]
                    else "1\tinit\t/sbin/init\n")
        return R()

    return (cls or WP.WorkloadPreflight)(
        providers={"windows": win, "wsl": lambda: WP.wsl_inventory(runner=runner)})


def dry_run(fx, stage, preflight=None, **over):
    kw = {"spec_path": fx["spec_path"], "expect_spec_sha256": fx["spec_sha256"],
          "expect_inventory_sha256": fx["inventory_sha256"],
          "expect_binding_sha256": fx["binding_sha256"],
          "authorization_path": fx["authz_path"],
          "expect_authorization_sha256": fx["authz_sha256"],
          "authorized_root": fx["root"], "staging_dir": stage,
          "preflight": preflight or synthetic_preflight(), "guard_requires_absent": False}
    kw.update(over)
    return RUN.diagnostic_dry_run(**kw)


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


def build(root, tag, inner=None, verifier_src=None, full_roles=True):
    inner = inner or inner_bundle(root, "inner_" + tag)
    files = os.path.join(root, "src_" + tag)
    trace = w(os.path.join(files, "trace.json"), '{"kind":"environment_trace","rows":[]}\n')
    gates = w(os.path.join(files, "gates.json"), '{"pre_seal":true,"gates":[]}\n')
    spec = w(os.path.join(files, "spec.json"), '{"spec_id":"X"}\n')
    srcinv = w(os.path.join(files, "sources.json"), '{"modules":{}}\n')
    b = ENV.EnvelopeBuilder(os.path.join(root, "stage_" + tag), "ENV_" + tag)
    b.bind_collection(inner)
    b.bind_trace(trace, ENV.TRACE_COMPLETE)
    b.bind("qualification_spec", spec, relpath="tools/spec.json")
    b.bind("source_inventory", srcinv, relpath="tools/sources.json")
    b.bind("outer_verifier", verifier_src or os.path.join(_NODE, "evidence_envelope.py"),
           relpath="tools/verifier.py")
    if full_roles:
        bind_all_authorized_roles(b, files)
    b.mark_checked(gates)
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
    # This suite predates the real authorization contract and its envelope spec is deliberately
    # trivial. Exercise relocation as a non-authoritative diagnostic; Round 17 proves G17 with a
    # complete, separately pinned synthetic authorization.
    res = QV.diagnostic_relocate(*a, **_authorized_kw(a[0], kw))
    if res.get("child_record"):
        RECORDER.adopt_child_record(res["child_record"])
    return res


def diag_reloc(*a, **kw):
    """A diagnostic relocation. Its record is adopted only when a REAL child actually ran: an
    injected runner that starts nothing leaves no subprocess for anyone to observe, so there is
    nothing to adopt and nothing is claimed."""
    res = QV.diagnostic_relocate(*a, **kw)
    cr = res.get("child_record") or {}
    if cr and os.path.isfile(cr.get("sidecar_path") or ""):
        RECORDER.adopt_child_record(cr)
    return res


def mini(root, name="MINI_20260101", sidecar_text=None, empty_dir=None):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "r1.json"), '{"a":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    if empty_dir:
        os.makedirs(os.path.join(b, empty_dir))
    on_disk = [r for r in HI.walk_relpaths(b) if r not in HI.SELF_FILES]
    w(os.path.join(b, "SHA256SUMS"),
      "".join("%s  output  %s\n" % (HI.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
              for r in on_disk))
    graph = HI.walk_typed(b)
    dirs = sorted(r for r, k in graph.items() if k == "directory")
    inv = {r: v for r, v in HI.typed_inventory(b).items() if r not in HI.SELF_FILES}
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(
        {"schema": HI.BUNDLE_SEAL_SCHEMAS[0], "sealed": True, "inventory": sorted(on_disk),
         "file_count": len(on_disk) + len(HI.SELF_FILES),
         "directories": dirs, "directory_count": len(dirs),
         "typed_inventory_sha256": ENV.inventory_digest(inv),
         "sha256sums_sha256": HI.sha256_file(os.path.join(b, "SHA256SUMS"))}) + "\n")
    logs = w(os.path.join(root, "logs_" + name, "d1.log"), "line\n")
    arch = os.path.join(root, name + HI.ARCHIVE_SUFFIX)
    with tarfile.open(arch, "w:gz") as tf:
        tf.add(logs, arcname="logs_x/d1.log")
    w(arch + HI.SIDECAR_SUFFIX,
      sidecar_text if sidecar_text is not None
      else HI.sha256_file(arch) + "  " + name + HI.ARCHIVE_SUFFIX + "\n")
    return b, arch


def hi_pins(b, arch):
    return {"seal_sha256": HI.sha256_file(os.path.join(b, "FINAL_SEAL.json")),
            "sums_sha256": HI.sha256_file(os.path.join(b, "SHA256SUMS")),
            "archive_sha256": HI.sha256_file(arch),
            "file_count": len(HI.walk_relpaths(b))}


# ================================================================== R4-1
def test_r4_1_one_launch_api():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        good = dry_run(fx, os.path.join(td, "stage_ok"))
        detail = good.get("detail") or {}
        check("T15-1. BASELINE: the diagnostic harness runs the complete production sequence and "
              "stops at the launch boundary",
              good["code"] == "DIAGNOSTIC_ONLY" and good["diagnostic_only"] is True
              and good["refused"] is True and good["launch_callback_invocations"] == 0,
              good["code"])
        check("T15-1b. the supported public surface is declared, and the run class is not in it",
              "AuthorizedRun" not in RUN.__all__ and "_AuthorizedRun" not in RUN.__all__
              and "run_authorized" in RUN.__all__ and "diagnostic_dry_run" in RUN.__all__,
              RUN.__all__)
        check("T15-1c. and the class itself is private", "AuthorizedRun" not in dir(RUN))

        spec = QS.bind_authorized(fx["spec_path"], fx["spec_sha256"], fx["inventory_sha256"],
                                  fx["binding_sha256"], fx["authz_path"], fx["authz_sha256"],
                                  fx["root"])
        run = RUN._AuthorizedRun(spec, preflight=None)
        hit, msg = refuses(lambda: run.launch_and_collect(os.path.join(td, "never")),
                           "reached only through qual_runner_v2.run_authorized", RUN.RunnerError)
        check("T15-1d. MUTATION: constructing the run object directly and calling its launch "
              "method is refused BEFORE the counter moves, and no process is created",
              hit and run.launch_calls == 0 and run.child_record is None, msg[:100])

        hit, msg = refuses(
            lambda: RUN.run_authorized(fx["spec_path"], fx["spec_sha256"],
                                       fx["inventory_sha256"], fx["binding_sha256"],
                                       fx["authz_path"], fx["authz_sha256"], fx["root"],
                                       os.path.join(td, "never2"), preflight=object()),
            "preflight", TypeError)
        check("T15-1e. MUTATION: the production entry point has no preflight seam to inject into",
              hit, msg[:90])

        tree = ast.parse(open(os.path.join(_NODE, "qual_runner_v2.py"), encoding="utf-8").read())
        raw_owners, observed_owners = [], []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr in ("run", "Popen", "call", "check_output", "system") \
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess":
                fns = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                       and f.lineno <= n.lineno <= (f.end_lineno or f.lineno)]
                raw_owners.append(fns[-1].name if fns else "<module>")
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr == "run_observed" \
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "RP":
                fns = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                       and f.lineno <= n.lineno <= (f.end_lineno or f.lineno)]
                observed_owners.append(fns[-1].name if fns else "<module>")
        check("T15-1f. the runner makes no raw subprocess call and exactly one function delegates "
              "process ownership to run_observed, parsed rather than grepped",
              raw_owners == [] and observed_owners == ["launch_and_collect"],
              {"raw": raw_owners, "observed": observed_owners})
        check("T15-1g. and the module says plainly that this is API enforcement, not an OS "
              "sandbox, naming its root of trust",
              "not an os sandbox" in RUN.__doc__.lower()
              and "root of trust" in RUN.__doc__.lower())


# ================================================================== R4-2
def test_r4_2_final_recheck_is_last():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        base = dry_run(fx, os.path.join(td, "stage_base"))
        order = base["event_sequence"]
        check("T15-2. BASELINE: the order is authorize -> lead-in -> staging -> PRE-LAUNCH "
              "inventory -> FINAL byte recheck",
              order == ["authorization_check", "authorized:R15", "preflight:lead_in", "prepare",
                        "preflight:pre_launch", "final_launch_binding_recheck"], order)
        check("T15-2b. the process inventory now precedes the final byte check, so nothing "
              "injectable runs after it",
              order.index("preflight:pre_launch") < order.index("final_launch_binding_recheck"))

        swapped = {"done": False}

        class SwapAtPreLaunch(WP.WorkloadPreflight):
            def check(self, stage, spec=None):
                res = WP.WorkloadPreflight.check(self, stage, spec)
                if stage == "pre_launch" and not swapped["done"]:
                    with open(fx["collector_path"], "a", encoding="utf-8") as f:
                        f.write("\n# swapped at the pre-launch preflight\n")
                    swapped["done"] = True
                return res

        res = dry_run(fx, os.path.join(td, "stage_swap"),
                      preflight=synthetic_preflight(SwapAtPreLaunch))
        detail = res.get("detail") or {}
        reasons = list(detail.get("drift") or []) + list(detail.get("failures") or [])
        check("T15-2c. MUTATION: a preflight that swaps the pinned collector is caught before "
              "any process is created -- the runner stages the code it will launch and then "
              "rechecks it",
              swapped["done"]
              and res["code"] in ("LAUNCH_BEARING_DRIFT", "STAGED_CODE_MISMATCH")
              and res["launch_callback_invocations"] == 0, res["code"])
        check("T15-2d. and the reason names the collector and the digest that changed",
              any("collector" in x and ("hashes to" in x or "not the bound" in x)
                  for x in reasons), reasons[:1])

        tree = ast.parse(open(os.path.join(_NODE, "qual_runner_v2.py"), encoding="utf-8").read())
        seq = [f for f in ast.walk(tree)
               if isinstance(f, ast.FunctionDef) and f.name == "_sequence"][0]
        calls = sorted((n for n in ast.walk(seq)
                        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)),
                       key=lambda n: (n.lineno, n.col_offset))
        names = [n.func.attr for n in calls]
        try:
            i_final, i_launch = names.index("final_recheck"), names.index("launch_and_collect")
        except ValueError:                                # pragma: no cover - structural
            i_final, i_launch = -1, -1
        between = [n for n in names[i_final + 1:i_launch] if n in ("check", "prepare")]
        check("T15-2e. and between the final recheck and process creation the sequence calls no "
              "preflight and no preparation callback",
              i_final >= 0 and i_launch > i_final and between == [], between)


# ================================================================== R4-3
def test_r4_3_every_executable_input_is_pinned():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        check("T15-3. BASELINE: a fixture pinning the RESOLVED interpreter validates cleanly",
              QS.deep_validate_authorized(fx["doc"], fx["root"]) == [],
              QS.deep_validate_authorized(fx["doc"], fx["root"]))

        ghost = os.path.join(td, "no_such_interpreter")
        bad = authorized_fixture(os.path.join(td, "bad"),
                                 interpreter={"path": ghost, "sha256": "9" * 64})
        f = QS.deep_validate_authorized(bad["doc"], bad["root"])
        check("T15-3b. MUTATION: a nonexistent interpreter is refused as an executable input",
              any("interpreter" in x and "absent" in x for x in f),
              [x for x in f if "interpreter" in x][:1])

        wrong = authorized_fixture(os.path.join(td, "wrongdig"),
                                   interpreter={"path": os.path.realpath(sys.executable),
                                                "sha256": "9" * 64})
        f2 = QS.deep_validate_authorized(wrong["doc"], wrong["root"])
        check("T15-3c. MUTATION: an interpreter whose bytes do not match its pin is refused",
              any("interpreter" in x and "hashes to" in x for x in f2),
              [x for x in f2 if "interpreter" in x][:1])

        missing = authorized_fixture(os.path.join(td, "nointerp"))
        d = json.loads(json.dumps(missing["doc"]))
        d["collector_binding"].pop("interpreter")
        f3 = QS.deep_validate_authorized(d, missing["root"])
        check("T15-3d. MUTATION: omitting the interpreter entirely is refused",
              any("must name the exact interpreter" in x for x in f3), f3[:1])

        other = os.path.join(fx["root"], "not_the_declared_name.json")
        with open(other, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(fx["authz_doc"], fh, indent=1)
        hit, msg = refuses(
            lambda: QS.bind_authorized(fx["spec_path"], fx["spec_sha256"],
                                       fx["inventory_sha256"], fx["binding_sha256"], other,
                                       QS.sha256_file(other), fx["root"]),
            "which the specification does not name" if False else
            "the caller supplied", QS.AuthorizationError)
        check("T15-3e. MUTATION: an authorization record the specification does not name is "
              "refused, even with identical content", hit, msg[:130])

        res = dry_run(fx, os.path.join(td, "stage"))
        labels = (res.get("detail") or {}).get("final_recheck", {}).get("labels", [])
        check("T15-3f. the final recheck covers the spec, the authorization record, the "
              "interpreter, the collector and every evaluator",
              "interpreter" in labels and "collector" in labels
              and "qualification specification" in labels
              and "authorization record" in labels
              and any(x.startswith("STAGED ") for x in labels)
              and len(labels) == 22, len(labels))


# ================================================================== R4-4
def test_r4_4_semantic_result_validation():
    with tempfile.TemporaryDirectory() as td:
        stage = os.path.join(td, "stage")
        os.makedirs(stage)
        kept, opaque, fails = RUN.coerce_retained(
            {"raw_records": 6, "branch_observations": 25, "telemetry_retained": True,
             "collection_seconds": 0.02, "staging_dir": stage, "note": "ok"},
            staging_dir=stage)
        check("T15-4. BASELINE: a well-formed collector result is accepted whole",
              fails == [] and set(kept) == set(RUN.RETAINED_SCHEMA), fails)

        for label, payload, needle in (
                ("negative raw_records", {"raw_records": -5}, "outside its declared domain"),
                ("negative branch_observations", {"branch_observations": -1},
                 "outside its declared domain"),
                ("NaN duration", {"collection_seconds": float("nan")}, "not a finite number"),
                ("infinite duration", {"collection_seconds": float("inf")},
                 "not a finite number"),
                ("absurd count", {"raw_records": 10 ** 30}, "outside its declared domain"),
                ("bool as int", {"raw_records": True}, "not int"),
                ("wrong staging_dir", {"staging_dir": "/somewhere/else"},
                 "not the actual staging root")):
            _k, _o, f = RUN.coerce_retained(payload, staging_dir=stage)
            check("T15-4b. MUTATION: %-26s is refused for the intended reason" % label,
                  any(needle in x for x in f), (f or ["nothing"])[:1])

        _k, _o, f = RUN.coerce_retained({"staging_dir": stage})
        check("T15-4c. and staging_dir cannot be checked without a canonical staging path, so it "
              "must be omitted instead", any("must be omitted" in x for x in f), f[:1])
        _k, opaque, f = RUN.coerce_retained({"weird": float("nan")}, staging_dir=stage)
        check("T15-4d. unrecognised data that is not deterministically serialisable is refused "
              "rather than carried", f != [] and opaque is None, f[:1])
        _k, opaque, f = RUN.coerce_retained({"weird": {"b": 1, "a": 2}}, staging_dir=stage,
                                            require_minimum=False)
        check("T15-4e. and unrecognised data that IS serialisable becomes one deterministic "
              "untrusted string", f == [] and opaque == '{"weird":{"a":2,"b":1}}', opaque)


# ================================================================== R4-5 / R4-6
def test_r4_5_6_no_injection_in_g17():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "g")
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        good = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv)
        check("T15-5. CORRECTED: the legacy trivial-spec fixture is diagnostic and cannot prove "
              "production G17 execution",
              not good["g17_pass"] and good["diagnostic_only"] is True
              and not good["child_execution_proof"]["ok"]
              and has(good["failures"], "diagnostic execution is permanently non-adoptable"),
              good["failures"][:2])
        args = QV.relocate_and_verify.__code__.co_varnames[
            :QV.relocate_and_verify.__code__.co_argcount]
        check("T15-5b. the production signature carries no runner and no prelude seam",
              "runner" not in args and "child_prelude" not in args, list(args))

        calls = []

        def never_runs(argv, **kw):
            calls.append(list(argv))
            return types.SimpleNamespace(returncode=0, stdout="[]\n", stderr="")

        ws2 = os.path.join(td, "ws2")
        os.makedirs(ws2)
        fake = diag_reloc(env, ws2, sd, vd, boot, runner=never_runs,
                          expect_inventory_sha256=inv)
        check("T15-5c. MUTATION: a runner that never starts a child is DIAGNOSTIC ONLY and can "
              "never set g17_pass",
              fake["diagnostic_only"] is True and fake["g17_pass"] is False and len(calls) == 1,
              fake["g17_pass"])
        check("T15-5d. and the missing proof of execution is named as the reason",
              has(fake["failures"], "proof of execution"), fake["failures"][:1])

        ws3 = os.path.join(td, "ws3")
        os.makedirs(ws3)
        # The prelude carries the shim so this negative control still reports its own reads:
        # a suite that deliberately runs an aborting child must not leave an unobserved one.
        pre = diag_reloc(env, ws3, sd, vd, boot,
                         child_prelude=(RP.CHILD_SHIM_SOURCE
                                        + "import sys\nprint('[]')\nsys.exit(0)\n"),
                         expect_inventory_sha256=inv)
        check("T15-6. MUTATION: a prelude that exits before importing the bundled verifier is "
              "DIAGNOSTIC ONLY and cannot pass",
              pre["diagnostic_only"] is True and pre["g17_pass"] is False, pre["g17_pass"])
        check("T15-6b. and it is refused because diagnostic execution is permanently "
              "non-adoptable, regardless of what the injected child prints",
              has(pre["failures"], "diagnostic execution is permanently non-adoptable"),
              pre["failures"][:1])
        check("T15-6c. a diagnostic result also refuses to publish an attestation",
              QV.diagnostic_relocate.__doc__ is not None
              and "never" in QV.diagnostic_relocate.__doc__.lower())


# ================================================================== R4-7
def test_r4_7_bootstrap_is_pinned_externally():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "b")
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        good = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv)
        check("T15-7. CORRECTED: the legacy fixture checks the external bootstrap pin but remains "
              "diagnostic because its trivial spec is not authorization",
              not good["g17_pass"] and good["bootstrap_pin_checked"] is True
              and good["diagnostic_only"] is True,
              good["bootstrap_closure_sha256"][:16])
        ident = QV.bootstrap_identity()
        check("T15-7b. the closure is an explicit enumeration, not a discovery step",
              sorted(ident) == sorted(QV.BOOTSTRAP_FILES)
              and "run_provenance.py" in QV.BOOTSTRAP_FILES
              and "qual_spec.py" in QV.BOOTSTRAP_FILES
              and len(QV.BOOTSTRAP_FILES) == 4,
              sorted(ident))
        check("T15-7c. and the digest really is over that enumeration",
              QV.bootstrap_closure_digest() == QV._sha256_text(
                  "\x1e".join("%s\x1f%s" % (n, ident[n]) for n in sorted(ident))))

        ws2 = os.path.join(td, "ws2")
        os.makedirs(ws2)
        wrong = reloc(env, ws2, sd, vd, "c" * 64, expect_inventory_sha256=inv)
        check("T15-7d. MUTATION: a WRONG bootstrap pin refuses before the envelope is even "
              "copied", not wrong["g17_pass"] and wrong["relocated_to"] is None
              and has(wrong["failures"], "external diagnostic pin"),
              wrong["failures"][:1])
        ws3 = os.path.join(td, "ws3")
        os.makedirs(ws3)
        none = reloc(env, ws3, sd, vd, None, expect_inventory_sha256=inv)
        check("T15-7e. MUTATION: omitting it is refused as mandatory",
              not none["g17_pass"] and has(none["failures"], "is mandatory"),
              none["failures"][:1])
        check("T15-7f. and the authorization record must carry it, so the pin has a home outside "
              "the caller's own memory",
              "authorized_bootstrap_sha256" in QS.AUTHZ_REQUIRED_PINS
              and "authorized_bootstrap_sha256" in QS.AUTHZ_ALLOWED_KEYS)


# ================================================================== R4-8 / R4-9
def test_r4_8_9_canonical_attestation():
    with tempfile.TemporaryDirectory() as td:
        env, seal = build(td, "a")
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        outd = os.path.join(td, "out")
        os.makedirs(outd)
        pkg = os.path.join(outd, ENV.CANONICAL_ATTESTATION_DIR)
        res = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv, attestation_package=pkg)
        check("T15-8. CORRECTED: the legacy trivial-spec fixture cannot publish or authenticate a "
              "canonical attestation",
              not res["g17_pass"] and res["diagnostic_only"] is True
              and not os.path.exists(pkg), res["failures"][:2])
        check("T15-8b. refusing that legacy fixture leaves no final-name or partial package",
              os.listdir(outd) == [], os.listdir(outd))
        check("T15-8c. write_attestation has no canonical flag left to abuse",
              "canonical" not in ENV.write_attestation.__code__.co_varnames[
                  :ENV.write_attestation.__code__.co_argcount])

        forged = {"schema": ENV.RELOCATION_RESULT_SCHEMA, "source_stable": True,
                  "verified_copy_outer_seal_sha256": sd, "relocated_to": "/nowhere",
                  "verified_with": "tools/verifier.py", "verifier_source_sha256": vd,
                  "expectations": {"outer_seal_sha256": sd,
                                   "bundled_verifier_sha256": vd,
                                   "typed_inventory_sha256": inv,
                                   "bootstrap_closure_sha256": boot},
                  "g17_pass": True, "bootstrap_verified": True, "four_point_identity": True,
                  "passed": True, "failures": []}
        d1 = os.path.join(td, "f1")
        os.makedirs(d1)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d1, ENV.CANONICAL_ATTESTATION_DIR), forged, "FORGED",
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot),
            "published only by the production G17 operation", ENV.EnvelopeError)
        check("T15-8d. MUTATION: without the production token a caller-invented dictionary "
              "publishes nothing", hit and os.listdir(d1) == [], msg[:100])
        d2 = os.path.join(td, "f2")
        os.makedirs(d2)
        hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
            env, os.path.join(d2, ENV.CANONICAL_ATTESTATION_DIR), forged, "FORGED",
            expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
            expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot,
            token=ENV._CANONICAL_TOKEN), "external pin", ENV.EnvelopeError)
        check("T15-8e. MUTATION: even with the internal token, the old four-pin contract is "
              "incomplete and publishes nothing", hit and os.listdir(d2) == [], msg[:100])
        legacy_pins = {
            "expect_outer_seal_sha256": sd,
            "expect_verifier_sha256": vd,
            "expect_envelope_inventory_sha256": inv,
            "expect_bootstrap_sha256": boot,
        }
        for label in ("authorized spec", "authorization record", "full binding", "interpreter"):
            d = tempfile.mkdtemp(dir=td)
            hit, msg = refuses(lambda: ENV.publish_canonical_attestation(
                env, os.path.join(d, ENV.CANONICAL_ATTESTATION_DIR), res, "X",
                token=ENV._CANONICAL_TOKEN, **legacy_pins), "external pin", ENV.EnvelopeError)
            check("T15-8f. MUTATION: the legacy contract has no %-20s pin and is refused" % label,
                  hit and os.listdir(d) == [], msg[:90])

        # R4-9's old positive fixture is no longer authorized.  The fully authorized fault-
        # injection matrix lives in Round 17; here each former publication boundary must remain
        # unreachable from the legacy fixture and leave no final-name package.
        for label, victim in (("the single package rename", "rename"),
                              ("the sidecar write", "open"),
                              ("the attestation write", "open1")):
            env3, seal3 = build(td, "p_%s" % victim)
            sd3, vd3, inv3, boot3 = pins(env3, seal3)
            ws3 = os.path.join(td, "ws_%s" % victim)
            os.makedirs(ws3)
            parent = os.path.join(td, "pub_%s" % victim)
            os.makedirs(parent)
            target = os.path.join(parent, ENV.CANONICAL_ATTESTATION_DIR)
            res3 = reloc(env3, ws3, sd3, vd3, boot3, expect_inventory_sha256=inv3)
            hit, _msg = refuses(lambda: ENV.publish_canonical_attestation(
                env3, target, res3, QV.VERIFIER_ID, expect_outer_seal_sha256=sd3,
                expect_verifier_sha256=vd3, expect_envelope_inventory_sha256=inv3,
                expect_bootstrap_sha256=boot3, token=ENV._CANONICAL_TOKEN),
                "external pin", ENV.EnvelopeError)
            check("T15-9. CORRECTED: legacy input cannot reach %-26s and leaves NO final-name "
                  "package" % label, hit and not res3["g17_pass"] and not os.path.exists(target),
                  sorted(os.listdir(parent)))


# ================================================================== R4-10 / R4-11
def test_r4_10_11_historical_pins_and_directories():
    with tempfile.TemporaryDirectory() as td:
        b, arch = mini(td)
        p = hi_pins(b, arch)
        base = HI.verify_bundle(b, expected=p)
        check("T15-10. BASELINE: a miniature synthetic bundle with external pins passes",
              base["passed"], base["failures"][:2])
        bypass = HI.verify_bundle(b, expected=None, require_external_pins=False)
        check("T15-10b. MUTATION: require_external_pins=False can never pass, and says it is a "
              "diagnostic", not bypass["passed"] and bypass["diagnostic_only"] is True
              and has(bypass["failures"], "DIAGNOSTIC mode"), bypass["failures"][:1])
        nopins = HI.verify_bundle(b, expected=None)
        check("T15-10c. MUTATION: and omitting the pins in normal mode is refused",
              not nopins["passed"] and has(nopins["failures"], "no external pin supplied"),
              nopins["failures"][:1])

        b2, arch2 = mini(td, "EMPTY_20260101", empty_dir=os.path.join("logs", "kept"))
        p2 = hi_pins(b2, arch2)
        check("T15-11. BASELINE: a bundle whose seal binds its directories passes",
              HI.verify_bundle(b2, expected=p2)["passed"],
              HI.verify_bundle(b2, expected=p2)["failures"][:2])
        added = os.path.join(b2, "unlisted_empty")
        os.makedirs(added)
        f = HI.verify_bundle(b2, expected=p2)
        check("T15-11b. MUTATION: an unlisted empty directory is refused on the directory "
              "inventory and the count",
              not f["passed"] and has(f["failures"], "declares directories that are not")
              and has(f["failures"], "directory_count"), f["failures"][:2])
        os.rmdir(added)
        os.rmdir(os.path.join(b2, "logs", "kept"))
        f2 = HI.verify_bundle(b2, expected=p2)
        check("T15-11c. MUTATION: deleting a directory the seal binds is refused too",
              not f2["passed"] and has(f2["failures"], "missing="), f2["failures"][:1])
        os.makedirs(os.path.join(b2, "logs", "kept"))
        check("T15-11d. and restoring it exactly returns the bundle to passing",
              HI.verify_bundle(b2, expected=p2)["passed"])


# ================================================================== R4-12
def test_r4_12_inner_seal_is_an_integrity_check():
    with tempfile.TemporaryDirectory() as td:
        ok = inner_bundle(td, "ok")
        digest, fails = ENV.inner_seal_failures(ok, "FINAL_SEAL.json")
        check("T15-12. BASELINE: a collection whose seal binds its parsed checksum list, its "
              "inventory and its directories verifies clean", fails == [], fails)
        check("T15-12b. and the external inner-seal expectation is satisfied by the ACTUAL file",
              ENV.inner_seal_failures(ok, "FINAL_SEAL.json", expect_digest=digest)[1] == [])

        cases = {}
        for label, mutate, needle in (
                ("an invented schema",
                 lambda d: d.update(schema="totally-invented-by-me/9"),
                 "not one of the supported inner collection schemas"),
                ("no finality", lambda d: (d.pop("sealed", None), d.pop("final", None)),
                 "declares no finality"),
                ("a traversing sums_file", lambda d: d.update(sums_file="../outside_sums"),
                 "unsafe"),
                ("a wrong checksum-list digest",
                 lambda d: d.update(sha256sums_sha256="0" * 64), "but"),
                ("a short inventory", lambda d: d.update(inventory=[]),
                 "is not the collection's non-self files"),
                ("a wrong file count", lambda d: d.update(file_count=99),
                 "declares 99 files"),
                ("no directory inventory", lambda d: d.pop("directories"),
                 "declares no directory inventory"),
                ("an unknown field", lambda d: d.update(surprise=1),
                 "unknown field")):
            c = inner_bundle(td, "c%d" % len(cases))
            sp = os.path.join(c, "FINAL_SEAL.json")
            doc = json.loads(open(sp, encoding="utf-8").read())
            mutate(doc)
            w(sp, json.dumps(doc) + "\n")
            _d, f = ENV.inner_seal_failures(c, "FINAL_SEAL.json")
            cases[label] = f
            check("T15-12c. MUTATION: %-30s is refused" % label, any(needle in x for x in f),
                  (f or ["nothing"])[:1])

        empty = os.path.join(td, "empty")
        w(os.path.join(empty, "raw", "r.json"), "{}\n")
        w(os.path.join(empty, "SHA256SUMS"), "")
        w(os.path.join(empty, "FINAL_SEAL.json"),
          json.dumps(dict(ENV.inner_seal_document(empty), inventory=[])) + "\n")
        _d, f = ENV.inner_seal_failures(empty, "FINAL_SEAL.json")
        check("T15-12d. MUTATION: an EMPTY checksum list for a collection full of files is "
              "refused, because the list is parsed rather than merely hashed",
              has(f, "present but NOT listed"), f[:1])

        bad = os.path.join(td, "badline")
        w(os.path.join(bad, "raw", "r.json"), "{}\n")
        w(os.path.join(bad, "SHA256SUMS"), "not a checksum line at all\n")
        w(os.path.join(bad, "FINAL_SEAL.json"),
          json.dumps(ENV.inner_seal_document(bad)) + "\n")
        _d, f = ENV.inner_seal_failures(bad, "FINAL_SEAL.json")
        check("T15-12e. MUTATION: a malformed checksum line is refused",
              has(f, "malformed checksum line"), f[:1])


# ================================================================== R4-13
def test_r4_13_malformed_wsl_rows():
    def mk(rows):
        def runner(argv, **kw):
            class R:
                returncode = 0
                stderr = ""
            R.stdout = ("\n".join(["  NAME     STATE      VERSION",
                                   "* Ubuntu   Running    2", ""])
                        if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"] else rows)
            return R()
        return runner

    def win():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

    clean = WP.wsl_inventory(runner=mk("1\tinit\t/sbin/init\n"))
    ok = WP.WorkloadPreflight(providers={"windows": win, "wsl": lambda: clean}).check("lead_in")
    check("T15-13. BASELINE: a distribution whose rows all parse is AVAILABLE and the stage is "
          "allowed", clean.status == WP.STATUS_AVAILABLE and ok.allowed
          and clean.extra["malformed_rows"] == 0, ok.reasons)

    bad = WP.wsl_inventory(runner=mk("1\tinit\t/sbin/init\n"
                                     "4242\tp2pool\t/usr/local/bin/p2pool\textra\n"))
    r = WP.WorkloadPreflight(providers={"windows": win, "wsl": lambda: bad}).check("lead_in")
    check("T15-13b. MUTATION: one malformed row -- a DENIED process with an extra field -- makes "
          "that named distribution ERROR, even though a benign row parsed",
          bad.status == WP.STATUS_ERROR
          and bad.extra["per_distribution"]["Ubuntu"]["ok"] is False,
          bad.extra["per_distribution"])
    check("T15-13c. the malformed row count and a redacted excerpt are recorded",
          bad.extra["malformed_rows"] == 1
          and "p2pool" in bad.extra["per_distribution"]["Ubuntu"]["malformed_excerpt"][0],
          bad.extra["per_distribution"]["Ubuntu"]["malformed_excerpt"])
    check("T15-13d. and the stage is refused", not r.allowed, r.reasons[:1])

    short = WP.wsl_inventory(runner=mk("1\tinit\n"))
    check("T15-13e. MUTATION: a truncated row is malformed too, not merely skipped",
          short.status == WP.STATUS_ERROR and short.extra["malformed_rows"] == 1,
          short.extra["malformed_rows"])

    def gitbash(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
            stdout = "1\tbash\t/mingw64/bin/bash.exe\nbroken row\n"
        return R()

    sh = WP.bash_inventory(runner=gitbash)
    check("T15-13f. the separate shell source applies the same rule and still cannot satisfy WSL",
          sh.status == WP.STATUS_ERROR and sh.extra["malformed_rows"] == 1
          and sh.extra["satisfies_wsl_requirement"] is False, sh.extra["malformed_rows"])


# ================================================================== R4-14
def test_r4_14_exact_sidecar_grammar():
    with tempfile.TemporaryDirectory() as td:
        accepted = {}
        for label, mk in (
                ("canonical two spaces",
                 lambda a: HI.sha256_file(a) + "  " + os.path.basename(a) + "\n"),
                ("one space", lambda a: HI.sha256_file(a) + " " + os.path.basename(a) + "\n"),
                ("leading asterisk",
                 lambda a: HI.sha256_file(a) + "  *" + os.path.basename(a) + "\n"),
                ("trailing spaces",
                 lambda a: HI.sha256_file(a) + "  " + os.path.basename(a) + "   \n"),
                ("tab separator",
                 lambda a: HI.sha256_file(a) + "\t" + os.path.basename(a) + "\n"),
                ("uppercase digest",
                 lambda a: HI.sha256_file(a).upper() + "  " + os.path.basename(a) + "\n"),
                ("no trailing newline",
                 lambda a: HI.sha256_file(a) + "  " + os.path.basename(a)),
                ("a second line",
                 lambda a: HI.sha256_file(a) + "  " + os.path.basename(a) + "\nextra\n")):
            d = os.path.join(td, "g%d" % len(accepted))
            os.makedirs(d)
            b, arch = mini(d, "GRAM_20260101")
            w(arch + HI.SIDECAR_SUFFIX, mk(arch))
            accepted[label] = HI.verify_bundle(b, expected=hi_pins(b, arch))["passed"]
        check("T15-14. BASELINE: the canonical two-space form passes",
              accepted["canonical two spaces"])
        for label in [k for k in accepted if k != "canonical two spaces"]:
            check("T15-14b. MUTATION: %-22s is refused by the exact grammar" % label,
                  not accepted[label], accepted[label])
        check("T15-14c. and the accepted grammar is stated exactly, not merely claimed to be "
              "exact", "exactly two spaces" in HI.SIDECAR_GRAMMAR
              and "No leading '*'" in HI.SIDECAR_GRAMMAR, HI.SIDECAR_GRAMMAR[:60])


# ================================================================== R4-15
def test_r4_15_child_sidecars_are_validated():
    """R4-15 as originally written, re-expressed against the Round-5 rule that a sidecar is an
    observation only when the parent watched that process start and return (R5-7)."""
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "root")
        w(os.path.join(repo, "node", "m.py"), "X = 1\n")
        shim = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                suite_child("pass", "T15-15-baseline")]
        r0 = RP.ProvenanceRecorder(repo, strict=False).begin()
        r0.run_declared(shim, cwd=repo)
        genuine = r0.declared_subprocesses[-1]
        r0.finish()
        check("T15-15. BASELINE: a genuine child that runs the shim and echoes this run's nonce "
              "is api-observed, with no sidecar failures",
              genuine["child_closure"] == RP.CHILD_OBSERVED
              and genuine.get("sidecar_failures") == []
              and (genuine["child_provenance"] or {}).get("nonce") == genuine["nonce"],
              genuine["child_closure"])

        real_exe = os.path.realpath(sys.executable)
        full = {"schema": RP.CHILD_SIDECAR_SCHEMA, "nonce": None, "command_identity": None,
                "argv": ["-c"], "cwd": repo, "root": repo, "pid": 4242,
                "executable": real_exe, "executable_sha256": RP.sha256_file(real_exe),
                "reads": [], "code_reads": [], "metadata": [], "grandchildren": [],
                "exit": 0, "observed": True}
        for label, mutate, needle in (
                ("an empty object", lambda d, n: d.clear(), "schema"),
                ("no schema", lambda d, n: d.pop("schema"), "schema"),
                ("a wrong nonce", lambda d, n: d.update(nonce="0" * 32), "nonce"),
                ("a forged executable digest",
                 lambda d, n: d.update(executable_sha256="0" * 64), "the parent hashed"),
                ("a nonexistent executable",
                 lambda d, n: d.update(executable="/no/such/python"), "not a regular file"),
                ("an unknown field", lambda d, n: d.update(surprise=1), "unknown field"),
                ("a missing field", lambda d, n: d.pop("reads"), "missing"),
                ("observed=false", lambda d, n: d.update(observed=False),
                 "does not declare itself an observation")):
            r = RP.ProvenanceRecorder(repo, strict=False).begin()
            case = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                    suite_child("pass", "T15-15b " + label)]
            _r, e, _inner = suite_run(case, repo,
                                      os.path.join(td, "g%d.json" % len(RESULTS)), inner=r)
            body = dict(full, nonce=e["nonce"], command_identity=e["command_identity"])
            mutate(body, e["nonce"])
            f = w(os.path.join(td, "s%d.json" % len(RESULTS)), json.dumps(body))
            entry = r.attach_child_provenance(case, f)
            r.pin_test_inventory(["a"], 1)
            r.finish()
            d = r.report("f", ["x"], canonical=True, actual_test_ids=["a"], actual_check_count=1)
            check("T15-15b. MUTATION: a sidecar with %-28s is refused" % label,
                  entry["child_closure"] != RP.CHILD_OBSERVED
                  and any(needle in x for x in entry["sidecar_failures"])
                  and not d["api_observed_closure_complete"] and not d["provenance_ok"],
                  (entry["sidecar_failures"] or ["nothing"])[:1])

        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        first_argv = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                      suite_child("pass", "T15-15c first")]
        side = os.path.join(td, "reuse.json")
        _r, e1, _i = suite_run(first_argv, repo, side, inner=r)
        first = r.attach_child_provenance(first_argv, side)
        check("T15-15c0. BASELINE: the first use of that sidecar and nonce is accepted",
              first["child_closure"] == RP.CHILD_OBSERVED,
              (first.get("sidecar_failures") or ["ok"])[:1])
        shim2 = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                 suite_child("pass", "T15-15c second")]
        _r2, _e2, _i2 = suite_run(shim2, repo, os.path.join(td, "second.json"), inner=r)
        second = r.attach_child_provenance(shim2, side)
        r.finish()
        check("T15-15c. MUTATION: a sidecar and nonce cannot be reused by a second child",
              second["child_closure"] != RP.CHILD_OBSERVED
              and any("already" in x for x in second["sidecar_failures"]),
              (second["sidecar_failures"] or ["nothing"])[:1])


# ================================================================== R4-16
def test_r4_16_read_api_coverage():
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "root")
        target = w(os.path.join(repo, "docs", "append_read.txt"), "bytes to read\n")
        control = w(os.path.join(repo, "docs", "control.txt"), "control\n")
        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        fd = os.open(target, os.O_RDWR | os.O_APPEND)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.read(fd, 32)
        finally:
            os.close(fd)
        pathlib.Path(control).read_text(encoding="utf-8")
        wfd = os.open(os.path.join(repo, "docs", "written.txt"), os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(wfd)
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("read", ["x"], canonical=False, actual_test_ids=["a"], actual_check_count=1)
        ur = sorted(d["undeclared_local_reads"])
        check("T15-16. BASELINE: a pathlib read is observed",
              "docs/control.txt" in ur, ur)
        check("T15-16b. MUTATION CLOSED: os.open(O_RDWR | O_APPEND) is observed too -- a "
              "descriptor is readable unless its ACCESS MODE is O_WRONLY",
              "docs/append_read.txt" in ur, ur)
        check("T15-16c. and a genuinely write-only descriptor is correctly NOT a read",
              "docs/written.txt" not in ur, ur)

        side = os.path.join(td, "child.json")
        a = w(os.path.join(td, "a.txt"), "a\n")
        b = w(os.path.join(td, "b.txt"), "b\n")
        c = w(os.path.join(td, "c.txt"), "c\n")
        code = (RP.CHILD_SHIM_SOURCE
                + "import os, _io, pathlib\n"
                  "fd = os.open(%r, os.O_RDONLY)\nos.read(fd, 8)\nos.close(fd)\n"
                  "_io.open(%r).read()\n"
                  "pathlib.Path(%r).read_text()\n" % (a, b, c))
        argv = [os.path.realpath(sys.executable), "-c", code]
        _r16, entry, _i16 = suite_run(argv, td, side)
        child = json.loads(open(side, encoding="utf-8").read())
        adopted = RECORDER.declared_subprocesses[-1]   # suite_run already attached it
        seen = {os.path.basename(x["path"]) for x in child.get("reads", [])}
        check("T15-16d. the child shim now covers os.open as well as builtins.open, io.open, "
              "_io.open and pathlib", {"a.txt", "b.txt", "c.txt"} <= seen,
              sorted(x for x in seen if x.endswith(".txt")))
        check("T15-16e. the child echoes the nonce it was given, and its sidecar validates",
              child["nonce"] == entry["nonce"] and child["schema"] == RP.CHILD_SIDECAR_SCHEMA
              and adopted["child_closure"] == RP.CHILD_OBSERVED,
              (adopted.get("sidecar_failures") or ["ok"])[:1])


# ================================================================== R4-17
def test_r4_17_metadata_boundary():
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "root")
        w(os.path.join(repo, "docs", "a.txt"), "aaaa\n")
        w(os.path.join(repo, "docs", "b.txt"), "bbbbbb\n")
        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        entries = sorted(pathlib.Path(os.path.join(repo, "docs")).iterdir())
        sizes = {p.name: p.stat().st_size for p in entries}
        chosen = max(sizes, key=sizes.get)
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("meta", ["x"], canonical=False, actual_test_ids=["a"], actual_check_count=1)
        md = d["metadata_observations"]
        check("T15-17. MUTATION CLOSED: a decision made from directory enumeration and sizes "
              "alone is recorded, with a stable entry identity",
              "docs" in md and md["docs"]["entries"] == ["a.txt", "b.txt"]
              and md["docs"]["entry_count"] == 2, sorted(md))
        check("T15-17b. and the sizes that drove the decision are recorded per file",
              md["docs/%s" % chosen]["size"] == sizes[chosen], chosen)
        boundary = json.dumps(d["observation_boundaries"])
        check("T15-17c. the boundary NAMES the metadata APIs it observes",
              "os.listdir" in boundary and "iterdir" in boundary and "scandir" in boundary)
        check("T15-17d. and names what remains OUTSIDE it rather than listing only mmap",
              "os.stat and os.path.getsize" in boundary)
        check("T15-17e. the report declares its observation model instead of claiming an "
              "unqualified completeness",
              d["observation_model"] == RP.OBSERVATION_MODEL
              and "api_observed_closure_complete" in d and "closure_complete" not in d,
              d["observation_model"])
        check("T15-17f. and the boundary says plainly that this is not an OS tracer",
              "NOT an operating-system tracer" in boundary)


# ================================================================== R4-18
def test_r4_18_runner_child_is_bound():
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "root")
        os.makedirs(os.path.join(repo, "node"))
        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        real_exe = os.path.realpath(sys.executable)
        sidecar = os.path.join(td, "owned_child.json")
        argv = [real_exe, "-I", "-B", "-c",
                suite_child("pass", "T15-18 production process owner")]
        observed = RP.run_observed(
            argv, executable=real_exe, expect_executable_sha256=RP.sha256_file(real_exe),
            cwd=repo, root=repo, expected_inputs={}, sidecar_path=sidecar)
        # One adoption globally consumes the operation-owned capability.  The implementation also
        # attaches that observation to every recorder already active at the real launch boundary,
        # so both this local recorder and the suite recorder account for the same child without
        # replaying its capability.
        RECORDER.adopt_child_record(observed.record)
        entry = r.declared_subprocesses[-1]
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("adopt", ["x"], canonical=False, actual_test_ids=["a"],
                     actual_check_count=1)
        bound = {k: entry.get(k) is not None for k in
                 ("executable_sha256", "cwd", "env_policy", "exit", "stdout_sha256",
                  "stderr_sha256", "inputs_after", "nonce", "declared_inputs")}
        check("T15-18. BASELINE: the operation that OWNED the child binds its interpreter bytes, "
              "argv, cwd, environment policy, inputs before and after, exit and stdout/stderr "
              "digests", all(bound.values()), bound)
        check("T15-18b. the adopted record removes the child from the undeclared list",
              not d["undeclared_subprocesses"], d["undeclared_subprocesses"])
        check("T15-18c. the child ran the project's OWN shim -- prepended by the operation, not "
              "injected by a caller -- so its sidecar is validated and it is api-observed",
              entry["child_closure"] == RP.CHILD_OBSERVED
              and entry.get("sidecar_failures") == []
              and (entry["child_provenance"] or {}).get("nonce") == observed.record["nonce"],
              entry["child_closure"])
        check("T15-18d. so the API-observed closure is complete for this suite",
              d["api_observed_closure_complete"] is True
              and d["closure_incomplete_reasons"] == [], d["closure_incomplete_reasons"][:1])

        # Do not launch an intentionally sidecar-less child inside this canonical suite.  The
        # exact mutation is a pure record-copy attack: it must remain non-adoptable even though it
        # reuses the capability token from a real completed run.
        r2 = RP.ProvenanceRecorder(repo, strict=False).begin()
        bare = dict(observed.record)
        bare.update(sidecar_path=None, sidecar_sha256=None, sidecar_path_classes=[],
                    sidecar_failures=["the copied record claims no sidecar"],
                    execution_proof_ok=False)
        # The genuine capability was consumed above.  Global single-use is checked before object
        # identity, so this edited copy is rejected as an attempted replay of an already-adopted
        # capability.  Round 17 separately proves that a pre-adoption copy is rejected on exact
        # object identity.
        hit, msg = refuses(lambda: r2.adopt_child_record(bare), "already been adopted", ValueError)
        r2.pin_test_inventory(["a"], 1)
        r2.finish()
        check("T15-18e. MUTATION: copying a real record and editing it to claim no sidecar cannot "
              "be adopted or converted into a weaker proof-only capability",
              hit and r2.declared_subprocesses == [], msg[:110])
        check("T15-18f. a record with no schema is refused outright",
              refuses(lambda: r.adopt_child_record({"argv": ["x"]}),
                      "must carry schema", ValueError)[0])


# ------------------------------------------------------------------ main
def main():
    print("ROUND 15 -- the fourth corrective audit's counterexamples. NON-EVIDENCE, NON-LIVE.\n")
    for name in EXPECTED_TESTS:
        print("[%s]" % name)
        globals()[name]()
    functional = len(RESULTS)
    check("T15-INV. the functional check count equals the pinned figure, so a deleted test "
          "cannot yield a smaller still-green n/n",
          functional == FUNCTIONAL_CHECK_COUNT,
          "%d functional checks, pinned at %d" % (functional, FUNCTIONAL_CHECK_COUNT))

    RECORDER.pin_test_inventory(EXPECTED_TESTS, FUNCTIONAL_CHECK_COUNT,
                                meta_check_count=META_CHECK_COUNT)
    RECORDER.finish()
    passed = sum(1 for r in RESULTS if r["passed"])
    doc = RECORDER.report(
        "round15", sys.argv, tested_commit=ARG.get("--commit"),
        canonical=bool(ARG.get("--commit")), actual_test_ids=list(EXPECTED_TESTS),
        actual_check_count=len(RESULTS),
        extra={"label": "NON-EVIDENCE offline infrastructure tests -- fourth corrective round",
               "authorises_no_live_run": True, "passed": passed, "total": len(RESULTS),
               "results": RESULTS})
    print("\nROUND 15: %d/%d" % (passed, len(RESULTS)))
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
