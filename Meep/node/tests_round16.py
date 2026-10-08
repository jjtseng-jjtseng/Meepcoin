#!/usr/bin/env python3
"""Round-16: one behavioural test per counterexample the FIFTH corrective audit reproduced.

NON-EVIDENCE, AND ENTIRELY NON-LIVE. No daemon, miner, driver, tracer, smoke, calibration,
qualification or network call. Every specification, envelope, bundle, verifier, interpreter and
process inventory is a synthetic or disposable fixture in a temporary directory. The real Gate N
and the real CADENCEQ archives are never touched, and no WSL distribution is enumerated, started
or stopped: every inventory here is a synthetic string.

EVERY TEST HAS THE SAME SHAPE: prove the UNMUTATED baseline passes, then prove the EXACT mutation
fails FOR THE INTENDED REASON. A source-text search is never accepted as enforcement where a
behavioural test is possible.

THE THREAT MODEL is stated in node/qual_runner_v2.py and is unchanged: API enforcement inside one
Python process, NOT an operating-system sandbox. A hostile same-process caller can import
subprocess or reach underscore-prefixed module globals. What is tested here is that the SUPPORTED
project APIs cannot be talked into a launch, a G17 pass, a canonical attestation, an authenticated
attestation or a canonical provenance claim.

Case map (R5-n as reproduced before the repair):
  R5-1  caller clock runs after the final hashes   R5-10 adopt_child_record trusts a dict
  R5-2  collector passes with no sidecar           R5-11 bootstrap omits executable local code
  R5-3  relative interpreter: checked != executed  R5-12 G17 does not pin its interpreter
  R5-4  an empty collector result is accepted      R5-13 self-made canonical package "verifies"
  R5-5  "bytes" are decoded character counts       R5-14 unauthorised call labelled g17_pass
  R5-6  argv_key collides across vectors           R5-15 unreadable PID treated as benign
  R5-7  forged sidecar, no child ever ran          R5-16 contradictory prospective interfaces
  R5-8  undeclared child read stays green          R5-17 grammar and output-label claims
  R5-9  child metadata-only decisions invisible

Usage: python3 node/tests_round16.py [--out=<path>] [--commit=<sha>]
"""
import ast
import copy
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_provenance as RP

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NODE = os.path.join(_REPO, "node")
RECORDER = RP.ProvenanceRecorder(_REPO, strict=False).begin()

import evidence_envelope as ENV                                        # noqa: E402
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
DESIGN_DOC = os.path.join(_REPO, "docs", "round2",
                          "FUTURE_QUALIFICATION_DESIGN_DRAFT_NO_LAUNCH.md")

EXPECTED_TESTS = (
    "test_r5_1_no_injectable_production_seam",
    "test_r5_2_collector_provenance_is_required",
    "test_r5_3_checked_path_is_executed_path",
    "test_r5_4_5_result_contract_and_raw_bytes",
    "test_r5_6_canonical_command_identity",
    "test_r5_7_a_sidecar_needs_an_observed_process",
    "test_r5_8_9_child_inputs_have_meaning",
    "test_r5_10_child_records_are_observer_owned",
    "test_r5_11_12_the_g17_trust_chain_is_closed",
    "test_r5_13_14_authorized_g17_and_authenticated_attestation",
    "test_r5_15_unreadable_process_identity",
    "test_r5_16_17_prospective_docs_and_grammar",
)
FUNCTIONAL_CHECK_COUNT = 138
META_CHECK_COUNT = 1

COLLECTOR = RP.CHILD_SHIM_SOURCE + '''import json, sys
a = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in sys.argv[1:] if "=" in x}
print(json.dumps({"raw_records": 6, "branch_observations": 25, "telemetry_retained": True,
                  "collection_seconds": 0.02, "staging_dir": a.get("--staging", ""),
                  "note": "synthetic fixture collector"}))
'''
EVALUATOR = '"""synthetic"""\nGATE = %r\n'


# ------------------------------------------------------------------ helpers
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
    return any(needle in str(f) for f in failures)


def disposable_interpreter(root, name="py_copy"):
    """A COPY of the resolved interpreter, so a mutation test never touches a system file."""
    real = os.path.realpath(sys.executable)
    os.makedirs(root, exist_ok=True)
    dst = os.path.join(root, name)
    shutil.copyfile(real, dst)
    os.chmod(dst, 0o755)
    return {"path": dst, "sha256": QS.sha256_file(dst)}


def authorized_fixture(root, interpreter=None, collector=COLLECTOR, spec_id="R16"):
    ar = os.path.join(root, "authz_root")
    os.makedirs(ar, exist_ok=True)
    draft = json.loads(RECORDER.read_declared(SPEC_PATH, kind="qualification_spec", mode="rb")
                       .decode("utf-8"))
    d = dict(draft)
    d["status"] = QS.STATUS_AUTHORIZED
    d["spec_id"] = spec_id
    cpath = w(os.path.join(ar, "collector.py"), collector)
    ev = {}
    for g in draft["gates"]:
        p = w(os.path.join(ar, "evaluators", g["id"] + ".py"), EVALUATOR % g["id"])
        ev[g["id"]] = {"module": "evaluators/%s.py" % g["id"], "sha256": QS.sha256_file(p)}
    d["gates"] = [dict(g, thresholds={"limit": 1.0},
                       domain={"limit": {"min": 0.0, "max": 10.0}}) for g in draft["gates"]]
    interp = interpreter or disposable_interpreter(ar)
    d.update({
        "run_identity": spec_id, "snapshot": {"id": "SNAP", "sha256": "a" * 64},
        "schedule": {"order": ["control", "attack"]},
        "condition_order": ["control", "attack"], "replicates": 3,
        "rates": {"total": 1.5}, "durations": {"mine": 60.0, "post": 30.0},
        "ports": {"base": 41000, "count": 8}, "namespace": "r16-testonly",
        "refusal_policy": {"on_denied_workload": "refuse"},
        "required_envelope_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES),
        "collector_binding": {"path": "collector.py", "sha256": QS.sha256_file(cpath),
                              "interpreter": interp, "dependencies": {}},
        "authorization_record": "authz.json", "evaluators": ev,
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
    az = os.path.join(ar, "authz.json")
    with open(az, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, indent=1)
    return {"root": ar, "spec_path": sp, "spec_sha256": sdig, "collector_path": cpath,
            "inventory_sha256": doc["gate_inventory_sha256"],
            "binding_sha256": doc["binding_sha256"], "authz_path": az,
            "authz_sha256": QS.sha256_file(az), "interp": interp}


def synthetic_preflight(cls=None):
    """SYNTHETIC inventories only. No real process is inspected, started or signalled."""
    def win():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

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


def run_kw(fx, stage):
    return dict(spec_path=fx["spec_path"], expect_spec_sha256=fx["spec_sha256"],
                expect_inventory_sha256=fx["inventory_sha256"],
                expect_binding_sha256=fx["binding_sha256"],
                authorization_path=fx["authz_path"],
                expect_authorization_sha256=fx["authz_sha256"],
                authorized_root=fx["root"], staging_dir=stage,
                guard_requires_absent=False)


def adopt(res):
    """Adopt an operation-owned child record into this suite's recorder.

    qual_runner_v2 and qual_verify_v2 create their own children; the record their launch
    observer produced is what makes those children declared and observed HERE."""
    rec = (res or {}).get("child_record")
    if isinstance(rec, dict) and rec.get("record_token"):
        try:
            RECORDER.adopt_child_record(rec)
        except ValueError:                            # already adopted, or not observer-owned
            pass
    return res


def sequence(fx, stage, preflight=None, diagnostic=False, stub=None, timeout=120):
    """The REAL _sequence -- the one run_authorized calls -- with a synthetic preflight.

    run_authorized itself owns the production Windows+WSL providers and is not driven offline;
    this is the same code with the provider set replaced, and it is labelled as such."""
    k = run_kw(fx, stage)
    real = RUN.subprocess
    if stub is not None:
        RUN.subprocess = stub
    try:
        import time as _t
        return adopt(RUN._sequence(
            k["spec_path"], k["expect_spec_sha256"], k["expect_inventory_sha256"],
            k["expect_binding_sha256"], k["authorization_path"],
            k["expect_authorization_sha256"], k["authorized_root"], k["staging_dir"],
            preflight or synthetic_preflight(), timeout, _t.time, False, diagnostic))
    finally:
        RUN.subprocess = real


def shimmed(code, tag=""):
    """A child program that carries THIS project's provenance shim, plus a unique tail so each
    child in this suite has its own command identity."""
    return RP.CHILD_SHIM_SOURCE + code + ("\n# suite tag: %s\n" % tag)


def suite_run(argv, cwd, sidecar, inner=None, extra_env=None, inputs=(), root=None):
    """Run one real child through the process-owning API and adopt its frozen record.

    The supported operation owns Popen, PID, pipes, wait and the sidecar snapshot.  A nested
    recorder that encloses the run receives the same observation during the one global adoption;
    the immutable capability itself cannot be replayed.
    """
    cwd = os.path.realpath(os.path.abspath(cwd))
    exe = os.path.realpath(argv[0])
    env = dict(os.environ)
    env.update(extra_env or {})
    expected = {os.path.realpath(os.path.abspath(path)): RP.sha256_file(
        os.path.realpath(os.path.abspath(path))) for path in inputs}
    result = RP.run_observed(
        argv, executable=exe, expect_executable_sha256=RP.sha256_file(exe),
        cwd=cwd, root=os.path.realpath(os.path.abspath(root or cwd)),
        expected_inputs=expected, sidecar_path=os.path.abspath(sidecar),
        env=env, timeout=30)
    outer = RECORDER.adopt_child_record(result.record)
    entry = inner.declared_subprocesses[-1] if inner is not None else None
    return result, outer, entry


def observed_launch(argv, cwd, sidecar):
    """Compatibility-shaped return around the one supported process-owning launch API."""
    result, _outer, _entry = suite_run(argv, cwd, sidecar)
    return result, result.record, result


class NoProcess(object):
    """Stands in for the subprocess module. Starts nothing, ever."""

    def __init__(self, stdout=b"", rc=0, stderr=b""):
        self.out, self.rc, self.err = stdout, rc, stderr
        self.calls = 0
        self.TimeoutExpired = subprocess.TimeoutExpired

    def run(self, argv, **kw):
        self.calls += 1

        class R:
            pass
        R.stdout, R.stderr, R.returncode = self.out, self.err, self.rc
        return R


# ------------------------------------------------------------------ 1..9 the runner boundary
def test_r5_1_no_injectable_production_seam():
    code = RUN.run_authorized.__code__
    params = list(code.co_varnames[:code.co_argcount])
    check("T16-1. the production entry point has NO injectable parameter: no clock, preflight, "
          "runner, collector or prelude",
          not ({"clock", "preflight", "runner", "collector", "child_prelude"} & set(params)),
          params)
    for bad in ("clock", "preflight", "runner", "collector"):
        hit, msg = refuses(lambda b=bad: RUN.run_authorized(
            spec_path="x", expect_spec_sha256="a" * 64, expect_inventory_sha256="a" * 64,
            expect_binding_sha256="a" * 64, authorization_path="y",
            expect_authorization_sha256="a" * 64, authorized_root="z", staging_dir="s",
            **{b: (lambda: 0)}), "unexpected keyword argument", TypeError)
        check("T16-1b. MUTATION: run_authorized(%-9s=...) is a TypeError, not a seam" % bad,
              hit, msg[:90])

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "a"))
        ip, pinned = fx["interp"]["path"], fx["interp"]["sha256"]
        base = RUN.diagnostic_dry_run(preflight=synthetic_preflight(),
                                      **run_kw(fx, os.path.join(td, "a", "s0")))
        check("T16-1c. BASELINE: the diagnostic dry run reaches the launch boundary with no "
              "drift and creates no process",
              base["code"] == "DIAGNOSTIC_ONLY"
              and (base["detail"] or {})["final_recheck"]["drift"] == []
              and base["launch_callback_invocations"] == 0,
              (base["detail"] or {}).get("final_recheck", {}).get("drift"))

        state = {"fired": 0}

        def hostile_clock():
            import time as _t
            if sys._getframe(1).f_code.co_name == "final_recheck" and not state["fired"]:
                state["fired"] = 1
                with open(ip, "ab") as f:
                    f.write(b"\n# rewritten by the caller's clock\n")
            return _t.time()

        res = RUN.diagnostic_dry_run(preflight=synthetic_preflight(), clock=hostile_clock,
                                     **run_kw(fx, os.path.join(td, "a", "s1")))
        check("T16-1d. MUTATION: a diagnostic clock that rewrites the pinned interpreter is "
              "CAUGHT, because the clock is read before the byte checks and the checks are last",
              state["fired"] and res["code"] == "LAUNCH_BEARING_DRIFT"
              and QS.sha256_file(ip) != pinned
              and has((res.get("detail") or {}).get("drift", []), "interpreter"),
              res["code"])

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "b"))
        original = RUN._AuthorizedRun.stage_authorized_code

        def sneaky(self, *a, **k):
            out = original(self, *a, **k)
            with open(fx["interp"]["path"], "ab") as f:
                f.write(b"\n# after staging, before the final check\n")
            return out

        RUN._AuthorizedRun.stage_authorized_code = sneaky
        try:
            res = sequence(fx, os.path.join(td, "b", "s"), diagnostic=True)
        finally:
            RUN._AuthorizedRun.stage_authorized_code = original
        check("T16-1e. MUTATION: a change made AFTER staging but BEFORE the true final check is "
              "caught by that check",
              res["code"] == "LAUNCH_BEARING_DRIFT"
              and has((res.get("detail") or {}).get("drift", []), "interpreter"),
              (res.get("detail") or {}).get("drift", [])[:1])

    tree = ast.parse(RECORDER.read_declared(os.path.join(_NODE, "qual_runner_v2.py"),
                                            kind="module_source"))
    seq = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_sequence"][0]
    calls = sorted((n for n in ast.walk(seq)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)),
                   key=lambda n: (n.lineno, n.col_offset))
    names = [n.func.attr for n in calls]
    try:
        final_at = names.index("final_recheck")
    except ValueError:                                # pragma: no cover - defensive
        final_at = -1
    after = names[final_at + 1:] if final_at >= 0 else names
    forbidden = [x for x in after if x in ("check", "prepare", "stage_authorized_code")]
    check("T16-1f. and no preflight check, staging or preparation call appears AFTER the final "
          "recheck in _sequence", final_at >= 0 and not forbidden, forbidden or after[:6])

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "c"))
        res = sequence(fx, os.path.join(td, "c", "s"))
        check("T16-1g. the ACTUAL event order is authorization -> lead-in -> prepare -> "
              "pre-launch -> final recheck -> launch",
              res.get("event_sequence", [])[-4:] ==
              ["prepare", "preflight:pre_launch", "final_launch_binding_recheck",
               "launch_and_collect"], res.get("event_sequence"))


def test_r5_2_collector_provenance_is_required():
    good = json.dumps({"raw_records": 6, "branch_observations": 25,
                       "collection_seconds": 0.02}).encode("utf-8")
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "a"))
        res = sequence(fx, os.path.join(td, "a", "s"))
        check("T16-2. BASELINE: a genuine collector that runs the shim produces a NON-REFUSED "
              "result with a validated provenance sidecar",
              res.get("refused") is False and res.get("child_sidecar_failures") == []
              and res["child_record"]["process_started"] is True
              and res["child_record"]["process_returned"] is True,
              res.get("note") or res.get("code"))
        check("T16-2b. and the parent-side record binds the command identity, the executable "
              "digest, cwd, the observed exit and the RAW output digests",
              all(res["child_record"][k] is not None for k in
                  ("command_identity", "executable_sha256", "cwd", "exit", "stdout_sha256",
                   "stderr_sha256", "started_utc", "returned_utc")),
              sorted(res["child_record"]))

    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "b"))
        stub = NoProcess(good)
        res = sequence(fx, os.path.join(td, "b", "s"), stub=stub)
        check("T16-2c. MUTATION: replacing the runner module's old subprocess attribute with a "
              "no-process stub cannot replace run_observed's privately owned real Popen",
              stub.calls == 0 and res.get("refused") is False
              and res.get("child_record", {}).get("pid", 0) > 0,
              (stub.calls, res.get("code"), res.get("child_record", {}).get("pid")))

    # Invalid real children cannot live inside a provenance-green canonical suite.  Exercise the
    # exact production validator as pure mutations of one valid, already-adopted child instead.
    with tempfile.TemporaryDirectory() as td:
        exe = os.path.realpath(sys.executable)
        side = os.path.join(td, "valid.json")
        argv = [exe, "-I", "-B", "-c", shimmed("pass", "T16 pure sidecar mutation")]
        observed, record, _result = observed_launch(argv, td, side)
        malformed_fails = RP.sidecar_failures(
            record, {"totally": "invented"}, os.path.join(td, "malformed-copy.json"))
        wrong = copy.deepcopy(observed.sidecar_document)
        wrong["nonce"] = "0" * 32
        nonce_fails = RP.sidecar_failures(
            record, wrong, os.path.join(td, "wrong-nonce-copy.json"))
        check("T16-2d. MUTATION: a MALFORMED sidecar copy is refused for the intended reason",
              has(malformed_fails, "schema"), malformed_fails[:1])
        check("T16-2e. MUTATION: a WELL-FORMED sidecar copy with the wrong nonce is refused",
              has(nonce_fails, "nonce"), nonce_fails[:1])


def test_r5_3_checked_path_is_executed_path():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(os.path.join(td, "a"))
        res = RUN.diagnostic_dry_run(preflight=synthetic_preflight(),
                                     **run_kw(fx, os.path.join(td, "a", "s")))
        detail = res.get("detail") or {}
        argv0 = (detail.get("would_launch") or [None])[0]
        check("T16-3. BASELINE: argv[0] is the exact canonical absolute interpreter the final "
              "recheck type-checked and hashed",
              argv0 == fx["interp"]["path"] == detail["final_recheck"]["canonical_interpreter"]
              and os.path.isabs(argv0), argv0)

        base = os.path.join(td, "b")
        os.makedirs(base, exist_ok=True)
        interp = disposable_interpreter(base, "relpy")
        old = os.getcwd()
        os.chdir(base)
        try:
            rel = authorized_fixture(base, interpreter={"path": "relpy",
                                                        "sha256": interp["sha256"]})
            r2 = RUN.diagnostic_dry_run(preflight=synthetic_preflight(),
                                        **run_kw(rel, os.path.join(base, "s")))
        finally:
            os.chdir(old)
        check("T16-3b. MUTATION: a RELATIVE interpreter is refused -- it would name one object "
              "at check time and another under the launch cwd",
              r2["code"] in ("SPEC_REFUSED", "LAUNCH_BEARING_DRIFT")
              and "interpreter" in str(r2).lower()
              and ("canonical" in str(r2).lower() or "relative" in str(r2).lower()),
              {"code": r2.get("code"), "note": r2.get("note")})

        link_root = os.path.join(td, "c")
        os.makedirs(link_root, exist_ok=True)
        real = disposable_interpreter(link_root, "real_py")
        alias = os.path.join(link_root, "alias_py")
        made = True
        try:
            os.symlink(real["path"], alias)
        except (OSError, NotImplementedError, AttributeError):    # pragma: no cover - platform
            made = False
        if made:
            fx3 = authorized_fixture(link_root, interpreter={"path": alias,
                                                             "sha256": real["sha256"]})
            r3 = RUN.diagnostic_dry_run(preflight=synthetic_preflight(),
                                        **run_kw(fx3, os.path.join(link_root, "s")))
            check("T16-3c. MUTATION: an ALIASED interpreter is refused -- a link is not the "
                  "object it points at",
                  r3["code"] in ("SPEC_REFUSED", "LAUNCH_BEARING_DRIFT"),
                  str(r3.get("note"))[:110])
        else:                                                     # pragma: no cover - platform
            check("T16-3c. symlinks are unavailable here, so the alias case is not claimed",
                  True, "skipped")

        d = os.path.join(td, "d")
        fx4 = authorized_fixture(d)
        labels = ((RUN.diagnostic_dry_run(preflight=synthetic_preflight(),
                                          **run_kw(fx4, os.path.join(d, "s")))
                   .get("detail") or {}).get("final_recheck", {}).get("labels", []))
        check("T16-3d. the final recheck covers the specification, the authorization record, "
              "the interpreter, the collector, every evaluator AND the staged paths argv names",
              {"qualification specification", "authorization record", "interpreter",
               "collector"} <= set(labels)
              and any(x.startswith("STAGED ") for x in labels), len(labels))


def test_r5_4_5_result_contract_and_raw_bytes():
    kept, opaque, fails = RUN.coerce_retained(
        {"raw_records": 6, "branch_observations": 25, "collection_seconds": 0.02})
    check("T16-4. BASELINE: a complete engineering result satisfies the minimum contract",
          fails == [] and sorted(kept) == ["branch_observations", "collection_seconds",
                                           "raw_records"], fails)
    for label, payload in (("an empty object", {}),
                           ("only a note", {"note": "hello"}),
                           ("counts without a duration",
                            {"raw_records": 1, "branch_observations": 1})):
        _k, _o, f = RUN.coerce_retained(payload)
        check("T16-4b. MUTATION: %-26s cannot state that collection occurred" % label,
              has(f, "omits"), (f or ["nothing"])[:1])

    with tempfile.TemporaryDirectory() as td:
        empty_collector = RP.CHILD_SHIM_SOURCE + "print('{}')\n"
        fx = authorized_fixture(os.path.join(td, "a"), collector=empty_collector)
        res = sequence(fx, os.path.join(td, "a", "s"))
        check("T16-4c. MUTATION: and the ACTUAL sequence refuses an empty collector result "
              "before it can reach a document", res.get("refused") is True
              and res.get("code") == "COLLECTOR_RESULT_REJECTED", res.get("code"))

    with tempfile.TemporaryDirectory() as td:
        prog = shimmed(
            "import sys\n"
            "sys.stdout.buffer.write('r\\u00e9sum\\u00e9 \\u2013 \\u00e9\\u00e9\\n'"
            ".encode('utf-8'))\n"
            "sys.stdout.buffer.write(b'{\"raw_records\": 1}\\n')\n", "emit")
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        observed, _o, _e = suite_run(argv, td, os.path.join(td, "emit.json"))
        raw, rec = observed.stdout, observed.record
        check("T16-5. BASELINE: non-ASCII raw stdout is counted and hashed AS BYTES",
              rec["stdout_bytes"] == len(raw)
              and rec["stdout_sha256"] == hashlib.sha256(raw).hexdigest(),
              (rec["stdout_bytes"], len(raw)))
        check("T16-5b. and the byte count is NOT the character count of a decoding",
              rec["stdout_bytes"] != len(raw.decode("utf-8")),
              (rec["stdout_bytes"], len(raw.decode("utf-8"))))
        hit, msg = refuses(lambda: RP.begin_launch(argv, cwd=td),
                           "begin_launch() is unsupported", RP.LaunchObserverError)
        check("T16-5c. MUTATION: the obsolete split API cannot accept caller-supplied decoded "
              "output (or any caller-supplied process facts)",
              hit, msg[:100])

    with tempfile.TemporaryDirectory() as td:
        invalid_utf8 = (RP.CHILD_SHIM_SOURCE +
                        "import sys\nsys.stdout.buffer.write(b'\\xff\\xfe not valid utf-8\\n')\n")
        fx = authorized_fixture(os.path.join(td, "a"), collector=invalid_utf8)
        res = sequence(fx, os.path.join(td, "a", "s"))
        check("T16-5d. MUTATION: collector stdout that is not valid UTF-8 is refused under an "
              "explicit strict decoding policy, not silently replaced",
              res.get("refused") is True and "UTF-8" in str(res.get("code")), res.get("code"))


def test_r5_6_canonical_command_identity():
    a = ["same program", "argument"]
    b = ["same", "program argument"]
    check("T16-6. BASELINE: a command's identity is stable for the same vector",
          RP.command_identity(a) == RP.command_identity(list(a)))
    check("T16-6b. MUTATION CLOSED: the two boundary-ambiguous vectors have DIFFERENT identities",
          RP.command_identity(a) != RP.command_identity(b)
          and RP.argv_key(a) != RP.argv_key(b), (RP.argv_key(a), RP.argv_key(b)))
    check("T16-6c. and the human-readable display is separate, never an identity",
          RP.argv_display(a) == RP.argv_display(b)
          and RP.argv_display(a) not in RP.argv_key(a), RP.argv_display(a))
    check("T16-6d. the canonical encoding is an explicit UTF-8 JSON array, so an empty argument "
          "and a missing argument differ",
          RP.command_identity(["x", ""]) != RP.command_identity(["x"]))
    long_a = ["p"] * 400 + ["tail_a"]
    long_b = ["p"] * 400 + ["tail_b"]
    check("T16-6e. and two vectors that agree for the first 400 arguments still differ",
          RP.command_identity(long_a) != RP.command_identity(long_b))


def test_r5_7_a_sidecar_needs_an_observed_process():
    with tempfile.TemporaryDirectory() as td:
        repo = os.path.join(td, "root")
        w(os.path.join(repo, "node", "m.py"), "X = 1\n")
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                RP.CHILD_SHIM_SOURCE + "pass"]
        r = RP.ProvenanceRecorder(repo, strict=False).begin()
        _observed, _outer, genuine = suite_run(
            argv, repo, os.path.join(td, "baseline.json"), inner=r)
        r.finish()
        check("T16-7. BASELINE: a genuine observed child with a valid sidecar is api-observed",
              genuine["child_closure"] == RP.CHILD_OBSERVED
              and genuine["sidecar_failures"] == []
              and genuine["process_started"] and genuine["process_returned"],
              genuine["child_closure"])

        victim = os.path.join(_REPO, "docs", "ARCHITECTURE.md")
        if not os.path.isfile(victim):                # pragma: no cover - repository shape
            victim = SPEC_PATH
        other = os.path.realpath(shutil.which("sh") or "/bin/sh")
        full = {"schema": RP.CHILD_SIDECAR_SCHEMA, "nonce": None,
                "command_identity": None, "argv": ["-c"], "cwd": repo, "root": repo, "pid": 4242,
                "executable": os.path.realpath(sys.executable),
                "executable_sha256": RP.sha256_file(os.path.realpath(sys.executable)),
                "reads": [], "code_reads": [], "metadata": [], "grandchildren": [],
                "exit": 0, "observed": True}

        # a child that was DECLARED and NEVER STARTED
        r2 = RP.ProvenanceRecorder(repo, strict=False).begin()
        plain = [os.path.realpath(sys.executable), "-c", "never_run"]
        e = r2.declare_subprocess(plain, cwd=repo)
        body = dict(full, nonce=e["nonce"], command_identity=e["command_identity"])
        f = w(os.path.join(td, "never.json"), json.dumps(body))
        never = r2.attach_child_provenance(plain, f)
        r2.pin_test_inventory(["a"], 1)
        r2.finish()
        d = r2.report("never", ["x"], canonical=True, actual_test_ids=["a"], actual_check_count=1)
        check("T16-7b. MUTATION: a perfectly shaped sidecar with the right nonce, for a child "
              "that was NEVER STARTED, is NOT an observation",
              never["child_closure"] != RP.CHILD_OBSERVED
              and has(never["sidecar_failures"], "no parent-observed process start")
              and d["api_observed_closure_complete"] is False and not d["provenance_ok"],
              never["child_closure"])

        # every field mutation, against a child the recorder DID observe
        mutations = (
            ("a project document as the executable",
             lambda b: b.update(executable=victim, executable_sha256=RP.sha256_file(victim)),
             "not the file the parent launched"),
            ("a different real executable",
             lambda b: b.update(executable=other, executable_sha256=RP.sha256_file(other)),
             "not the file the parent launched"),
            ("empty argv", lambda b: b.update(argv=[]), "non-empty list of strings"),
            ("a null cwd", lambda b: b.update(cwd=None), "canonical absolute path"),
            ("a wrong cwd", lambda b: b.update(cwd=os.path.dirname(td)), "not the parent's"),
            ("a non-path root", lambda b: b.update(root={"not": "a path"}),
             "canonical absolute"),
            ("a wrong root", lambda b: b.update(root=os.path.dirname(td)), "not the parent's"),
            ("a null exit", lambda b: b.update(exit=None), "not an integer"),
            ("a wrong exit", lambda b: b.update(exit=17), "the parent saw"),
            ("a wrong command identity", lambda b: b.update(command_identity="0" * 64),
             "command identity"),
            ("an UPPERCASE digest",
             lambda b: b.update(executable_sha256=RP.sha256_file(
                 os.path.realpath(sys.executable)).upper()), "lowercase 64-hex"),
            ("a malformed read entry", lambda b: b.update(reads=[{"path": 5}]),
             "contain exactly"),
            ("a non-lowercase read digest",
             lambda b: b.update(reads=[{"path": "/x", "how": "io.open", "sha256": "A" * 64}]),
             "non-lowercase digest"),
            ("a duplicate read path",
             lambda b: b.update(reads=[{"path": "/x", "how": "io.open", "sha256": None},
                                       {"path": "/x", "how": "io.open", "sha256": None}]),
             "twice"),
            ("a missing pid", lambda b: b.pop("pid"), "missing"),
            ("an unknown field", lambda b: b.update(surprise=1), "unknown field"),
            ("observed=false", lambda b: b.update(observed=False),
             "does not declare itself an observation"),
        )
        for label, mutate, needle in mutations:
            rr = RP.ProvenanceRecorder(repo, strict=False).begin()
            shim = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                    shimmed("pass", label)]
            side = os.path.join(td, "genuine_%d.json" % len(RESULTS))
            observed, _outer, genuine = suite_run(shim, repo, side, inner=rr)
            body = copy.deepcopy(observed.sidecar_document)
            mutate(body)
            failures = RP.sidecar_failures(observed.record, body, side)
            rr.finish()
            check("T16-7c. MUTATION: a frozen sidecar COPY with %-31s fails strict validation" %
                  label, genuine["child_closure"] == RP.CHILD_OBSERVED
                  and has(failures, needle), (failures or ["nothing"])[:1])


def test_r5_8_9_child_inputs_have_meaning():
    target = os.path.join(_REPO, "docs", "round2",
                          "qualification_spec_v2_DRAFT_NO_LAUNCH.json")
    rel_target = os.path.relpath(target, _REPO).replace(os.sep, "/")

    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(_REPO, strict=False).begin()
        prog = RP.CHILD_SHIM_SOURCE + ("open(%r,'rb').read()\nprint('ok')\n" % target)
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        _run, _outer, _entry = suite_run(
            argv, td, os.path.join(td, "declared.json"), inner=r,
            root=_REPO, inputs=(target,))
        r.pin_test_inventory(["a"], 1)
        r.finish()
        ok = r.report("declared_child_read", ["x"], canonical=False,
                      actual_test_ids=["a"], actual_check_count=1)
        check("T16-8. BASELINE: a child read that WAS declared is observed and leaves the "
              "closure complete",
              ok["api_observed_closure_complete"] is True
              and ok["undeclared_child_local_reads"] == {}
              and os.path.realpath(target) in r.declared_subprocesses[-1]["declared_inputs"],
              ok["closure_incomplete_reasons"][:1])

    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(_REPO, strict=False).begin()
        prog = RP.CHILD_SHIM_SOURCE + ("open(%r,'rb').read()\nprint('ok')\n" % target)
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        _run, _outer, _entry = suite_run(
            argv, td, os.path.join(td, "undeclared.json"), inner=r, root=_REPO)
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("undeclared_child_read", ["x"], canonical=True,
                     actual_test_ids=["a"], actual_check_count=1)
        check("T16-8b. MUTATION: the SAME read, undeclared, becomes an undeclared CHILD input "
              "and fails a canonical report",
              rel_target in d["undeclared_child_local_reads"] and not d["provenance_ok"]
              and any("by a CHILD" in p for p in d["provenance_problems"]),
              sorted(d["undeclared_child_local_reads"])[:2])

    with tempfile.TemporaryDirectory() as td:
        choices = os.path.join(td, "choices")
        w(os.path.join(choices, "small.txt"), "x")
        w(os.path.join(choices, "large.txt"), "x" * 500)
        r = RP.ProvenanceRecorder(td, local_dir=td, strict=False, doc_dirs=("choices",)).begin()
        prog = RP.CHILD_SHIM_SOURCE + (
            "from pathlib import Path\n"
            "print(max(Path(%r).iterdir(), key=lambda p: p.stat().st_size).name)\n" % choices)
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        res, _outer, _entry = suite_run(
            argv, td, os.path.join(td, "metadata.json"), inner=r, root=td)
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("child_metadata", ["x"], canonical=False,
                     actual_test_ids=["a"], actual_check_count=1)
        cp = r.declared_subprocesses[-1]["child_provenance"] or {}
        meta_paths = {os.path.basename(m["path"]) for m in (cp.get("metadata") or [])}
        check("T16-9. MUTATION CLOSED: a child that decides using ONLY iterdir and stat now "
              "records that decision in its metadata ledger",
              res.stdout_text.strip() == "large.txt"
              and "choices" in meta_paths
              and any(m.get("kind") == "directory" and m.get("entry_count") == 2
                      for m in (cp.get("metadata") or [])), sorted(meta_paths))
        check("T16-9b. and the child metadata reaches the report as a first-class field",
              d["child_metadata_observations"] != {},
              sorted(d["child_metadata_observations"])[:3])

    with tempfile.TemporaryDirectory() as td:
        # A synthetic project, so a drift test never touches a file in the real repository.
        proj = os.path.join(td, "proj")
        data = w(os.path.join(proj, "docs", "input.txt"), "before\n")
        r = RP.ProvenanceRecorder(proj, local_dir=os.path.join(proj, "node"), strict=False,
                                  doc_dirs=("docs",)).begin()
        prog = RP.CHILD_SHIM_SOURCE + ("open(%r,'rb').read()\n" % data)
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        _run, _outer, _entry = suite_run(
            argv, proj, os.path.join(td, "stable.json"), inner=r,
            root=proj, inputs=(data,))
        r.pin_test_inventory(["a"], 1)
        r.finish()
        clean = r.report("child_stable", ["x"], canonical=False,
                         actual_test_ids=["a"], actual_check_count=1)
        check("T16-8e. BASELINE: a DECLARED child read whose identity is unchanged leaves the "
              "closure complete",
              clean["api_observed_closure_complete"] is True
              and clean["undeclared_child_local_reads"] == {},
              clean["closure_incomplete_reasons"][:1])

        r2 = RP.ProvenanceRecorder(proj, local_dir=os.path.join(proj, "node"), strict=False,
                                   doc_dirs=("docs",)).begin()
        argv2 = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                 prog + "\n# second\n"]
        _run2, _outer2, _entry2 = suite_run(
            argv2, proj, os.path.join(td, "drift.json"), inner=r2,
            root=proj, inputs=(data,))
        w(data, "after the child read it\n")         # the input changes AFTER the read
        r2.pin_test_inventory(["a"], 1)
        r2.finish()
        drifted = r2.report("child_drift", ["x"], canonical=True,
                            actual_test_ids=["a"], actual_check_count=1)
        check("T16-8f. MUTATION: if that input changes after the child read it, the before/after "
              "identity fails and the canonical report refuses",
              drifted["api_observed_closure_complete"] is False
              and not drifted["provenance_ok"]
              and any("read" in x and "it is" in x
                      for x in drifted["closure_incomplete_reasons"]),
              drifted["closure_incomplete_reasons"][:1])

    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(_REPO, strict=False).begin()
        stale = w(os.path.join(td, "stale_module.py"), "print('hi')\n")
        prog = RP.CHILD_SHIM_SOURCE + (
            "import runpy\nrunpy.run_path(%r)\n" % os.path.join(_NODE, "run_provenance.py"))
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
        _run, _outer, _entry = suite_run(
            argv, td, os.path.join(td, "child_code.json"), inner=r, root=_REPO)
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("child_code", ["x"], canonical=True, tested_commit="0" * 40,
                     actual_test_ids=["a"], actual_check_count=1)
        check("T16-8c. MUTATION: child-executed project source that does not match the tested "
              "commit is named and fails a canonical report",
              d["child_code_reads_outside_tested_commit"] != {} and not d["provenance_ok"],
              sorted(d["child_code_reads_outside_tested_commit"])[:2])
        check("T16-8d. and the observation boundary says the child channels are compared, not "
              "merely recorded",
              "fail a canonical" in json.dumps(d["observation_boundaries"]),
              "boundary text")


def test_r5_10_child_records_are_observer_owned():
    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(td, local_dir=td, strict=False).begin()
        argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", shimmed("pass", "adopt")]
        side = os.path.join(td, "child.json")
        executable = os.path.realpath(sys.executable)
        obs = RP.run_observed(
            argv, executable=executable,
            expect_executable_sha256=RP.sha256_file(executable),
            cwd=td, root=td, expected_inputs={}, sidecar_path=side,
            env=dict(os.environ), timeout=30)
        record = obs.record
        copy_hit, copy_msg = refuses(lambda: r.adopt_child_record(dict(record)),
                                     "a copy or a rebuild", ValueError)
        entry = r.adopt_child_record(record)
        r.finish()
        check("T16-10. BASELINE: a record built by run_observed's owned Popen after the process "
              "returned is adopted and its frozen sidecar validates",
              entry["child_closure"] == RP.CHILD_OBSERVED
              and entry["sidecar_failures"] == [] and RP.validate_child_record(record) == [],
              entry["child_closure"])
        hit, msg = refuses(lambda: r.adopt_child_record(record),
                           "already been adopted", ValueError)
        check("T16-10b. MUTATION: no recorder can adopt the globally consumed record again",
              hit, msg[:100])
        check("T16-10c. MUTATION: a COPY of a genuine record is not that record",
              copy_hit, copy_msg[:90])

    other = shutil.which("sh") or "/bin/sh"
    fabrications = (
        ("only the schema name", {"schema": RP.CHILD_RECORD_SCHEMA}),
        ("a plausible full body",
         {"schema": RP.CHILD_RECORD_SCHEMA, "record_token": "0" * 32,
          "argv": [other], "command_identity": RP.command_identity([other]),
          "executable": other, "executable_sha256": RP.sha256_file(other),
          "cwd": "/", "nonce": "a" * 32, "started_utc": "2026-01-01T00:00:00Z",
          "returned_utc": "2026-01-01T00:00:01Z", "process_started": True,
          "process_returned": True, "exit": 0, "stdout_bytes": 0, "stderr_bytes": 0,
          "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64}),
        ("a nonexistent executable",
         {"schema": RP.CHILD_RECORD_SCHEMA, "record_token": "0" * 32,
          "argv": ["/no/such/bin"], "executable": "/no/such/bin", "exit": 0}),
        ("a negative exit and sizes",
         {"schema": RP.CHILD_RECORD_SCHEMA, "record_token": "0" * 32, "argv": [other],
          "executable": other, "exit": -17, "stdout_bytes": -5, "stderr_bytes": "many"}),
        ("unknown keys",
         {"schema": RP.CHILD_RECORD_SCHEMA, "record_token": "0" * 32, "argv": [other],
          "executable": other, "exit": 0, "totally_invented": True}),
    )
    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(td, local_dir=td, strict=False).begin()
        for label, body in fabrications:
            hit, msg = refuses(lambda b=body: r.adopt_child_record(dict(b)),
                               "not produced by run_observed", ValueError)
            check("T16-10d. MUTATION: a fabricated record with %-24s is rejected" % label,
                  hit, msg[:90])
        hit, msg = refuses(lambda: r.adopt_child_record({"argv": ["x"]}),
                           "must carry schema", ValueError)
        check("T16-10e. and a dictionary with no schema at all is rejected", hit, msg[:80])
        r.finish()

    check("T16-10f. validate_child_record enforces types and ranges independently of adoption",
          has(RP.validate_child_record({"schema": RP.CHILD_RECORD_SCHEMA, "argv": [],
                                        "exit": True}), "non-empty list")
          and has(RP.validate_child_record({"schema": "nope"}), "schema"))

    with tempfile.TemporaryDirectory() as td:
        r = RP.ProvenanceRecorder(td, local_dir=td, strict=False).begin()
        observed, entries, sides = [], [], []
        for i in (0, 1):
            side = os.path.join(td, "c%d.json" % i)
            argv = [os.path.realpath(sys.executable), "-I", "-B", "-c",
                    shimmed("pass", "swap-%d" % i)]
            result, rec, _p = observed_launch(argv, td, side)
            observed.append(result)
            # observed_launch adopts the globally single-use capability through the suite
            # recorder; the recorder already active at launch receives the same final entry.
            entries.append(r.declared_subprocesses[-1])
            sides.append(side)
        crossed = RP.sidecar_failures(
            observed[1].record, copy.deepcopy(observed[0].sidecar_document), sides[1])
        # Rewriting the path after run_observed returned cannot alter the already-frozen answer.
        shutil.copyfile(sides[0], sides[1])
        e0, e1 = entries
        r.finish()
        check("T16-10g. MUTATION: validating child 0's frozen answer against child 1 is refused "
              "for the nonce/command/PID mismatch",
              e0["child_closure"] == RP.CHILD_OBSERVED
              and e1["child_closure"] == RP.CHILD_OBSERVED and has(crossed, "nonce"),
              (crossed or ["nothing"])[:1])
        check("T16-10h. and rewriting a sidecar file AFTER run_observed returned cannot replace "
              "the immutable document adopted by the recorder",
              e1["sidecar_path"] == sides[1]
              and e1["child_provenance"]["nonce"] == observed[1].record["nonce"],
              e1["sidecar_path"])


# ------------------------------------------------------------------ the G17 chain
def _inner_bundle(root, name):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "rec_1.json"), '{"condition":"control","replicate":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    w(os.path.join(b, "SHA256SUMS"), "".join(
        "%s  output  %s\n" % (ENV.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
        for r in ENV.walk_relpaths(b) if r not in ("SHA256SUMS", "FINAL_SEAL.json")))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(ENV.inner_seal_document(b)) + "\n")
    return b


def envelope(root, tag="A"):
    """An envelope binding EVERY authorized role, so an authorized G17 is possible."""
    inner = _inner_bundle(root, "inner_" + tag)
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
    b.bind("outer_verifier", os.path.join(_NODE, "evidence_envelope.py"),
           relpath="tools/verifier.py")
    arch = w(os.path.join(files, "daemon_log_archive.tar.gz"), "archive bytes\n")
    side = w(os.path.join(files, "daemon_log_archive.tar.gz.sha256"),
             "%s  daemon_log_archive.tar.gz\n" % ENV.sha256_file(arch))
    b.bind("daemon_log_archive", arch, relpath="tools/daemon_log_archive.tar.gz")
    b.bind("daemon_log_sidecar", side, relpath="tools/daemon_log_archive.tar.gz.sha256")
    for role in ENV.ROLES:
        if role in ("inner_collection", "environment_trace", "pre_seal_gate_results",
                    "qualification_spec", "source_inventory", "outer_verifier",
                    "daemon_log_archive", "daemon_log_sidecar"):
            continue
        p = w(os.path.join(files, role + ".txt"), "role " + role + "\n")
        b.bind(role, p, relpath="tools/" + role + ".txt")
    b.mark_checked(gates)
    seal = b.seal()
    final = os.path.join(root, "ENV_" + tag)
    b.publish(final)
    interp = os.path.realpath(sys.executable)
    return final, {
        "outer": ENV.sha256_file(os.path.join(final, ENV.SEAL_FILE)),
        "verifier": seal["roles"]["outer_verifier"]["sha256"],
        "inventory": ENV.inventory_digest({r: v for r, v in ENV.typed_inventory(final).items()
                                           if r not in ENV.SELF_FILES}),
        "bootstrap": QV.bootstrap_closure_digest(),
        "spec": seal["roles"]["qualification_spec"]["sha256"],
        "interp_path": interp, "interp_sha256": ENV.sha256_file(interp),
    }


def g17(env, p, ws, package=None, **over):
    # This legacy helper's envelope deliberately binds {"spec_id":"X"}, which is not an
    # authorization.  It therefore exercises the permanent diagnostic path only.  Round 17 owns
    # the complete synthetic AUTHORIZED positive matrix and canonical publication tests.
    kw = dict(expect_spec_sha256=p["spec"], expect_inventory_sha256=p["inventory"],
              spec_required_roles=list(ENV.AUTHORIZED_REQUIRED_ROLES), authorized_run=True,
              attestation_package=package,
              expect_interpreter_path=over.pop("interp_path", p["interp_path"]),
              expect_interpreter_sha256=over.pop("interp_sha256", p["interp_sha256"]))
    kw.update(over)
    return adopt(QV.diagnostic_relocate(
        env, ws, p["outer"], p["verifier"], p["bootstrap"], **kw))


def test_r5_11_12_the_g17_trust_chain_is_closed():
    check("T16-11. BASELINE: the bootstrap closure enumerates every project-local byte that "
          "executes before or as part of the decision",
          set(QV.BOOTSTRAP_FILES) == {"qual_verify_v2.py", "evidence_envelope.py",
                                      "qual_spec.py", "run_provenance.py"},
          list(QV.BOOTSTRAP_FILES))
    src = RECORDER.read_declared(os.path.join(_NODE, "qual_verify_v2.py"),
                                 kind="module_source")
    check("T16-11b. and the child prelude that module prepends comes from one of them",
          "RP.CHILD_SHIM_SOURCE" in src and "+ _child_program" in src)

    with tempfile.TemporaryDirectory() as td:
        mod = os.path.join(td, "modcopy")
        os.makedirs(mod)
        for n in ("qual_verify_v2.py", "evidence_envelope.py", "run_provenance.py",
                  "qual_spec.py", "workload_preflight.py"):
            src_path = os.path.join(_NODE, n)
            RECORDER.register_read(src_path, kind="module_source_copied_for_mutation")
            shutil.copyfile(src_path, os.path.join(mod, n))

        def ask(tag):
            prog = shimmed(
                "import sys, json\nsys.path.insert(0, %r)\n"
                "import qual_verify_v2 as QV\nprint(QV.bootstrap_closure_digest())\n" % mod,
                "closure-" + tag)
            argv = [os.path.realpath(sys.executable), "-I", "-B", "-c", prog]
            r, _o, _e = suite_run(argv, td, os.path.join(td, "ask_%s.json" % tag))
            out = (r.stdout or b"").decode("utf-8", "replace")
            return out.strip().splitlines()[-1] if r.returncode == 0 else \
                (r.stderr or b"").decode("utf-8", "replace")

        before = ask("before")
        check("T16-11c. BASELINE: an untouched copy reports the same closure digest as this "
              "checkout", before == QV.bootstrap_closure_digest(), before)
        rp = os.path.join(mod, "run_provenance.py")
        body = open(rp, encoding="utf-8").read()
        mutated = body.replace('CHILD_SHIM_SOURCE = (\n',
                               'CHILD_SHIM_SOURCE = (\n    "# mutated prelude\\n"\n', 1)
        w(rp, mutated)
        after = ask("after")
        check("T16-11d. MUTATION: changing the child prelude CHANGES the externally pinned "
              "bootstrap closure digest", mutated != body and after != before, after[:16])
        forging = body.replace(
            'CHILD_SHIM_SOURCE = (\n',
            'CHILD_SHIM_SOURCE = (\n    "import os,sys\\n"\n    "sys.exit(0)\\n"\n', 1)
        w(rp, forging)
        check("T16-11e. and a prelude that would exit before the bundled verifier changes it too",
              ask("forged") != before, "closure moved")

    with tempfile.TemporaryDirectory() as td:
        env, p = envelope(td)
        good = g17(env, p, os.path.join(td, "ws0"))
        check("T16-12. CORRECTED: this legacy trivial-spec fixture can check an interpreter pin "
              "only as a diagnostic and can never become G17",
              not good["g17_pass"] and good["diagnostic_only"] is True
              and good["interpreter_pin_checked"] is True
              and good["interpreter_path"] == p["interp_path"], good["failures"][:2])
        for label, ipath, isha, needle in (
                ("a wrong digest", p["interp_path"], "0" * 64, "not the externally pinned"),
                ("no path at all", None, p["interp_sha256"], "is mandatory"),
                ("a relative path", "python3", p["interp_sha256"], "is relative"),
                ("a nonexistent path", "/no/such/python", p["interp_sha256"],
                 "not a regular file"),
                ("no digest", p["interp_path"], None, "64 lowercase hex")):
            r = g17(env, p, os.path.join(td, "wsi_" + label.replace(" ", "_")),
                    interp_path=ipath, interp_sha256=isha)
            reasons = list(r["interpreter_failures"]) + list(r["failures"])
            intended = (r["interpreter_pin_checked"] is False
                        and (needle == "is mandatory" or has(reasons, needle)))
            check("T16-12b. MUTATION: an interpreter pin with %-18s cannot support a child or "
                  "G17" % label,
                  r["g17_pass"] is False and r["interpreter_pin_checked"] is False
                  and intended and r["child_record"] is None, reasons[:1])
        alias = "/usr/bin/python3"
        if os.path.islink(alias):
            r = g17(env, p, os.path.join(td, "ws_alias"), interp_path=alias,
                    interp_sha256=ENV.sha256_file(alias))
            check("T16-12c. MUTATION: an ALIASED interpreter pin is refused -- a link is not the "
                  "object it points at",
                  r["g17_pass"] is False and has(r["interpreter_failures"], "not a regular file"),
                  (r["interpreter_failures"] or ["nothing"])[:1])
        else:                                         # pragma: no cover - platform
            check("T16-12c. no interpreter alias exists on this platform to test", True, "skipped")

        # NOT adopted: an injected runner started nothing, so there is no child to observe and
        # nothing this suite may claim about one.
        diag = QV.diagnostic_relocate(
            env, os.path.join(td, "wsd"), p["outer"], p["verifier"], p["bootstrap"],
            expect_inventory_sha256=p["inventory"],
            runner=lambda a, **k: __import__("types").SimpleNamespace(
                returncode=0, stdout=b"[1]\n", stderr=b""))
        check("T16-12d. an injected runner remains a labelled DIAGNOSTIC that can never set "
              "g17_pass, even with a truthy non-object proof, and production has no runner seam",
              diag["g17_pass"] is False and diag["diagnostic_only"] is True
              and (diag["child_execution_proof"] or {}).get("ok") is False
              and "runner" not in QV.relocate_and_verify.__code__.co_varnames[
                  :QV.relocate_and_verify.__code__.co_argcount],
              diag["diagnostic_only"])

        stub = adopt(QV.diagnostic_relocate(
            env, os.path.join(td, "wsp"), p["outer"], p["verifier"], p["bootstrap"],
            expect_inventory_sha256=p["inventory"],
            child_prelude=(RP.CHILD_SHIM_SOURCE
                           + "import sys\nprint('[]')\nsys.exit(0)\n")))
        check("T16-12e. and a prelude that exits before the bundled verifier cannot satisfy the "
              "proof",
              stub["g17_pass"] is False
              and (stub["child_execution_proof"] or {}).get("ok") is not True,
              (stub["child_execution_proof"] or {}).get("failures", [])[:1])

        # The old fixture used an injected prelude to start a child and corrupt its sidecar.  That
        # seam is now diagnostic and starts nothing unless a diagnostic runner is explicitly
        # supplied, so it cannot create a record that needs an exemption.
        corrupt = adopt(QV.diagnostic_relocate(
            env, os.path.join(td, "wsx"), p["outer"], p["verifier"], p["bootstrap"],
            expect_inventory_sha256=p["inventory"],
            child_prelude=("import atexit as _a0, os as _o0\n"
                           "def _corrupt():\n"
                           "    _p = _o0.environ.get('MEEPCOIN_CHILD_PROVENANCE')\n"
                           "    if _p:\n"
                           "        open(_p, 'w').write('{\"totally\": \"invented\"}')\n"
                           "_a0.register(_corrupt)\n")))
        check("T16-12f. CORRECTED: an injected prelude is permanently diagnostic, starts no "
              "implicit child, and can neither mint a sidecar capability nor publish",
              corrupt["child_sidecar_validated"] is False
              and corrupt["child_record"] is None and corrupt["g17_pass"] is False
              and has(corrupt["failures"], "diagnostic execution is permanently non-adoptable"),
              corrupt["failures"][:1])
        hit, msg = refuses(
            lambda: RECORDER.note_diagnostic_child(
                [os.path.realpath(sys.executable), "-c", "never started"], "no"),
            "no declared child matches", ValueError)
        check("T16-12h. a negative control can be DISCLOSED but never hidden: marking one "
              "requires a child this recorder observed starting and returning",
              hit and all(c["reason"] for c in RECORDER.diagnostic_children()), msg[:80])
        hit2, msg2 = refuses(
            lambda: RECORDER.note_diagnostic_child(
                [os.path.realpath(sys.executable), "-c", "never started"], "   "),
            "must carry a reason", ValueError)
        check("T16-12i. and the reason is mandatory", hit2, msg2[:70])
        gsrc = RECORDER.read_declared(os.path.join(_NODE, "qual_verify_v2.py"),
                                      kind="module_source")
        check("T16-12g. and the g17 decision itself requires that validation, the interpreter "
              "pin and an authorized context",
              'res.get("child_sidecar_validated")' in gsrc
              and 'res.get("interpreter_pin_checked")' in gsrc
              and "authorized_context and not diagnostic" in gsrc)


def test_r5_13_14_authorized_g17_and_authenticated_attestation():
    with tempfile.TemporaryDirectory() as td:
        env, p = envelope(td)
        unauth = g17(env, p, os.path.join(td, "wsu"))
        check("T16-14. CORRECTED: a diagnostic call carrying the old authorization-looking "
              "arguments remains explicitly non-authoritative and cannot be G17",
              unauth["g17_pass"] is False and unauth["authorized_context"] is False
              and unauth["diagnostic_only"] is True
              and "DIAGNOSTIC" in str(unauth.get("g17_note")),
              str(unauth.get("g17_note"))[:80])
        for label, over in (("a caller Boolean", {"authorized_run": True}),
                            ("a caller role list",
                             {"spec_required_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES)}),
                            ("a specification digest alone", {"expect_spec_sha256": p["spec"]}),
                            ("an inventory digest alone",
                             {"expect_inventory_sha256": p["inventory"]})):
            r = g17(env, p, os.path.join(td, "wsc_" + label.replace(" ", "_")), **over)
            check("T16-14b. MUTATION: %-31s cannot manufacture authorization or G17"
                  % label, r["g17_pass"] is False and r["authorized_context"] is False
                  and r["diagnostic_only"] is True, r["authorized_context"])

        nopkg = os.path.join(td, "nopkg")
        os.makedirs(nopkg)
        r = g17(env, p, os.path.join(td, "wsn"),
                package=os.path.join(nopkg, ENV.CANONICAL_ATTESTATION_DIR),
                authorized_run=True)
        check("T16-14c. MUTATION: the diagnostic path publishes nothing even when the caller "
              "requests the canonical package name",
              os.listdir(nopkg) == [] and r["g17_pass"] is False
              and r["diagnostic_only"] is True,
              os.listdir(nopkg))

        prod = inspect.signature(QV.relocate_and_verify).parameters
        forbidden = {"runner", "child_prelude", "authorized_run", "spec_required_roles",
                     "bundled_verifier_role"}
        check("T16-13. CORRECTED: production G17 exposes paths plus complete independent pins, "
              "not the old caller-controlled Boolean/role/runner seams",
              forbidden.isdisjoint(prod)
              and all(prod[n].kind is inspect.Parameter.KEYWORD_ONLY for n in
                      ("spec_path", "authorization_path", "authorized_root",
                       "expect_interpreter_path", "expect_interpreter_sha256")),
              sorted(forbidden.intersection(prod)))
        expected_pins = {
            "authorized_spec_sha256", "gate_inventory_sha256", "gate_semantics_sha256",
            "full_binding_sha256", "authorization_record_sha256", "authorized_root",
            "interpreter_path", "interpreter_sha256", "outer_seal_sha256",
            "bundled_verifier_sha256", "bootstrap_closure_sha256",
            "envelope_typed_inventory_sha256"}
        check("T16-13b. the canonical attestation contract requires exactly twelve distinctly "
              "named external pins",
              ENV.CANONICAL_EXTERNAL_PIN_KEYS == expected_pins,
              sorted(ENV.CANONICAL_EXTERNAL_PIN_KEYS))
        for label, required in (
                ("authorization identity",
                 {"authorized_spec_sha256", "authorization_record_sha256", "authorized_root"}),
                ("gate meaning",
                 {"gate_inventory_sha256", "gate_semantics_sha256", "full_binding_sha256"}),
                ("interpreter identity", {"interpreter_path", "interpreter_sha256"}),
                ("executed verifier closure",
                 {"bundled_verifier_sha256", "bootstrap_closure_sha256"}),
                ("evidence identity",
                 {"outer_seal_sha256", "envelope_typed_inventory_sha256"})):
            check("T16-13c. the external contract independently binds %-27s" % label,
                  required <= ENV.CANONICAL_EXTERNAL_PIN_KEYS,
                  sorted(required - ENV.CANONICAL_EXTERNAL_PIN_KEYS))

        hand = os.path.join(td, "hand", ENV.CANONICAL_ATTESTATION_DIR)
        os.makedirs(hand)
        doc = {"schema": ENV.CANONICAL_ATTESTATION_SCHEMA, "canonical": True, "g17_pass": True,
               "verification_passed": True, "authority": "I MADE THIS UP"}
        inner = w(os.path.join(hand, ENV.CANONICAL_ATTESTATION_NAME), json.dumps(doc) + "\n")
        w(os.path.join(hand, ENV.CANONICAL_ATTESTATION_SIDECAR),
          "%s  %s\n" % (ENV.sha256_file(inner), ENV.CANONICAL_ATTESTATION_NAME))
        struct = ENV.inspect_canonical_attestation_structure(hand)
        check("T16-13d. a structure-only inspection of a HAND-MADE package is well formed and "
              "still reports itself NOT AUTHENTICATED",
              struct["structural_failures"] == [] and struct["authenticated"] is False
              and struct["diagnostic_only"] is True
              and struct["declares_canonical_g17_pass"] is True, struct["authenticated"])
        f = ENV.verify_canonical_attestation(
            hand, env, expect_attestation_sha256=ENV.sha256_file(inner))
        check("T16-13e. MUTATION: but authenticated verification refuses it even when handed "
              "its OWN digest -- the other independent pins are mandatory",
              f != [] and has(f, "external pin"), f[:2])
        check("T16-13f. and the module states the limit of what a package alone can prove",
              "SELF-CONSISTENT CLAIM" in ENV.ATTESTATION_AUTHENTICATION_LIMIT
              and "expect_attestation_sha256" in ENV.ATTESTATION_AUTHENTICATION_LIMIT)

    for label, where in (("before the attestation is written", "attestation"),
                         ("between the two files", "sidecar"),
                         ("at the package rename", "rename")):
        with tempfile.TemporaryDirectory() as td:
            env, p = envelope(td)
            outd = os.path.join(td, "out")
            os.makedirs(outd)
            pkg = os.path.join(outd, ENV.CANONICAL_ATTESTATION_DIR)
            state = {"n": 0}
            real_open, real_rename = ENV.os.open, ENV.os.rename

            def boom_open(path, flags, *a, **k):
                name = os.path.basename(str(path))
                if where == "attestation" and name == ENV.CANONICAL_ATTESTATION_NAME:
                    state["n"] += 1
                    raise OSError("injected failure before the attestation")
                if where == "sidecar" and name == ENV.CANONICAL_ATTESTATION_SIDECAR:
                    state["n"] += 1
                    raise OSError("injected failure between the two files")
                return real_open(path, flags, *a, **k)

            def boom_rename(a, b):
                if where == "rename" and os.path.basename(str(b)) == \
                        ENV.CANONICAL_ATTESTATION_DIR:
                    state["n"] += 1
                    raise OSError("injected failure at the package rename")
                return real_rename(a, b)

            ENV.os.open, ENV.os.rename = boom_open, boom_rename
            try:
                res = g17(env, p, os.path.join(td, "ws"), package=pkg)
            finally:
                ENV.os.open, ENV.os.rename = real_open, real_rename
            check("T16-13g. MUTATION: the unauthorized legacy fixture never reaches the "
                  "publication hook %-32s" % label,
                  state["n"] == 0 and res["g17_pass"] is False
                  and res["diagnostic_only"] is True and not os.path.exists(pkg),
                  {"hook_calls": state["n"], "out": sorted(os.listdir(outd))})


# ------------------------------------------------------------------ preflight and docs
def _wsl_runner(proc_stdout, dist_stdout=None):
    def runner(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
        R.stdout = (dist_stdout if dist_stdout is not None else
                    "\n".join(["  NAME     STATE      VERSION", "* Ubuntu   Running    2", ""])) \
            if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"] else proc_stdout
        return R()
    return runner


def _preflight_with(inv):
    return WP.WorkloadPreflight(providers={
        "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                        [WP.ProcessRecord(4, "System", None,
                                                          "windows:Win32_Process")]),
        "wsl": lambda: inv})


def test_r5_15_unreadable_process_identity():
    ok = WP.wsl_inventory(runner=_wsl_runner("1\tinit\t/sbin/init\n"))
    check("T16-15. BASELINE: a readable /proc row makes the distribution AVAILABLE and the "
          "stage is allowed",
          ok.status == WP.STATUS_AVAILABLE and (ok.extra or {})["malformed_rows"] == 0
          and _preflight_with(ok).check("lead_in", {"denied_workloads": ["p2pool"]}).allowed,
          ok.status)
    only = WP.wsl_inventory(runner=_wsl_runner("123\t\t\n"))
    check("T16-15b. MUTATION: a PID whose name AND executable are both unreadable makes the "
          "required inventory ERROR -- it is unknown, not evidence of absence",
          only.status == WP.STATUS_ERROR and (only.extra or {})["malformed_rows"] == 1
          and not _preflight_with(only).check("lead_in",
                                              {"denied_workloads": ["p2pool"]}).allowed,
          (only.extra or {}).get("per_distribution"))
    mixed = WP.wsl_inventory(runner=_wsl_runner("1\tinit\t/sbin/init\n123\t\t\n"))
    check("T16-15c. MUTATION: one benign row does not rescue it",
          mixed.status == WP.STATUS_ERROR
          and not _preflight_with(mixed).check("lead_in",
                                               {"denied_workloads": ["p2pool"]}).allowed,
          mixed.status)
    bash_ok = WP.bash_inventory(runner=lambda a, **k: __import__("types").SimpleNamespace(
        returncode=0, stdout="1\tinit\t/sbin/init\n", stderr=""))
    bash_bad = WP.bash_inventory(runner=lambda a, **k: __import__("types").SimpleNamespace(
        returncode=0, stdout="123\t\t\n", stderr=""))
    check("T16-15d. the separate bash source applies the same rule",
          bash_ok.status == WP.STATUS_AVAILABLE and bash_bad.status == WP.STATUS_ERROR,
          (bash_ok.status, bash_bad.status))

    good = WP.wsl_distributions(runner=_wsl_runner(""))
    check("T16-15e. BASELINE: a valid header and valid rows enumerate normally",
          good[1] == WP.STATUS_AVAILABLE and [d["name"] for d in good[0]] == ["Ubuntu"],
          good[1])
    for label, text in (
            ("a missing header", "* Ubuntu   Running    2\n* Alt      Running    2\n"),
            ("an unrecognised header", "GARBAGE LINE\n* Ubuntu   Running    2\n"),
            ("a reordered header", "  STATE  NAME  VERSION\n* Ubuntu   Running    2\n")):
        rows, status, err = WP.wsl_distributions(runner=_wsl_runner("", text))
        check("T16-15f. MUTATION: %-24s refuses instead of silently dropping a "
              "distribution" % label,
              rows is None and status == WP.STATUS_ERROR and "header" in str(err), str(err)[:70])
    check("T16-15g. and the header is a declared constant, not an implicit skip",
          WP.WSL_LIST_HEADER == ("NAME", "STATE", "VERSION"), WP.WSL_LIST_HEADER)
    extra_field = WP.wsl_inventory(
        runner=_wsl_runner("1\tinit\t/sbin/init\n4242\tp2pool\t/usr/bin/p2pool\textra\n"))
    check("T16-15h. the Round-4 matrix is still green: one malformed row with an extra field "
          "still makes the distribution ERROR",
          extra_field.status == WP.STATUS_ERROR
          and (extra_field.extra or {})["malformed_rows"] == 1,
          (extra_field.extra or {}).get("malformed_excerpt"))
    denied = WP.wsl_inventory(
        runner=_wsl_runner("1\tinit\t/sbin/init\n4242\tp2pool\t/usr/bin/p2pool\n"))
    d = _preflight_with(denied).check("lead_in", {"denied_workloads": ["p2pool"]})
    check("T16-15i. and a DENIED name in a well-formed row still refuses, by equality on a "
          "normal form", denied.status == WP.STATUS_AVAILABLE and not d.allowed,
          d.summary()[:90])
    ok_name = _preflight_with(WP.wsl_inventory(
        runner=_wsl_runner("1\tinit\t/sbin/init\n4242\txmrigger\t/usr/bin/xmrigger\n"))
    ).check("lead_in", {"denied_workloads": ["xmrig"]})
    check("T16-15j. while a name that merely CONTAINS a denied name does not match",
          ok_name.allowed, ok_name.summary()[:90])
    check("T16-15k. NO distribution was enumerated, started, queried or stopped by this suite: "
          "every inventory above is a synthetic string", True,
          "synthetic runners only")


def test_r5_16_17_prospective_docs_and_grammar():
    text = RECORDER.read_declared(DESIGN_DOC, kind="design_note")
    interfaces = text[text.index("## 3. Interfaces, in one page"):
                      text.index("## 4. The non-circular verification boundary")]
    for stale in ("QualificationRunner(spec, collector, preflight).run(staging)",
                  "Collectors are injected",
                  "the single `launch_and_collect` callback",
                  "Injected Windows and WSL inventory providers"):
        check("T16-16. the INTERFACES section no longer describes %-42s as a current "
              "interface" % ("`" + stale[:38] + "`"),
              interfaces.count(stale) == 0, interfaces.count(stale))
    check("T16-16a. and where those phrases still appear they are inside a dated errata "
          "section that says they WERE wrong",
          text.count("QualificationRunner(spec, collector, preflight).run(staging)") == 0
          or "stale documentation" in text, "errata")
    check("T16-16b. and it describes exactly one production runner entry point, by its real "
          "signature", "run_authorized(spec_path" in text and "no callback" in text)
    check("T16-16c. the diagnostic boundary is stated explicitly alongside it",
          "diagnostic_dry_run" in text and "stops at the launch boundary" in text)
    check("T16-16d. the Round-5 errata section exists and names the reproduced cases",
          "## 1d. Corrections after the FIFTH corrective audit" in text
          and text.count("(R5-") >= 12, text.count("(R5-"))
    check("T16-16e. and the PARTIAL statement is still explicit, not quietly dropped",
          "Marked PARTIAL rather than broadened" in text
          and "os.path.getsize" in text)

    for label, value, want in (("lowercase", "a" * 64, True), ("UPPERCASE", "A" * 64, False),
                               ("mixed case", "aB" * 32, False), ("63 characters", "a" * 63,
                                                                  False)):
        check("T16-17. is_hex64 accepts %-12s exactly as its messages claim" % label,
              QS.is_hex64(value) is want and ENV._is_hex64(value) is want,
              (QS.is_hex64(value), ENV._is_hex64(value)))
    check("T16-17b. the runner's ordering documentation matches the implementation",
          "stage_authorized_code" in (RUN.__doc__ or "")
          and "final_launch_binding_recheck" in (RUN.__doc__ or "")
          and (RUN.__doc__ or "").index("preflight:pre_launch")
          < (RUN.__doc__ or "").index("final_launch_binding_recheck"))
    check("T16-17c. a byte count is labelled as bytes only where bytes were measured",
          "RAW BYTES" in (RUN._AuthorizedRun.launch_and_collect.__doc__ or "")
          and "exact byte streams" in (RP.ObservedCompletedProcess.__doc__ or ""),
          "runner and process-owning result both describe exact raw bytes")
    check("T16-17d. and the structure-only attestation checker cannot be mistaken for "
          "verification",
          "NOT AUTHENTICATION" in ENV.inspect_canonical_attestation_structure.__doc__
          and "authenticated" in ENV.verify_canonical_attestation.__doc__)


# ------------------------------------------------------------------ main
def main():
    for name in EXPECTED_TESTS:
        globals()[name]()
    functional = len(RESULTS)
    ids = list(EXPECTED_TESTS)
    check("T16-INV. the functional check count equals the pinned figure, so a deleted test "
          "cannot yield a smaller still-green n/n",
          functional == FUNCTIONAL_CHECK_COUNT,
          "%d functional checks, pinned at %d" % (functional, FUNCTIONAL_CHECK_COUNT))
    RECORDER.pin_test_inventory(ids, FUNCTIONAL_CHECK_COUNT, META_CHECK_COUNT)
    RECORDER.finish()
    failed = [r for r in RESULTS if not r["passed"]]
    doc = RECORDER.report(
        "round16", sys.argv[1:], tested_commit=ARG.get("--commit"),
        canonical=bool(ARG.get("--commit")), actual_test_ids=ids,
        actual_check_count=len(RESULTS),
        extra={"label": "ROUND 16 -- fifth corrective audit, behavioural closures",
               "non_evidence": True, "live": False,
               "authorises_no_live_run": True,
               "results": RESULTS, "total": len(RESULTS),
               "passed": len(RESULTS) - len(failed),
               "functional_check_count": functional,
               "meta_check_count": META_CHECK_COUNT,
               "non_evidence_note": ("green offline tests authorize no live run, no "
                                     "measurement and no design promotion")})
    if OUT:
        os.makedirs(os.path.dirname(os.path.abspath(OUT)) or ".", exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
    print("\n%d/%d passed%s" % (len(RESULTS) - len(failed), len(RESULTS),
                                (" -> " + OUT) if OUT else ""))
    if not doc.get("provenance_ok"):
        print("PROVENANCE PROBLEMS: %s" % doc.get("provenance_problems"))
    return 1 if failed or not doc.get("provenance_ok") else 0


if __name__ == "__main__":
    sys.exit(main())
