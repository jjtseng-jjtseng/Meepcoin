#!/usr/bin/env python3
"""Round-12 (third corrective revision): specification binding, authorization, the runner's
executable boundary, and the workload preflight.

NON-EVIDENCE, AND ENTIRELY NON-LIVE. No daemon, miner, driver, tracer, smoke, calibration,
qualification or network call. Every process inventory is a synthetic fixture; the only subprocess
is the qualification runner launching a synthetic pinned collector that prints one JSON line, and
that child carries the provenance shim so what it reads is observed rather than assumed.

EVERY ADVERSARIAL TEST FOLLOWS THE SAME SHAPE: prove the UNMUTATED baseline passes, then prove the
EXACT mutation fails FOR THE INTENDED REASON. A bare exception is never the assertion.

Tests this suite deliberately no longer contains, because they blessed unsafe behaviour:
  * "a pre-launch preflight refusal is reported even after collection ran" -- the order was wrong;
  * an AUTHORIZED clone with null thresholds and no external binding reaching a collector;
  * anything that accepted a caller-constructed FrozenSpec or a collector OBJECT as authority.

The counterexample matrix for the third corrective audit lives in node/tests_round14.py.

Green here means the infrastructure passed offline checks. It does not cadence-qualify the miner
and it authorises no measurement.

Usage: python3 node/tests_round12.py [--out=<path>] [--commit=<sha>]
"""
import ast
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_provenance as RP

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NODE = os.path.join(_REPO, "node")
# Started BEFORE any test module is imported. T12-0 proves that against sys.modules.
RECORDER = RP.ProvenanceRecorder(_REPO, strict=False).begin()
_MODULES_AT_BEGIN = frozenset(sys.modules)

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

EXPECTED_TESTS = (
    "test_0_start_order", "test_1_committed_draft", "test_2_substitution_is_detected",
    "test_3_authorization_record", "test_4_bind_is_the_only_producer",
    "test_5_runner_is_refusal_only", "test_6_executable_entry_point",
    "test_7_result_schema_is_typed", "test_8_preflight_floor_is_immutable",
    "test_9_preflight_never_kills_or_starts",
)
FUNCTIONAL_CHECK_COUNT = 127
META_CHECK_COUNT = 1

COLLECTOR = RP.CHILD_SHIM_SOURCE + '''import json, sys
a = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in sys.argv[1:] if "=" in x}
print(json.dumps({"raw_records": 6, "branch_observations": 25, "telemetry_retained": True,
                  "collection_seconds": 0.02, "staging_dir": a.get("--staging", ""),
                  "note": "synthetic fixture collector; it starts no daemon and opens no socket"}))
'''
EVALUATOR = '"""A synthetic evaluator. It evaluates nothing."""\nGATE = %r\n'


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


def spec_bytes():
    return RECORDER.read_declared(SPEC_PATH, kind="qualification_spec", mode="rb")


def draft_doc():
    return json.loads(spec_bytes().decode("utf-8"))


def refuses(fn, needle, cls=QS.SpecError):
    """(matched_intended_reason, message). A bare exception is not a pass."""
    try:
        fn()
        return False, "nothing was raised"
    except cls as e:
        return (needle in str(e)), "%s: %s" % (type(e).__name__, e)


def rewrite(doc, path):
    doc = dict(doc)
    for k in [k for k in doc if k.startswith("_")]:
        doc.pop(k)
    doc["gate_inventory_sha256"] = QS.gate_inventory_digest(doc["gates"])
    doc["binding_sha256"] = "0" * 64
    doc["binding_sha256"] = QS.full_binding_digest(doc)
    raw = (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    with open(path, "wb") as f:
        f.write(raw)
    return raw


def authorized_fixture(root, spec_id="TESTONLY_R12", mutate=None, mutate_authz=None):
    """A GENUINELY complete AUTHORIZED specification. Test-only, never committed; its collector
    starts nothing. Building it proves completeness is REACHABLE, so the refusals below are about
    the specific defect rather than about an impossible schema."""
    ar = os.path.join(root, "authz_root")
    os.makedirs(ar, exist_ok=True)
    draft = draft_doc()
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
        "run_identity": spec_id, "snapshot": {"id": "SNAP_TESTONLY", "sha256": "a" * 64},
        "schedule": {"order": ["control", "attack"]},
        "condition_order": ["control", "attack"], "replicates": 3,
        "rates": {"total": 1.5}, "durations": {"mine": 60.0, "post": 30.0},
        "ports": {"base": 41000, "count": 8}, "namespace": "testonly-r12",
        "refusal_policy": {"on_denied_workload": "refuse"},
        "required_envelope_roles": list(ENV.AUTHORIZED_REQUIRED_ROLES),
        "collector_binding": {"path": "collector.py", "sha256": QS.sha256_file(cpath),
                              "interpreter": _pinned_interpreter(), "dependencies": {}},
        "authorization_record": "authz.json", "evaluators": ev,
    })
    if mutate:
        mutate(d, ar)
    sp = os.path.join(ar, "spec.json")
    rewrite(d, sp)
    sdig = QS.sha256_file(sp)
    doc = json.loads(open(sp, encoding="utf-8").read())
    rec = {
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
    if mutate_authz:
        mutate_authz(rec)
    az = os.path.join(ar, "authz.json")
    with open(az, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, indent=1)
    return {"root": ar, "spec_path": sp, "spec_sha256": sdig, "collector_path": cpath,
            "inventory_sha256": doc["gate_inventory_sha256"],
            "binding_sha256": doc["binding_sha256"], "authz_path": az,
            "authz_sha256": QS.sha256_file(az), "doc": doc}


def bind(fx, **over):
    kw = {"spec_path": fx["spec_path"], "expect_file_sha256": fx["spec_sha256"],
          "expect_inventory_sha256": fx["inventory_sha256"],
          "expect_binding_sha256": fx["binding_sha256"],
          "authorization_path": fx["authz_path"],
          "expect_authorization_sha256": fx["authz_sha256"], "authorized_root": fx["root"]}
    kw.update(over)
    return QS.bind_authorized(**kw)


def clean_preflight():
    def win():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

    def runner(argv, **kw):
        class R:
            returncode = 0
            stderr = ""
        R.stdout = (("  NAME              STATE           VERSION\n"
                     "* Ubuntu            Running         2\n")
                    if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]
                    else "1\tinit\t/sbin/init\n")
        return R()

    return WP.WorkloadPreflight(providers={"windows": win,
                                           "wsl": lambda: WP.wsl_inventory(runner=runner)})


def dry_run(fx, stage, preflight=None, **over):
    """Drive the DIAGNOSTIC harness. It performs the complete production sequence and stops at
    the launch boundary: it creates no process and structurally cannot return a non-refused
    document. The real run_authorized owns the real Windows+WSL providers and takes no preflight
    at all, which is why a synthetic-inventory test necessarily uses this path (R4-1, 2A/2B)."""
    kw = {"spec_path": fx["spec_path"], "expect_spec_sha256": fx["spec_sha256"],
          "expect_inventory_sha256": fx["inventory_sha256"],
          "expect_binding_sha256": fx["binding_sha256"],
          "authorization_path": fx["authz_path"],
          "expect_authorization_sha256": fx["authz_sha256"],
          "authorized_root": fx["root"], "staging_dir": stage,
          "preflight": preflight or clean_preflight(),
          "guard_requires_absent": False}
    kw.update(over)
    return RUN.diagnostic_dry_run(**kw)


# ------------------------------------------------------------------ 0
def test_0_start_order():
    started_before = sorted(m for m in ("qual_spec", "qual_runner_v2", "workload_preflight",
                                        "evidence_envelope", "tests_round2")
                            if m in _MODULES_AT_BEGIN)
    check("T12-0. the provenance START observation preceded every target test module import "
          "(none of them were in sys.modules at that instant)",
          started_before == [] and RECORDER.start is not None
          and RECORDER.start["when"] == "start", started_before)
    check("T12-0b. and those modules are imported by the time the tests run",
          all(m in sys.modules for m in ("qual_spec", "qual_runner_v2")))


# ------------------------------------------------------------------ 1
def test_1_committed_draft():
    RECORDER.register_read(SPEC_PATH, kind="qualification_spec")
    d = QS.parse_spec(spec_bytes(), SPEC_PATH)
    check("T12-1. the committed specification is DRAFT_NO_LAUNCH",
          d["status"] == QS.STATUS_DRAFT, d["status"])
    check("T12-1b. it carries 17 gates, each with an index, a kind and an execution layer",
          len(d["gates"]) == 17
          and all(g["layer"] in QS.LAYERS and g["kind"] in QS.KINDS for g in d["gates"]),
          len(d["gates"]))
    check("T12-1c. every threshold is null",
          [g["id"] for g in d["gates"] if g.get("thresholds") is not None] == [])
    check("T12-1d. it declares no authorization record", d.get("authorization_record") is None)
    check("T12-1e. it is marked a PROVISIONAL CANDIDATE rather than a canonical inventory",
          d.get("provisional_candidate") is True)
    check("T12-1f. its declared digests equal the ones recomputed from its own bytes",
          d["_derived_gate_inventory_sha256"] == d["gate_inventory_sha256"]
          and d["_derived_binding_sha256"] == d["binding_sha256"])
    check("T12-1g. refusal_reason says a draft is a design document, not an authorisation",
          "not an authorisation" in (QS.refusal_reason(d) or ""),
          (QS.refusal_reason(d) or "")[:70])

    flipped = dict(d)
    flipped["status"] = QS.STATUS_AUTHORIZED
    nofail = QS.completeness_failures(flipped)
    check("T12-1h. flipping status alone leaves a long list of completeness failures",
          len(nofail) > 20, len(nofail))
    check("T12-1i. and without an authorized root completeness can NEVER return empty",
          any("presence is not validity" in f for f in nofail), nofail[-1][:60])
    with tempfile.TemporaryDirectory() as td:
        rooted = QS.completeness_failures(flipped, td)
        check("T12-1j. with a real root it still fails, on the operational fields the draft "
              "deliberately omits", len(rooted) >= 14, len(rooted))
    docs = os.path.join(_REPO, "docs")
    found = [f for _r, _d, fs in os.walk(docs) for f in fs
             if f.lower().startswith(("authz", "authoriz"))]
    check("T12-1k. and no authorization record exists anywhere under docs/", found == [], found)


# ------------------------------------------------------------------ 2
def test_2_substitution_is_detected():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        s = bind(fx)
        check("T12-2. BASELINE: the complete fixture binds",
              s.spec_id == "TESTONLY_R12" and s.bound_by_bind_authorized is True)

        for name, over, needle in (
                ("file digest", {"expect_file_sha256": "0" * 64}, "file sha256"),
                ("gate inventory digest", {"expect_inventory_sha256": "0" * 64},
                 "gate inventory sha256"),
                ("full binding digest", {"expect_binding_sha256": "0" * 64},
                 "full binding sha256"),
                ("authorization digest", {"expect_authorization_sha256": "0" * 64},
                 "authorization record sha256")):
            hit, msg = refuses(lambda o=over: bind(fx, **o), needle, QS.SpecError)
            check("T12-2b. a wrong %-22s is refused for the intended reason" % name, hit,
                  msg[:90])

        for name in ("expect_file_sha256", "expect_inventory_sha256", "expect_binding_sha256",
                     "expect_authorization_sha256", "authorized_root"):
            hit, msg = refuses(lambda n=name: bind(fx, **{n: None}), "supplied independently",
                               QS.AuthorizationError)
            check("T12-2c. omitting %-28s is refused: every pin is mandatory" % name, hit,
                  msg[:80])

        doc = json.loads(open(fx["spec_path"], encoding="utf-8").read())
        for name, mut, needle in (
                ("reorder", lambda g: list(reversed(g)), "reordered or renumbered"),
                ("rename", lambda g: [dict(x, title=x["title"] + "!") if i == 0 else x
                                      for i, x in enumerate(g)], "gate_inventory_sha256"),
                ("relayer", lambda g: [dict(x, layer=QS.LAYER_POST_SEAL) if i == 0 else x
                                       for i, x in enumerate(g)], "gate_inventory_sha256"),
                ("truncate", lambda g: g[:-1], "gate_inventory_sha256")):
            d2 = json.loads(json.dumps(doc))
            d2["gates"] = mut(d2["gates"])
            raw = (json.dumps(d2, indent=1) + "\n").encode("utf-8")
            hit, msg = refuses(lambda r=raw: QS.parse_spec(r, "fixture"), needle, QS.SpecError)
            check("T12-2d. a gate %-9s is detected by the inventory digest" % name, hit, msg[:80])

        moved = json.loads(json.dumps(doc))
        moved["gates"] = [dict(g, thresholds={"limit": 9.0}) for g in moved["gates"]]
        check("T12-2e. moving a THRESHOLD does not move the gate-identity digest",
              QS.gate_inventory_digest(moved["gates"])
              == QS.gate_inventory_digest(doc["gates"]))
        check("T12-2f. but it does move the gate-SEMANTICS digest, which the authorization "
              "record pins separately",
              QS.gate_semantics_digest(moved["gates"])
              != QS.gate_semantics_digest(doc["gates"]))
        check("T12-2g. and it moves the full binding digest too",
              QS.full_binding_digest(moved) != QS.full_binding_digest(doc))

        for field, value in (("snapshot", {"id": "OTHER", "sha256": "c" * 64}),
                             ("ports", {"base": 42000, "count": 8}),
                             ("namespace", "somethingelse"),
                             ("refusal_policy", {"on_denied_workload": "refuse",
                                                 "note": "changed"}),
                             ("replicates", 4), ("rates", {"total": 9.0}),
                             ("condition_order", ["attack", "control"])):
            d3 = json.loads(json.dumps(doc))
            d3[field] = value
            check("T12-2h. the binding digest covers %-16s" % field,
                  QS.full_binding_digest(d3) != QS.full_binding_digest(doc))


# ------------------------------------------------------------------ 3
def test_3_authorization_record():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        rec = QS.load_authorization_record(fx["authz_path"], fx["authz_sha256"])
        check("T12-3. BASELINE: the fixture's authorization record loads with every required pin",
              all(rec.get(f) not in (None, "", [], {}) for f in QS.AUTHZ_REQUIRED_PINS),
              sorted(set(QS.AUTHZ_REQUIRED_PINS) - set(rec)))
        doc = json.loads(open(fx["spec_path"], encoding="utf-8").read())
        doc["_spec_sha256"] = fx["spec_sha256"]
        doc["_derived_binding_sha256"] = doc["binding_sha256"]
        doc["_derived_gate_inventory_sha256"] = doc["gate_inventory_sha256"]
        doc["_derived_gate_semantics_sha256"] = QS.gate_semantics_digest(doc["gates"])
        check("T12-3b. and it cross-pins the specification with no disagreements",
              QS.cross_pin_failures(doc, rec) == [], QS.cross_pin_failures(doc, rec))

        clean = {k: v for k, v in rec.items() if not k.startswith("_")}
        for pin in QS.AUTHZ_REQUIRED_PINS:
            r2 = {k: v for k, v in clean.items() if k != pin}
            p = os.path.join(td, "az_%s.json" % pin)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(r2, f)
            hit, msg = refuses(lambda q=p: QS.load_authorization_record(q), "missing %s" % pin,
                               QS.AuthorizationError)
            check("T12-3c. an authorization record missing %-38s is refused" % pin, hit, msg[:70])

        p = os.path.join(td, "az_extra.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(dict(clean, surprise=1), f)
        hit, msg = refuses(lambda: QS.load_authorization_record(p), "unknown authorization field",
                           QS.AuthorizationError)
        check("T12-3d. an unknown authorization field is refused by the allowlist", hit, msg[:80])

        for label, mut, needle in (
                ("spec bytes", lambda r: r.update(authorizes_spec_sha256="9" * 64),
                 "approves spec bytes"),
                ("binding", lambda r: r.update(authorizes_binding_sha256="9" * 64),
                 "approves binding"),
                ("gate inventory",
                 lambda r: r.update(authorizes_gate_inventory_sha256="9" * 64),
                 "approves gate inventory"),
                ("gate semantics",
                 lambda r: r.update(authorizes_gate_semantics_sha256="9" * 64),
                 "a threshold moved"),
                ("roles", lambda r: r.update(
                    authorized_required_envelope_roles=["inner_collection"]), "approves roles"),
                ("evaluators", lambda r: r.update(authorized_evaluators={"G01": "9" * 64}),
                 "evaluator inventory"),
                ("collector", lambda r: r.update(
                    authorized_collector={"path": "other.py", "sha256": "9" * 64}),
                 "approves collector"),
                ("a launch-bearing value",
                 lambda r: r["authorized_launch_values"].update(replicates=99),
                 "launch-bearing field")):
            r3 = json.loads(json.dumps(clean))
            mut(r3)
            fails = QS.cross_pin_failures(doc, r3)
            check("T12-3e. a record disagreeing about %-22s is refused" % label,
                  any(needle in f for f in fails), (fails or ["nothing"])[:1])

        hit, msg = refuses(lambda: bind(fx, authorization_path=os.path.join(td, "nope.json")),
                           "", Exception)
        check("T12-3f. and a missing authorization record file is fatal, not a warning",
              "nothing was raised" not in msg, msg[:60])


# ------------------------------------------------------------------ 4
def test_4_bind_is_the_only_producer():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        s = bind(fx)
        check("T12-4. BASELINE: a bound specification records that bind_authorized produced it",
              s.bound_by_bind_authorized is True)
        forged = QS.FrozenSpec(dict(fx["doc"]), fx["spec_path"], fx["spec_sha256"],
                               fx["inventory_sha256"], "0" * 64, fx["binding_sha256"],
                               fx["authz_sha256"], fx["root"], "2026-01-01T00:00:00Z")
        check("T12-4b. a directly constructed one records that it did NOT, even with every field "
              "copied from a real bind", forged.bound_by_bind_authorized is False)
        check("T12-4c. and that marker is DEFENCE IN DEPTH, stated as such: the load-bearing "
              "control is that the executable entry point takes no object at all",
              "not a security boundary" in QS.__doc__)

        hit, msg = refuses(lambda: setattr(s, "spec_sha256", "z" * 64), "immutable", TypeError)
        check("T12-4d. a FrozenSpec refuses attribute mutation", hit, msg[:60])
        hit, msg = refuses(lambda: s["gates"][0].__setitem__("id", "X"), "", Exception)
        check("T12-4e. and its nested documents are frozen too",
              "nothing was raised" not in msg, msg[:60])

        before = s.spec_sha256
        with open(fx["spec_path"], "ab") as f:
            f.write(b"\n")
        check("T12-4f. mutating the file after a bind does not change what the bound object "
              "reports", s.spec_sha256 == before)
        hit, msg = refuses(lambda: bind(fx), "file sha256", QS.SpecError)
        check("T12-4g. and re-binding the mutated file is refused", hit, msg[:70])


# ------------------------------------------------------------------ 5
def test_5_runner_is_refusal_only():
    with tempfile.TemporaryDirectory() as td:
        d = QS.parse_spec(spec_bytes(), SPEC_PATH)
        r = RUN.RefusalOnlyRunner(d, guard_requires_absent=False)
        out = r.run(os.path.join(td, "never"))
        check("T12-5. the committed draft is refused as SPEC_NOT_AUTHORIZED",
              out["code"] == "SPEC_NOT_AUTHORIZED", out["code"])
        check("T12-5b. with zero launch-callback invocations and no directory created",
              out["launch_callback_invocations"] == 0
              and not os.path.exists(os.path.join(td, "never")))
        check("T12-5c. QualificationRunner is now the refusal-only class",
              RUN.QualificationRunner is RUN.RefusalOnlyRunner)

        fx = authorized_fixture(td)
        s = bind(fx)
        out2 = RUN.RefusalOnlyRunner(s, guard_requires_absent=False).run(
            os.path.join(td, "never2"))
        check("T12-5d. even a GENUINELY bound specification cannot launch through it",
              out2["code"] == "RUNNER_NOT_EXECUTABLE"
              and out2["launch_callback_invocations"] == 0, out2["code"])
        check("T12-5e. and the refusal points at the one executable entry point",
              "run_authorized" in out2["reason"], out2["reason"][:80])

        src = open(os.path.join(_NODE, "qual_runner_v2.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        pub = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)
               and not n.name.startswith("_")]
        check("T12-5f. there is no module-level function named collect", "collect" not in pub,
              sorted(pub))
        ra = [n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_authorized"][0]
        args = [a.arg for a in ra.args.args] + [a.arg for a in ra.args.kwonlyargs]
        check("T12-5g. and the executable entry point accepts no spec object, collector or "
              "runner callable",
              not any(a in args for a in ("spec", "collector", "runner", "callback")), args)
        check("T12-5h. its parameters are paths and external hashes",
              all(a in args for a in ("spec_path", "expect_spec_sha256", "authorization_path",
                                      "expect_authorization_sha256", "authorized_root")))
        cls = [n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "RefusalOnlyRunner"][0]
        proc = [c.func.attr for c in ast.walk(cls) if isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute)
                and c.func.attr in ("run", "Popen", "call", "check_output", "system", "execv")
                and isinstance(c.func.value, ast.Name)
                and c.func.value.id in ("subprocess", "os")]
        check("T12-5i. and the refusal-only class body contains no process-creation call",
              proc == [], proc)


# ------------------------------------------------------------------ 6
def test_6_executable_entry_point():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        stage = os.path.join(td, "stage_ok")
        good = dry_run(fx, stage)
        detail = good.get("detail") or {}
        check("T12-6. BASELINE: the complete fixture runs the whole sequence and stops exactly "
              "at the launch boundary",
              good.get("code") == "DIAGNOSTIC_ONLY" and good.get("diagnostic_only") is True,
              good.get("code"))
        check("T12-6b. the order is authorize -> lead-in -> staging -> PRE-LAUNCH -> final "
              "recheck, with the process inventory BEFORE the final byte check",
              good["event_sequence"] == ["authorization_check", "authorized:TESTONLY_R12",
                                         "preflight:lead_in", "prepare",
                                         "preflight:pre_launch",
                                         "final_launch_binding_recheck"],
              good["event_sequence"])
        check("T12-6c. the runner created its own staging root and said so",
              os.path.isdir(stage) and any("exclusive mkdir" in e
                                           for e in good["preparation_side_effects"]),
              good["preparation_side_effects"])
        check("T12-6d. the final recheck covers the spec, the authorization record, the "
              "INTERPRETER, the collector and all 17 evaluators",
              detail["final_recheck"]["files_rechecked"] == 22
              and detail["final_recheck"]["drift"] == []
              and "interpreter" in detail["final_recheck"]["labels"]
              and any(x.startswith("STAGED ")
                      for x in detail["final_recheck"]["labels"]),
              detail["final_recheck"]["files_rechecked"])
        check("T12-6e. the code that WOULD be launched is the runner's own staged copy, re-hashed "
              "after the final recheck",
              detail["staged_code"]["failures"] == []
              and detail["would_launch"][3].startswith(detail["staged_code"]["root"]),
              detail["staged_code"]["root"])
        check("T12-6e2. and argv[0] is the externally pinned interpreter",
              detail["would_launch"][0] == fx["doc"]["collector_binding"]["interpreter"]["path"])

        denied = WP.WorkloadPreflight(providers={
            "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                            [WP.ProcessRecord(1, "p2pool.exe", None,
                                                              "windows:Win32_Process")]),
            "wsl": clean_preflight().providers["wsl"]})
        s2 = os.path.join(td, "stage_lead_in")
        r2 = dry_run(fx, s2, preflight=denied)
        check("T12-6f. a LEAD-IN preflight refusal happens before any staging directory exists",
              r2["code"] == "PREFLIGHT_LEAD_IN" and not os.path.exists(s2)
              and r2["launch_callback_invocations"] == 0, r2["code"])

        class NotAPreflight:
            def check(self, stage_name, spec=None):   # pragma: no cover - never called
                return WP.PreflightResult(stage_name, True, [], [], [], [], [])

        r3 = RUN.diagnostic_dry_run(fx["spec_path"], fx["spec_sha256"], fx["inventory_sha256"],
                                    fx["binding_sha256"], fx["authz_path"], fx["authz_sha256"],
                                    fx["root"], os.path.join(td, "s3"), NotAPreflight(),
                                    guard_requires_absent=False)
        check("T12-6g. an injected object that is not a WorkloadPreflight is refused as "
              "NO_PREFLIGHT rather than trusted",
              r3["code"] == "NO_PREFLIGHT" and not os.path.exists(os.path.join(td, "s3")),
              r3["code"])

        s4 = os.path.join(td, "stage_exists")
        os.makedirs(s4)
        r4 = dry_run(fx, s4)
        check("T12-6h. an existing staging path is refused before the lead-in preflight",
              r4["code"] == "STAGING_EXISTS", r4["code"])

        fx2 = authorized_fixture(os.path.join(td, "drift"), spec_id="TESTONLY_DRIFT")
        with open(fx2["collector_path"], "a", encoding="utf-8") as f:
            f.write("\n# changed after the specification pinned it\n")
        r5 = dry_run(fx2, os.path.join(td, "drift", "stage"))
        check("T12-6i. a launch-bearing file that changed after it was pinned is refused",
              r5["code"] in ("SPEC_REFUSED", "LAUNCH_BEARING_DRIFT"), r5["code"])
        check("T12-6j. and the launch callback was never invoked",
              r5["launch_callback_invocations"] == 0)
        check("T12-6k. every refusal document carries the invocation count, so a reader can see "
              "for themselves that it is zero",
              all(x["launch_callback_invocations"] == 0 for x in (r2, r3, r4, r5)))


# ------------------------------------------------------------------ 7
def test_7_result_schema_is_typed():
    with tempfile.TemporaryDirectory() as td:
        fx = authorized_fixture(td)
        stage = os.path.join(td, "stage")
        good = dry_run(fx, stage)
        check("T12-7. BASELINE: the refusal document carries only allowlisted top-level keys",
              set(good) <= RUN.REFUSAL_ALLOWED_KEYS,
              sorted(set(good) - RUN.REFUSAL_ALLOWED_KEYS))
        okr = RUN.coerce_retained({"raw_records": 6, "branch_observations": 25,
                                   "telemetry_retained": True, "collection_seconds": 0.02,
                                   "staging_dir": stage, "note": "ok"}, staging_dir=stage)
        check("T12-7b. a well-formed collector result is accepted whole",
              okr[2] == [] and set(okr[0]) == set(RUN.RETAINED_SCHEMA), okr[2])

        kept, opaque, fails = RUN.coerce_retained(
            {"raw_records": 6, "an_unknown_key": {"smuggled": "payload"}},
            require_minimum=False)
        check("T12-7c. an unknown collector key never lands in a named field",
              "an_unknown_key" not in kept and fails == [], sorted(kept))
        check("T12-7d. it is confined to one untrusted STRING that cannot impersonate anything",
              isinstance(opaque, str) and "smuggled" in opaque, type(opaque).__name__)
        for (k, v), why in (((("raw_records"), "six"), "str for int"),
                            (("raw_records", True), "bool for int"),
                            (("telemetry_retained", 1), "int for bool"),
                            (("staging_dir", 3), "int for str"),
                            (("raw_records", -5), "negative count"),
                            (("branch_observations", -1), "negative count"),
                            (("collection_seconds", float("nan")), "NaN duration"),
                            (("collection_seconds", float("inf")), "infinite duration"),
                            (("staging_dir", "/somewhere/else"), "wrong staging path")):
            _kept, _o, f = RUN.coerce_retained({k: v}, staging_dir=stage)
            check("T12-7e. a %-18s in the collector result is refused" % why, f != [],
                  (f or ["nothing"])[:1])
        _k, _o, nan_fail = RUN.coerce_retained({"weird": float("nan")}, staging_dir=stage)
        check("T12-7e2. and unrecognised data that is not deterministically serialisable is "
              "refused rather than carried", nan_fail != [], (nan_fail or ["nothing"])[:1])

        hit, msg = refuses(lambda: RUN.assert_allowed_schema({"surprise": 1},
                                                             RUN.RESULT_ALLOWED_KEYS, "doc"),
                           "outside the allowlist", RUN.RunnerError)
        check("T12-7f. an unknown top-level result key is a refusal", hit, msg[:70])
        hit, msg = refuses(lambda: RUN.assert_engineering_only(
            {"retained": {"deep": {"series_valid": True}}}), "scientific vocabulary",
            RUN.RunnerError)
        check("T12-7g. and a scientific key nested at any depth is refused as defence in depth",
              hit, msg[:70])
        check("T12-7h. the module says plainly that its guards are not a proof, and that this "
              "library is API enforcement rather than an operating-system sandbox",
              "not a proof" in RUN.__doc__.lower()
              and "not an os sandbox" in RUN.__doc__.lower()
              and "root of trust" in RUN.__doc__.lower())
        check("T12-7i. the diagnostic document is explicitly marked diagnostic_only, so it can "
              "never be mistaken for an authorized run",
              good["diagnostic_only"] is True and good["refused"] is True)


# ------------------------------------------------------------------ 8
def test_8_preflight_floor_is_immutable():
    p = WP.WorkloadPreflight(providers={}, required_sources=("windows",))
    check("T12-8. a caller passing required_sources=('windows',) does NOT shrink the floor",
          set(WP.REQUIRED_SOURCES) <= set(p.required_sources), p.required_sources)
    p2 = WP.WorkloadPreflight(providers={}, required_sources=("windows", "extra"))
    check("T12-8b. a caller may EXTEND it", "extra" in p2.required_sources, p2.required_sources)
    p3 = WP.WorkloadPreflight(providers={}, denylist=("only_this",))
    check("T12-8c. and the denylist floor is likewise a floor, never a replacement",
          set(WP.normalize_name(n) for n in WP.DEFAULT_DENYLIST) <= p3.denylist)

    def win_ok():
        return WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(4, "System", None, "windows:Win32_Process")])

    def wsl_ok():
        return WP.Inventory("wsl:distributions", WP.STATUS_AVAILABLE,
                            [WP.ProcessRecord(1, "init", "/sbin/init", "wsl:Ubuntu:/proc")],
                            extra={"enumerated": [{"name": "Ubuntu", "state": "running"}],
                                   "per_distribution": {"Ubuntu": {"ok": True}}})

    ok = WP.WorkloadPreflight(providers={"windows": win_ok, "wsl": wsl_ok}).check("lead_in")
    check("T12-8d. BASELINE: two available required sources and nothing denied allows the stage",
          ok.allowed, ok.reasons)

    for label, provs in (
            ("a missing provider", {"windows": win_ok}),
            ("an ERROR inventory",
             {"windows": win_ok, "wsl": lambda: WP.Inventory("wsl:distributions",
                                                             WP.STATUS_ERROR, error="boom")}),
            ("an UNAVAILABLE inventory",
             {"windows": win_ok, "wsl": lambda: WP.Inventory("wsl:distributions",
                                                             WP.STATUS_UNAVAILABLE,
                                                             detail="nothing seen")}),
            ("a provider that raises",
             {"windows": win_ok, "wsl": lambda: (_ for _ in ()).throw(OSError("nope"))}),
            ("a provider returning the wrong type",
             {"windows": win_ok, "wsl": lambda: ["not", "an", "Inventory"]})):
        r = WP.WorkloadPreflight(providers=provs).check("lead_in")
        check("T12-8e. %-38s refuses the stage" % label, not r.allowed, r.reasons[:1])

    denied = WP.WorkloadPreflight(providers={
        "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                        [WP.ProcessRecord(1, "P2Pool.EXE",
                                                          "C:\\Tools\\P2Pool.EXE",
                                                          "windows:Win32_Process")]),
        "wsl": wsl_ok}).check("pre_launch")
    check("T12-8f. a denied workload is matched on the normal form, case and suffix included",
          not denied.allowed and denied.denied[0].normalized_name == "p2pool",
          denied.reasons[:1])
    notdenied = WP.WorkloadPreflight(providers={
        "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                        [WP.ProcessRecord(1, "xmrigger.exe",
                                                          "C:\\x\\xmrigger.exe",
                                                          "windows:Win32_Process")]),
        "wsl": wsl_ok}).check("lead_in")
    check("T12-8g. but matching is EQUALITY, so xmrigger is not xmrig", notdenied.allowed,
          notdenied.reasons)
    ambiguous = WP.WorkloadPreflight(providers={
        "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                        [WP.ProcessRecord(1, "xmrig-helper", None,
                                                          "windows:Win32_Process")]),
        "wsl": wsl_ok}).check("lead_in")
    check("T12-8h. and an unresolvable name containing a denied token refuses as AMBIGUOUS",
          not ambiguous.allowed and ambiguous.ambiguous, ambiguous.reasons[:1])
    cov = WP.WorkloadPreflight(providers={
        "windows": lambda: WP.Inventory("windows:Win32_Process", WP.STATUS_AVAILABLE,
                                        [WP.ProcessRecord(8, "WorkloadsSessionHost.exe", None,
                                                          "windows:Win32_Process")]),
        "wsl": wsl_ok}).check("lead_in")
    check("T12-8i. an NPU covariate is recorded and is never a blocker",
          cov.allowed and len(cov.covariates) == 1, cov.reasons)
    both, allowed = WP.WorkloadPreflight(providers={"windows": win_ok,
                                                    "wsl": wsl_ok}).check_both_stages()
    check("T12-8j. both stages are re-run from scratch over the same complete source set",
          allowed and [x.stage for x in both] == ["lead_in", "pre_launch"],
          [x.stage for x in both])


# ------------------------------------------------------------------ 9
def test_9_preflight_never_kills_or_starts():
    src = open(os.path.join(_NODE, "workload_preflight.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    banned = {"kill", "terminate", "send_signal", "killpg", "setpriority", "nice"}
    hits = [(n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
            for n in ast.walk(tree) if isinstance(n, ast.Call)
            and (n.func.attr if isinstance(n.func, ast.Attribute)
                 else getattr(n.func, "id", "")) in banned]
    check("T12-9. the preflight module contains no termination call, parsed rather than grepped",
          hits == [], hits)
    doc_node = tree.body[0].value if (tree.body and isinstance(tree.body[0], ast.Expr)
                                      and isinstance(tree.body[0].value, ast.Constant)) else None
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and isinstance(n.value, str) and n is not doc_node]
    cmds = [s[:40] for s in strings if "Stop-Process" in s or "taskkill" in s.lower()]
    check("T12-9b. and no shell command string that would terminate anything -- the module "
          "docstring may NAME them, no executable string may contain one", cmds == [], cmds)

    starts = []
    for n in ast.walk(tree):
        if isinstance(n, ast.List) and n.elts and isinstance(n.elts[0], ast.Name) \
                and n.elts[0].id == "WSL_EXE":
            starts.append([e.value for e in n.elts if isinstance(e, ast.Constant)])
    check("T12-9c. every wsl.exe invocation in the source is an enumeration or an explicit "
          "--exec query, and none of them starts a distribution",
          starts and all(("--list" in a) or ("--exec" in a) for a in starts), starts)
    # Behavioural, not a source-text search: drive the provider with a synthetic enumeration and
    # prove the stopped distribution is recorded and never asked anything.
    seen = []

    def runner(argv, **kw):
        seen.append(list(argv))

        class R:
            returncode = 0
            stderr = ""
        R.stdout = ("\n".join(["  NAME              STATE           VERSION",
                               "* Ubuntu            Running         2",
                               "  docker-desktop    Stopped         2", ""])
                    if argv[:3] == [WP.WSL_EXE, "--list", "--verbose"]
                    else "1\tinit\t/sbin/init\n")
        return R()

    inv = WP.wsl_inventory(runner=runner)
    queried = [a[2] for a in seen if a[:2] == [WP.WSL_EXE, "-d"]]
    check("T12-9d. a STOPPED distribution is enumerated, recorded and never queried -- querying "
          "it would start it",
          inv.extra["stopped_not_queried"] == ["docker-desktop"]
          and "docker-desktop" not in queried and queried == ["Ubuntu"],
          {"queried": queried, "stopped": inv.extra["stopped_not_queried"]})
    doc = WP.write_refusal.__doc__ or ""
    check("T12-9e. and the refusal document records that nothing was terminated or started",
          "NO result bundle is created" in doc and "started_anything" in src)


# ------------------------------------------------------------------ main
def main():
    print("ROUND 12 -- specification, authorization, runner boundary, preflight. NON-LIVE.\n")
    for name in EXPECTED_TESTS:
        print("[%s]" % name)
        globals()[name]()
    functional = len(RESULTS)
    check("T12-INV. the functional check count equals the pinned figure, so a deleted test "
          "cannot yield a smaller still-green n/n",
          functional == FUNCTIONAL_CHECK_COUNT,
          "%d functional checks, pinned at %d" % (functional, FUNCTIONAL_CHECK_COUNT))

    RECORDER.pin_test_inventory(EXPECTED_TESTS, FUNCTIONAL_CHECK_COUNT,
                                meta_check_count=META_CHECK_COUNT)
    RECORDER.finish()
    passed = sum(1 for r in RESULTS if r["passed"])
    doc = RECORDER.report(
        "round12", sys.argv, tested_commit=ARG.get("--commit"),
        canonical=bool(ARG.get("--commit")), actual_test_ids=list(EXPECTED_TESTS),
        actual_check_count=len(RESULTS),
        extra={"label": "NON-EVIDENCE offline infrastructure tests",
               "authorises_no_live_run": True, "passed": passed, "total": len(RESULTS),
               "results": RESULTS})
    print("\nROUND 12: %d/%d" % (passed, len(RESULTS)))
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
