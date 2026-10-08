#!/usr/bin/env python3
"""Round-11 harness tests: the environment trace is a shape, not a verdict.

NON-EVIDENCE. These validate the harness, never the protocol.

node/env_trace.py records what else the machine was doing while a run happened. That is useful
context and a standing hazard: a trace that is allowed to condemn a measurement becomes an
after-the-fact filter, and an after-the-fact filter is how a null result quietly becomes a
positive one. The rule is therefore split and both halves are tested here:

  STRUCTURE is a gate     rows on the 5 s cadence, a 30 s lead-in before launch, a 30 s lead-out
                          after cleanup, every metric carrying an explicit status
  VALUES are covariates   nothing observed may exclude a record, invalidate a replicate or
                          authorise a rerun

Test 8 is the load-bearing one: every measured value in a passing trace is replaced with garbage
and the verifier still passes it, which is what "the verifier cannot read values" has to mean if
it is going to be believed.

Test 10 takes ONE real ~70 s trace of this machine. It launches no workload and stops nothing.

Usage: python3 node/tests_round11.py [--out=docs/round2/tests_round11.json] [--real=1]
"""
import ast, copy, json, os, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env_trace as ET
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round11.json")
REAL = ARG.get("--real", "1") == "1"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def metric(status="available", value=1, detail="reason"):
    return {"status": status, "value": value if status == "available" else None,
            "source": "synthetic", "detail": None if status == "available" else detail}


def synth(n=20, launch_index=7, cleanup_index=12, interval=ET.INTERVAL_S, t0=1000.0):
    """A well-formed trace: 7 rows of lead-in (35 s) and 7 of lead-out (35 s) around the run."""
    rows = []
    for i in range(n):
        r = {"index": i, "scheduled_mono": t0 + i * interval,
             "scheduled_utc": "2026-08-27T00:%02d:%02dZ" % divmod(int(i * interval), 60),
             "actual_mono": t0 + i * interval + 0.01, "actual_wall": 1.0 + i * interval,
             "actual_utc": "2026-08-27T00:%02d:%02dZ" % divmod(int(i * interval), 60),
             "lateness_s": 0.01, "completed_mono": t0 + i * interval + 0.5,
             "sample_duration_s": 0.49}
        for k in ET.REQUIRED_METRICS:
            r[k] = metric()
        rows.append(r)
    return {"kind": "environment_trace", "non_evidence": True, "label": "synthetic",
            "policy": {"structure_is_a_gate": True, "values_are_covariates_only": True,
                       "may_exclude_a_record": False, "may_authorise_a_rerun": False},
            "interval_s": interval, "required_lead_in_s": ET.LEAD_IN_S,
            "required_lead_out_s": ET.LEAD_OUT_S,
            "t0_mono": t0, "t0_wall": 1.0, "t0_utc": "2026-08-27T00:00:00Z",
            "windows_sampler_start_error": None,
            "markers": [{"name": "launch", "mono": t0 + launch_index * interval, "wall": 1.0,
                         "utc": "2026-08-27T00:00:35Z"},
                        {"name": "cleanup", "mono": t0 + cleanup_index * interval, "wall": 1.0,
                         "utc": "2026-08-27T00:01:00Z"}],
            "row_count": n, "rows": rows}


def rejects(doc, needle):
    f = ET.verify_trace(doc)
    return any(needle in x for x in f), f


# ------------------------------------------------------------------ 1. the baseline
def test_1_baseline():
    f = ET.verify_trace(synth())
    check("T11-1. a well-formed synthetic trace passes the structure gate", not f, f[:3])
    d = synth()
    check("T11-1b. it really does carry all %d required metrics on every row"
          % len(ET.REQUIRED_METRICS),
          all(k in r for r in d["rows"] for k in ET.REQUIRED_METRICS),
          sorted(set(ET.REQUIRED_METRICS) - set(d["rows"][0])))


# ------------------------------------------------------------------ 2. cadence
def test_2_cadence_gaps():
    d = synth()
    del d["rows"][9]
    d["row_count"] = len(d["rows"])
    for i, r in enumerate(d["rows"]):
        r["index"] = i
    hit, f = rejects(d, "not 5.0s")
    check("T11-2. a dropped row leaves a double-length gap and is REJECTED", hit, f[:2])

    d = synth()
    d["rows"][4]["index"] = 99
    hit, f = rejects(d, "declares index")
    check("T11-2b. a renumbered row is REJECTED", hit, f[:2])

    d = synth()
    d["interval_s"] = 10.0
    hit, f = rejects(d, "!= the required 5.0s")
    check("T11-2c. a trace taken at the wrong cadence is REJECTED", hit, f[:2])

    d = synth()
    d["row_count"] = 3
    hit, f = rejects(d, "row_count")
    check("T11-2d. a stated row_count that disagrees with the rows is REJECTED", hit, f[:2])


# ------------------------------------------------------------------ 3. lateness
def test_3_lateness():
    d = synth()
    d["rows"][6]["actual_mono"] = d["rows"][6]["scheduled_mono"] + 6.0
    d["rows"][6]["lateness_s"] = 6.0
    hit, f = rejects(d, "lost a slot")
    check("T11-3. a row a full cadence interval late is REJECTED as a lost slot", hit, f[:2])

    d = synth()
    d["rows"][6]["lateness_s"] = 0.0            # forged to look punctual
    d["rows"][6]["actual_mono"] += 3.0
    hit, f = rejects(d, "!= actual - scheduled")
    check("T11-3b. a forged lateness that contradicts the two times is REJECTED", hit, f[:2])

    d = synth()
    d["rows"][6]["actual_mono"] = d["rows"][6]["scheduled_mono"] - 1.0
    d["rows"][6]["lateness_s"] = -1.0
    hit, f = rejects(d, "before it was scheduled")
    check("T11-3c. a row taken before its slot is REJECTED", hit, f[:2])

    d = synth()
    d["rows"][3].pop("actual_utc")
    hit, f = rejects(d, "has no actual_utc")
    check("T11-3d. a row missing its actual UTC stamp is REJECTED", hit, f[:2])


# ------------------------------------------------------------------ 4. never substitute zero
def test_4_no_zero_substitution():
    for k in ("npu", "windows_cpu_percent", "wsl_cpu_percent"):
        d = synth()
        d["rows"][5][k] = {"status": "unavailable", "value": 0, "source": "s", "detail": "why"}
        hit, f = rejects(d, "must not be filled in")
        check("T11-4. %s reported unavailable but carrying 0 is REJECTED" % k, hit, f[:2])

        d = synth()
        d["rows"][5][k] = {"status": "available", "value": None, "source": "s", "detail": None}
        hit, f = rejects(d, "claims to be available but carries no value")
        check("T11-4b. %s claiming available with no value is REJECTED" % k, hit, f[:2])

    d = synth()
    d["rows"][2]["npu"] = {"status": "missing", "value": None, "source": "s", "detail": "x"}
    hit, f = rejects(d, "is not one of")
    check("T11-4c. an invented status is REJECTED", hit, f[:2])

    d = synth()
    d["rows"][2]["npu"] = {"status": "unavailable", "value": None, "source": "s", "detail": ""}
    hit, f = rejects(d, "without a reason")
    check("T11-4d. an unavailable metric with no stated reason is REJECTED", hit, f[:2])

    for k in ET.REQUIRED_METRICS:
        d = synth()
        d["rows"][1].pop(k)
        hit, f = rejects(d, "has no %s envelope" % k)
        check("T11-4e. a row missing its %s envelope is REJECTED" % k, hit, f[:1])


# ------------------------------------------------------------------ 5/6. lead-in and lead-out
def test_5_lead_in_and_out():
    d = synth(launch_index=4)                   # only 20 s of lead-in
    hit, f = rejects(d, "less than the required 30.0s")
    check("T11-5. a trace starting under 30 s before launch is REJECTED", hit, f[:2])

    d = synth(cleanup_index=16)                 # only 15 s of lead-out
    hit, f = rejects(d, "less than the required 30.0s")
    check("T11-5b. a trace ending under 30 s after cleanup is REJECTED", hit, f[:2])

    d = synth(launch_index=6, cleanup_index=13)
    check("T11-5c. exactly 30 s of lead-in and lead-out is enough",
          not ET.verify_trace(d), ET.verify_trace(d)[:2])

    d = synth()
    d["markers"] = [m for m in d["markers"] if m["name"] != "cleanup"]
    hit, f = rejects(d, "records no 'cleanup' marker")
    check("T11-5d. a trace with no cleanup marker is REJECTED", hit, f[:2])

    d = synth()
    d["markers"][1]["mono"] = d["markers"][0]["mono"] - 1
    hit, f = rejects(d, "is before")
    check("T11-5e. cleanup before launch is REJECTED", hit, f[:2])


def test_6_policy_declaration():
    d = synth()
    d["policy"]["may_exclude_a_record"] = True
    hit, f = rejects(d, "covariates only")
    check("T11-6. a trace claiming it may exclude a record is REJECTED", hit, f[:2])

    d = synth()
    d["policy"]["may_authorise_a_rerun"] = True
    hit, f = rejects(d, "covariates only")
    check("T11-6b. a trace claiming it may authorise a rerun is REJECTED", hit, f[:2])

    d = synth()
    d["kind"] = "something_else"
    hit, f = rejects(d, "is not an environment_trace")
    check("T11-6c. a document of the wrong kind is REJECTED", hit, f[:2])

    d = synth()
    d["rows"] = []
    hit, f = rejects(d, "carries no rows")
    check("T11-6d. an empty trace is REJECTED", hit, f[:2])


# ------------------------------------------------------------------ 7. bad shapes, one file
def test_7_file_level():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "t.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(synth(), f)
        check("T11-7. verify_trace accepts a path as well as a document",
              not ET.verify_trace(p), ET.verify_trace(p)[:2])
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not json")
        f2 = ET.verify_trace(p)
        check("T11-7b. an unreadable trace file is REJECTED, not skipped",
              bool(f2) and "could not be read" in f2[0], f2[:1])


# ------------------------------------------------------------------ 8. values cannot gate
def test_8_values_are_never_read():
    d = synth()
    poison = [0, -1, 10 ** 9, "", "n/a", None, [], {}, {"total": 0}, float("inf")]
    for i, r in enumerate(d["rows"]):
        for j, k in enumerate(ET.REQUIRED_METRICS):
            r[k]["value"] = poison[(i + j) % len(poison)]
            if r[k]["value"] is None:            # None would trip the available-without-value
                r[k]["value"] = 0                # rule, which is a STATUS rule, not a value one
    f = ET.verify_trace(d)
    check("T11-8. replacing EVERY measured value with garbage still passes the structure gate "
          "-- the verifier cannot read values, so it cannot be made to reject a row for what it "
          "observed", not f, f[:3])

    src = open(os.path.join(REPO, "node/env_trace.py"), encoding="utf-8").read()
    body = src[src.index("def verify_trace("):src.index("def _wait_for_slot(")]
    check("T11-8b. and verify_trace's body never dereferences a metric value",
          '["value"]' not in body and ".get(\"value\")" in body
          and body.count(".get(\"value\")") == 2,
          body.count(".get(\"value\")"))


# ------------------------------------------------------------------ 9. read-only by inspection
def test_9_tracer_is_read_only():
    src = open(os.path.join(REPO, "node/env_trace.py"), encoding="utf-8").read()
    forbidden = ("Stop-Process", "taskkill", "os.kill", "SIGKILL", "SIGTERM",
                 "ProcessorAffinity", "PriorityClass", "Set-ItemProperty", "powercfg",
                 "Set-Service", "Stop-Service", "shutdown")
    hits = [w for w in forbidden if w in src]
    check("T11-9. the tracer contains no call that could stop or reprioritise anything",
          not hits, hits)
    check("T11-9b. the only process it ever terminates is its own PowerShell helper",
          src.count("self.proc.terminate()") == 1 and "self.proc.kill" not in src,
          src.count("self.proc.terminate()"))
    check("T11-9c. it opens exactly one file for writing: its own output",
          src.count('open(self.out_path, "w"') == 1
          and src.count(', "w", encoding') == 1, src.count(', "w", encoding'))
    check("T11-9d. the NPU attribution is labelled a heuristic in the trace itself",
          "HEURISTIC:" in src and "is NOT guessed" in src)
    wrap = src[src.index("def _wrap("):src.index("def _wait_for_slot(")]
    check("T11-9e. --wrap reports the trace verdict and the command's exit status separately",
          "TRACE STRUCTURE" in wrap and "WRAPPED COMMAND EXIT" in wrap
          and "return rc if rc is not None else 1" in wrap, None)
    # a blunt text search would trip over `for f in fails` -- a loop over failure messages is
    # not a retry. The precise property is that the wrapped command is invoked exactly once and
    # not from inside any loop, so the function is parsed instead of grepped.
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_wrap")
    calls, in_loop = [], []

    def walk(node, loops):
        for ch in ast.iter_child_nodes(node):
            deeper = loops + [ch] if isinstance(ch, (ast.For, ast.While, ast.AsyncFor)) else loops
            if isinstance(ch, ast.Call):
                nm = ast.unparse(ch.func)
                if nm in ("subprocess.call", "subprocess.run", "subprocess.Popen",
                          "subprocess.check_call", "os.system"):
                    calls.append(nm)
                    if loops:
                        in_loop.append(nm)
            walk(ch, deeper)

    walk(fn, [])
    check("T11-9f. --wrap invokes the wrapped command exactly once, and never from a loop",
          calls == ["subprocess.call"] and not in_loop, [calls, in_loop])
    check("T11-9g. and it says so in its own output, so a reader cannot mistake the two",
          "never authorises a rerun" in wrap and "neither validates nor " in wrap
          and "invalidates the command" in wrap)


# ------------------------------------------------------------------ 10. one real trace
def test_10_real_trace():
    if not REAL:
        check("T11-10. real trace SKIPPED (--real=0)", True, "skipped by request")
        return
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "real.json")
        t0 = time.time()
        r = subprocess.run([sys.executable, "-B", os.path.join(REPO, "node/env_trace.py"),
                            "--out=" + p, "--seconds=5", "--lead=31", "--label=T11"],
                           capture_output=True, text=True, timeout=300)
        took = time.time() - t0
        check("T11-10. a real ~70 s trace of this machine completes and passes its structure gate",
              r.returncode == 0 and "STRUCTURE: PASS" in r.stdout,
              [r.returncode, r.stdout.strip().splitlines()[-1:], r.stderr[-200:]])
        doc = json.load(open(p, encoding="utf-8"))
        check("T11-10b. it took roughly the expected time, so the cadence was not skipped",
              60 <= took <= 200 and doc["row_count"] >= 14, [round(took, 1), doc["row_count"]])
        statuses = {}
        for row in doc["rows"]:
            for k in ET.REQUIRED_METRICS:
                statuses.setdefault(k, set()).add(row[k]["status"])
        check("T11-10c. every required metric was reported with a legal status on every row",
              all(s <= set(ET.STATUSES) for s in statuses.values()),
              {k: sorted(v) for k, v in statuses.items()})
        first = doc["rows"][0]["wsl_cpu_percent"]
        check("T11-10d. the FIRST row's WSL CPU is unavailable, not 0 -- there is no previous "
              "tick to difference against and the trace says so",
              first["status"] == "unavailable" and first["value"] is None
              and "previous tick" in (first["detail"] or ""), first)
        npu = doc["rows"][-1]["npu"]
        check("T11-10e. the NPU metric is either attributed with its owning pid or explicitly "
              "unavailable with a reason -- never a bare zero",
              (npu["status"] == "available" and "busiest_pid" in (npu["value"] or {})
               and "HEURISTIC" in (npu["source"] or ""))
              or (npu["status"] in ("unavailable", "error") and npu["value"] is None
                  and bool(npu["detail"])),
              {k: npu[k] for k in ("status", "source")})
        watched = doc["rows"][-1]["watched_processes"]["value"]
        absent = [w["name"] for w in watched if w["status"] == "not_running"]
        check("T11-10f. a process that is not running is reported as not_running, never as 0 CPU",
              all(w["instances"] == [] for w in watched if w["status"] == "not_running"),
              absent)
        unread = [i for w in watched for i in w.get("instances", [])
                  if i["cpu_seconds_status"] != "available"]
        check("T11-10g. a process whose CPU time this session cannot read says so and carries "
              "no number", all(i["cpu_seconds"] is None and i["cpu_seconds_detail"]
                               for i in unread), len(unread))
        check("T11-10h. the run's own driver and daemons are looked for by RESOLVED exe path",
              doc["rows"][0]["wsl_process_inventory"]["status"] == "available"
              and "truncates at 15" in
              (doc["rows"][0]["wsl_process_inventory"]["detail"] or ""),
              doc["rows"][0]["wsl_process_inventory"]["detail"])


def main():
    print("NON-EVIDENCE round-11 harness tests: environment-trace structure, never a verdict\n")
    for fn in (test_1_baseline, test_2_cadence_gaps, test_3_lateness,
               test_4_no_zero_substitution, test_5_lead_in_and_out, test_6_policy_declaration,
               test_7_file_level, test_8_values_are_never_read, test_9_tracer_is_read_only,
               test_10_real_trace):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round11", sys.argv, False,
                                       CORE_SOURCES + ("node/env_trace.py",
                                                       "node/tests_round11.py")),
                       real_trace_taken=REAL,
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
