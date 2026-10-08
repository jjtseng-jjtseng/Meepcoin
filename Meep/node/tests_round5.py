#!/usr/bin/env python3
"""Round-5 harness tests: topology conformance and branch readability are SEPARATE measurements.

NON-EVIDENCE. These validate the harness, never the protocol.

The defect being closed: Sampler.run() performed every branch view first and then the topology
snapshot inside ONE try, whose broad except marked any failure `topology_conformant=False`. A
canonical read spanning a reorganisation was therefore reported as topology drift --
results/SMOKE_20260815_gateC4 was invalidated as INVALID_TOPOLOGY_DRIFT for a run whose topology
never drifted (full mesh, nothing forbidden, links up throughout; the single bad sample failed with
"InconsistentView: prev_hash break at height 603" before topology was ever measured).

Policy under test (OPERATIONAL_PREREGISTRATION.md section 9):
  1  topology conformance      zero tolerance, measured independently and first
  2  branch-view readability   <=2 unreadable per phase AND >=90% readable AND >=10 readable
  3  an unreadable branch view is never a topology verdict
  4  an unreadable branch view is never same-tip/lag/fork/PARTITION/RECOVERY; it breaks streaks
  5  exceeding the branch limits is INVALID_BRANCH_EVIDENCE_COVERAGE, never topology drift

Usage: python3 node/tests_round5.py [--out=docs/round2/tests_round5.json]
"""
import json, os, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import branch_evidence as BE
import coverage as COV
import sample_verify as SAMPV
import series_validate as SV
import symmetric_series as SS
import topology as T
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import full_record, resync_coverage

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round5.json")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAXU, MINF, MINS = (SS.BRANCH_MAX_UNREADABLE, SS.BRANCH_MIN_FRACTION, SS.BRANCH_MIN_SAMPLES)


# --------------------------------------------------------------------------- sampler drive
class StubDaemon:
    def __init__(self, name):
        self.name, self.rpc = name, f"http://127.0.0.1:1/{name}"


def drive_one_sample(node_view_impl, snapshot_impl, conformance_impl):
    """Run the REAL Sampler for exactly one scheduled sample with injected observations."""
    ds = {n: StubDaemon(n) for n in ("h1", "h2", "atk")}
    orig = (BE.node_view, T.snapshot, T.conformance)
    BE.node_view, T.snapshot, T.conformance = node_view_impl, snapshot_impl, conformance_impl
    try:
        stop = threading.Event()
        # C: the sampler now takes the ONE sealed schedule instead of a phase name
        clock = SS.PhaseClock(time.monotonic(), 3600.0)
        samp = SS.Sampler(ds, ds, 31, stop, clock)
        samp.start()
        for _ in range(200):                      # first sample is taken immediately
            if samp.samples:
                break
            time.sleep(0.02)
        stop.set()
        samp.join(timeout=10)
        return samp.samples[0] if samp.samples else None
    finally:
        BE.node_view, T.snapshot, T.conformance = orig


def healthy_view(d, start_height, retries=2):
    return {"height": 40, "tip": "a" * 64, "attempts": 1, "anchor_height": 30,
            "anchor_hash": "z" * 64, "tip_cumulative_difficulty": 100,
            "canonical": [], "anchored": [], "canonical_hashes": [],
            "anchored_hashes": ["z" * 64, "a" * 64], "alt_block_hashes": []}


def healthy_snapshot(nodes):
    return {"undirected_links": [("atk", "h1"), ("atk", "h2"), ("h1", "h2")],
            "adjacency": {}, "raw_rows": [], "rpc_errors": [], "unresolved": [],
            "raw_connection_counts": {"h1": 2, "h2": 2, "atk": 2}}


def conf_ok(adj, names, topo):
    return {"conformant": True, "missing": [], "forbidden_present": [],
            "non_conformance_reasons": []}


def test_1_branch_failure_is_not_topology_failure():
    def bad_view(d, start_height, retries=2):
        e = BE.InconsistentView("view still inconsistent after 2 retries: "
                                "prev_hash break at height 603")
        e.attempts, e.retries = 3, 2
        raise e
    s = drive_one_sample(bad_view, healthy_snapshot, conf_ok)
    check("E1. an unreadable branch view leaves topology CONFORMANT",
          s is not None and s.get("topology_observed") is True
          and s.get("topology_conformant") is True,
          None if s is None else [s.get("topology_observed"), s.get("topology_conformant")])
    check("E1b. the same sample is marked branch_readable=False with a typed error",
          s is not None and s.get("branch_readable") is False
          and "InconsistentView" in (s.get("branch_error") or "")
          and "prev_hash break" in (s.get("branch_error") or ""),
          None if s is None else s.get("branch_error"))
    check("E1c. the retry count and phase travel with the failed sample",
          s is not None and s.get("branch_attempts") == 3 and s.get("branch_retries") == 2
          and s.get("phase") == "mining" and s.get("scheduled_mono") is not None,
          None if s is None else [s.get("branch_attempts"), s.get("branch_retries")])
    check("E1d. no branch verdict is invented for an unread sample",
          s is not None and s.get("all_same_tip") is None
          and s.get("h1_h2_genuinely_forked") is None and s.get("tips") is None,
          None if s is None else [s.get("all_same_tip"), s.get("h1_h2_genuinely_forked")])
    check("E1e. the topology measurement itself is retained, not discarded",
          s is not None and s.get("links") and s.get("topology_error") is None,
          None if s is None else s.get("links"))


def test_2_real_topology_failures_still_fail():
    cases = {
        "a missing required edge": ({"conformant": False, "missing": [("h1", "h2")],
                                     "forbidden_present": [],
                                     "non_conformance_reasons": ["missing h1-h2"]}, None),
        "a forbidden edge": ({"conformant": False, "missing": [],
                              "forbidden_present": [("atk", "h2")],
                              "non_conformance_reasons": ["forbidden atk-h2"]}, None),
        "an unresolved active peer": ({"conformant": False, "missing": [],
                                       "forbidden_present": [],
                                       "non_conformance_reasons": ["unresolved peer"]}, None),
    }
    for label, (conf, _) in cases.items():
        s = drive_one_sample(healthy_view, healthy_snapshot,
                             lambda a, n, t, _c=conf: _c)
        check(f"E2. {label} is a topology FAILURE even with a readable branch view",
              s is not None and s.get("topology_conformant") is False
              and s.get("branch_readable") is True,
              None if s is None else [s.get("topology_conformant"), s.get("branch_readable")])

    def boom_snapshot(nodes):
        raise RuntimeError("injected topology RPC failure")
    s = drive_one_sample(healthy_view, boom_snapshot, conf_ok)
    check("E2d. a topology RPC failure fails CLOSED as nonconformant",
          s is not None and s.get("topology_observed") is False
          and s.get("topology_conformant") is False
          and "injected topology RPC failure" in (s.get("topology_error") or ""),
          None if s is None else s.get("topology_error"))
    check("E2e. a topology RPC failure does not damage a readable branch view",
          s is not None and s.get("branch_readable") is True,
          None if s is None else s.get("branch_readable"))


# --------------------------------------------------------------------------- coverage policy
def phase_samples(n_total, n_unreadable, phase="mining"):
    out = []
    for i in range(n_total):
        unread = i < n_unreadable
        out.append({"phase": phase, "topology_observed": True, "topology_conformant": True,
                    "branch_readable": not unread,
                    "branch_error": "InconsistentView: x" if unread else None,
                    "all_same_tip": None if unread else True,
                    "h1_h2_genuinely_forked": None if unread else False})
    return out


def cov_for(n_mining, u_mining, n_post, u_post, mine_s=900.0, post_s=420.0):
    samples = phase_samples(n_mining, u_mining, "mining") + \
        phase_samples(n_post, u_post, "post_stop")
    return COV.branch_evaluate(samples, mine_s, post_s, 15.0, MAXU, MINF, MINS)


def test_3_4_5_thresholds():
    # measured shape: 900/15 = 60 mining samples, 420/15 = 28 post_stop samples
    for u in (0, 1, 2):
        r = cov_for(60, u, 28, u)
        check(f"E3. measured phases with {u} unreadable pass all three limits",
              r["adequate"] is True, r["failures"])
    r = cov_for(60, 3, 28, 3)
    check("E3d. three unreadable always fails", r["adequate"] is False, r["failures"][:2])
    check("E3e. it fails on the max-unreadable rule by name",
          any("unreadable branch samples > allowed" in f for f in r["failures"]),
          r["failures"][:2])

    # 12-sample phase: two unreadable is within max_unreadable but breaks the 90% rule
    r = cov_for(12, 2, 28, 0)
    check("E4. in a 12-sample phase two unreadable fails the 90% rule",
          r["adequate"] is False
          and any("readable fraction" in f and f.startswith("mining") for f in r["failures"]),
          r["failures"][:2])
    check("E4b. and one unreadable in a 12-sample phase still passes",
          cov_for(12, 1, 28, 0)["adequate"] is True, cov_for(12, 1, 28, 0)["failures"])

    # the smoke's actual shape: 13 mining, 12 post_stop
    check("E4c. the 180+180 smoke shape tolerates exactly one unreadable per phase",
          cov_for(13, 1, 12, 1)["adequate"] is True
          and cov_for(13, 2, 12, 0)["adequate"] is False,
          [cov_for(13, 1, 12, 1)["failures"], cov_for(13, 2, 12, 0)["failures"][:1]])

    # the 10-readable floor governs when a phase is small
    r = cov_for(10, 1, 28, 0)
    check("E5. a phase with only 9 readable fails the 10-sample floor",
          r["adequate"] is False and any("< floor 10" in f for f in r["failures"]),
          r["failures"][:2])
    check("E5b. 60 and 28 expected: two unreadable passes, three fails",
          cov_for(60, 2, 28, 2)["adequate"] is True
          and cov_for(60, 3, 28, 3)["adequate"] is False)
    check("E5c. a post_stop failure alone is enough to fail the record",
          cov_for(60, 0, 28, 3)["adequate"] is False,
          cov_for(60, 0, 28, 3)["failures"][:1])
    check("E5d. zero samples in a phase is a failure, not a vacuous pass",
          cov_for(60, 0, 0, 0)["adequate"] is False,
          cov_for(60, 0, 0, 0)["failures"][:2])


def test_6_unreadable_breaks_streaks():
    # 20 consecutive forked samples would be a PARTITION; one unreadable in the middle must not
    # be spliced over
    forked = [{"phase": "mining", "topology_observed": True, "topology_conformant": True,
               "branch_readable": True, "h1_h2_genuinely_forked": True} for _ in range(20)]
    check("E6. twenty consecutive readable forked samples give a run of 20",
          SS.longest_true_run_readable(forked, "h1_h2_genuinely_forked") == 20,
          SS.longest_true_run_readable(forked, "h1_h2_genuinely_forked"))
    broken = list(forked)
    broken[10] = {"phase": "mining", "topology_observed": True, "topology_conformant": True,
                  "branch_readable": False, "branch_error": "InconsistentView: x",
                  "h1_h2_genuinely_forked": None}
    got = SS.longest_true_run_readable(broken, "h1_h2_genuinely_forked")
    check("E6b. one unreadable sample breaks the 20-sample partition streak into 10+9",
          got == 10, got)
    check("E6c. the unreadable sample is NOT skipped over (skipping would give 19)",
          got != 19, got)

    # recovery: three consecutive same-tip post_stop samples, with one unreadable in the middle
    from tests_round4 import one_sample
    _b = 901.0
    post = [one_sample("post_stop", _b + i * 15.0) for i in range(3)]
    rec = full_record("control", 1)
    rec["samples"] = post
    resync_coverage(rec)
    r_ok = SAMPV.recompute_samples(rec, {}, lambda m: None) or {}
    post_broken = list(post)
    post_broken.insert(1, one_sample("post_stop", _b + 7.5, readable=False))
    res_a, res_b = {}, {}
    rec_a = full_record("control", 1)
    rec_a["samples"] = post
    resync_coverage(rec_a)
    SAMPV.recompute_samples(rec_a, res_a, lambda m: None)
    rec_b = full_record("control", 1)
    rec_b["samples"] = post_broken
    resync_coverage(rec_b)
    SAMPV.recompute_samples(rec_b, res_b, lambda m: None)
    check("E6d. three readable same-tip post samples are a recovery run",
          res_a.get("recovery_recomputed") is True or res_a.get("recovery_first_index") == 0,
          [res_a.get("recovery_recomputed"), res_a.get("recovery_first_index")])
    check("E6e. an unreadable sample inside the run breaks it",
          res_b.get("recovery_first_index") in (None, 1)
          and res_b.get("recovery_first_index") != 0,
          res_b.get("recovery_first_index"))


def test_7_8_status_precedence():
    check("E7. a topology failure invalidates even when branch coverage is adequate",
          SS.record_status(False, True, True) == "INVALID_TOPOLOGY_DRIFT")
    check("E7b. topology failure outranks a simultaneous branch-coverage failure",
          SS.record_status(False, True, False) == "INVALID_TOPOLOGY_DRIFT")
    check("E8. inadequate branch coverage is named for what it is",
          SS.record_status(True, True, False) == "INVALID_BRANCH_EVIDENCE_COVERAGE")
    check("E8b. it is never mislabelled as topology drift",
          SS.record_status(True, True, False) != "INVALID_TOPOLOGY_DRIFT")
    check("E8c. sample coverage keeps its own distinct status",
          SS.record_status(True, False, True) == "INVALID_SAMPLE_COVERAGE")
    check("E8d. all three healthy is OK", SS.record_status(True, True, True) == "OK")

    # and the series validator refuses a record whose branch coverage is inadequate
    r = full_record("control", 1)
    r["samples"] = phase_samples(60, 3, "mining") + phase_samples(28, 3, "post_stop")
    resync_coverage(r)
    r["status"] = SS.record_status(True, True, r["branch_coverage"]["adequate"])
    out = SV.validate([r], verifier_results={})
    check("E8e. series_validate rejects an inadequate-branch-coverage record",
          any("inadequate branch-evidence coverage" in x for x in out["invalid_reasons"]),
          [x for x in out["invalid_reasons"] if "branch" in x][:2])
    r2 = full_record("control", 1)
    r2.pop("branch_coverage", None)
    out2 = SV.validate([r2], verifier_results={})
    check("E8f. a record with NO branch-coverage report cannot be counted",
          any("branch_coverage" in x or "branch-evidence coverage" in x
              for x in out2["invalid_reasons"]),
          [x for x in out2["invalid_reasons"] if "branch" in x][:2])


def test_9_offline_recompute():
    r = full_record("control", 1)
    r["samples"] = phase_samples(60, 1, "mining") + phase_samples(28, 1, "post_stop")
    resync_coverage(r)
    res, fails = {}, []
    SAMPV.recompute_samples(r, res, fails.append)
    rb = res.get("branch_coverage_recomputed") or {}
    check("E9. the offline verifier independently recomputes branch coverage",
          rb.get("phases", {}).get("mining", {}).get("unreadable") == 1
          and rb.get("phases", {}).get("post_stop", {}).get("unreadable") == 1
          and rb.get("adequate") is True,
          [rb.get("adequate"), rb.get("phases", {}).get("mining", {}).get("unreadable")])
    check("E9b. it independently recomputes topology observation counts",
          res.get("topology_observed_samples") == 88, res.get("topology_observed_samples"))
    check("E9c. an honest record produces no coverage disagreement",
          not [f for f in fails if "coverage" in f], fails[:2])
    # a record whose STORED coverage disagrees with its samples must fail
    r_bad = full_record("control", 1)
    r_bad["samples"] = phase_samples(60, 5, "mining") + phase_samples(28, 0, "post_stop")
    resync_coverage(r_bad)
    r_bad["branch_coverage"]["adequate"] = True                 # tamper
    r_bad["branch_coverage"]["phases"]["mining"]["unreadable"] = 0
    res2, fails2 = {}, []
    SAMPV.recompute_samples(r_bad, res2, fails2.append)
    check("E9d. a tampered coverage report is caught by recomputation",
          any("branch_coverage" in f or "branch coverage" in f for f in fails2), fails2[:3])
    r_no = full_record("control", 1)
    r_no.pop("branch_coverage", None)
    res3, fails3 = {}, []
    SAMPV.recompute_samples(r_no, res3, fails3.append)
    check("E9e. a record without the preregistered thresholds cannot be re-evaluated",
          any("not the preregistered" in f for f in fails3), fails3[:2])


def test_10_identity_on_every_event():
    for field, wrong in (("attempt_id", "WRONG_ATTEMPT"), ("triplet_id", "WRONG_TRIPLET"),
                         ("matched_replicate_id", "WRONG_MRI"), ("series_id", "WRONG_SERIES")):
        r = full_record("control", 1, mine_s=10.0, honest_rate=5.0)
        evs = r["miner_evidence"]["h1"]["events"]
        idx = len(evs) - 1                       # the LAST event, not the first
        evs[idx][field] = wrong
        fails = []
        SAMPV.check_identity(r, {}, fails.append)
        check(f"E10. a wrong {field} on the LAST event fails",
              any(field in f and wrong in f for f in fails), fails[:2])
    r = full_record("control", 1, mine_s=10.0, honest_rate=5.0)
    fails = []
    SAMPV.check_identity(r, {}, fails.append)
    check("E10e. an honest record still passes identity", not fails, fails[:2])
    r2 = full_record("control", 1, mine_s=10.0, honest_rate=5.0)
    del r2["miner_evidence"]["h2"]["events"][3]["condition"]
    fails2 = []
    SAMPV.check_identity(r2, {}, fails2.append)
    check("E10f. a MISSING identity field on a middle event fails",
          any("has no condition" in f for f in fails2), fails2[:2])


def test_11_preregistered():
    """The policy must be PREREGISTERED and the document must match the enforced constants."""
    doc = open(os.path.join(REPO, "docs/round2/OPERATIONAL_PREREGISTRATION.md"),
               encoding="utf-8").read()
    check("E11. section 9 preregisters the topology-vs-branch split",
          "Topology conformance vs branch readability" in doc
          and "preregistered 2026-08-15, before any measured series" in doc)
    check("E11b. the document states all three enforced thresholds",
          f"at most **{MAXU}**" in doc and f"at least **{int(MINF * 100)} %**" in doc
          and f"at least **{MINS}**" in doc,
          [MAXU, MINF, MINS])
    check("E11c. the document states zero tolerance for real topology nonconformance",
          "zero tolerance" in doc and "topology RPC failure" in doc)
    check("E11d. the document states an unreadable sample breaks streaks, never splices",
          "breaks" in doc and "never manufacture" in doc)
    check("E11e. the document fixes the status precedence the code implements",
          "INVALID_TOPOLOGY_DRIFT` > `INVALID_SAMPLE_COVERAGE` > "
          "`INVALID_BRANCH_EVIDENCE_COVERAGE`" in doc)
    check("E11f. the enforced status order matches the documented order",
          [SS.record_status(*c) for c in ((False, False, False), (True, False, False),
                                          (True, True, False), (True, True, True))]
          == ["INVALID_TOPOLOGY_DRIFT", "INVALID_SAMPLE_COVERAGE",
              "INVALID_BRANCH_EVIDENCE_COVERAGE", "OK"])


def main():
    print("NON-EVIDENCE round-5 harness tests: topology vs branch readability\n")
    test_1_branch_failure_is_not_topology_failure()
    test_2_real_topology_failures_still_fail()
    test_3_4_5_thresholds()
    test_6_unreadable_breaks_streaks()
    test_7_8_status_precedence()
    test_9_offline_recompute()
    test_10_identity_on_every_event()
    test_11_preregistered()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round5", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round5.py",)),
                       policy={"branch_max_unreadable": MAXU,
                               "branch_min_fraction": MINF,
                               "branch_min_samples": MINS},
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
