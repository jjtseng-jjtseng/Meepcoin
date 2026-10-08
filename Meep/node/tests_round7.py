#!/usr/bin/env python3
"""Round-7 harness tests: the offline checker must not accept a forged time window, a hidden
fork, a non-identical start, a contradicted topology, or a partial coverage comparison.

NON-EVIDENCE. These validate the harness, never the protocol.

DISCRIMINATING-BY-CONSTRUCTION (Commit M). Every mutation group below starts from a disposable
CURRENT-SCHEMA synthetic fixture that is first proved to pass the current sample verifier with
ZERO failures, and every assertion requires a MUTATION-SPECIFIC failure substring. This matters
because Commit K deliberately made the historical Gate G record invalid under the current schema:
an unmutated `gate_g_copy()` already carries SEVEN failures, so any test that mutated it and
merely asserted "not passed" was satisfied by the pre-existing baseline defect rather than by the
protection it claimed to test. 23 such uses and 12 generic `caught(rec)` calls existed before this
rewrite.

The immutable raw Gate G record is now used in exactly ONE place: test_18_gate_g, the dedicated
historical-rejection test, which asserts those seven findings and their categories explicitly.

  1  time window and cadence   post_end was never bound; coverage was a row count; event phase
                               was read from the event rather than derived from dispatch_mono
  2  branch geometry           metadata was optional and lag was decided by hash MEMBERSHIP, so
                               injecting the peer's tip into a sequence hid a real fork as lag
  3  start identity            start_identical was never derived from start_state
  4  topology                  the stored boolean outranked the raw adjacency it came from
  5  coverage comparison       only an allowlist of fields was compared
  6  side effects              running a bundled verifier wrote .pyc into the sealed bundle

Usage: python3 node/tests_round7.py [--out=docs/round2/tests_round7.json]
"""
import copy, glob, hashlib, json, os, shutil, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bundle_verify as BV
import coverage as COV
import sample_verify as SAMPV
import series_validate as SV
import symmetric_series as SS
from provenance import Provenance
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import (ANCH, ANCHOR_H, build_series, full_record, one_sample,
                          resync_coverage)

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round7.json")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
GATE_G = os.path.join(REPO, "results/SMOKE_20260815_gateG")


def verify_rec(rec):
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        return SAMPV.verify_file(p)


def gate_g_copy():
    """A DISPOSABLE in-memory copy of the real Gate G record. The file is only ever read.

    Used ONLY by test_18_gate_g. It is historical pre-Commit-K evidence and is invalid under the
    current schema, so it is not a usable base for any other mutation test."""
    return json.load(open(glob.glob(os.path.join(GATE_G, "raw", "*.json"))[0], encoding="utf-8"))


def recov(rec):
    """Recompute both coverage reports so only the targeted mutation remains in the record."""
    rec["sample_coverage"] = COV.evaluate(rec["samples"], rec["mine_seconds"],
                                          rec["post_seconds"], rec["sample_seconds"],
                                          COV.TOPO_MIN_FRACTION, COV.TOPO_MIN_SAMPLES,
                                          COV.TOPO_MAX_NONCONFORMANT)
    rec["branch_coverage"] = COV.branch_evaluate(rec["samples"], rec["mine_seconds"],
                                                 rec["post_seconds"], rec["sample_seconds"],
                                                 COV.BRANCH_MAX_UNREADABLE,
                                                 COV.BRANCH_MIN_FRACTION, COV.BRANCH_MIN_SAMPLES)
    rec["verdicts"] = dict(rec["verdicts"],
                           sample_coverage_adequate=rec["sample_coverage"]["adequate"],
                           branch_coverage_adequate=rec["branch_coverage"]["adequate"])
    return rec


# --------------------------------------------------------------- the audited baseline gate
BASELINES = {}


def fixture(cond="control", forked=False):
    """A disposable CURRENT-SCHEMA record. Its unmutated form is proved clean by baseline_gate()."""
    return full_record(cond, 1, partition=forked)


def baseline_gate():
    """One centrally audited gate: every base this suite mutates must start with ZERO failures.

    Without this, a mutation test can be satisfied by a defect that was already present before the
    mutation -- exactly what happened when these tests mutated the historical Gate G record."""
    for cond in ("none", "control", "attack"):
        r = verify_rec(fixture(cond))
        BASELINES[cond] = r["passed"] and not r["failures"]
        check(f"R7-0. BASELINE {cond}: the unmutated fixture passes with ZERO failures",
              BASELINES[cond], r["failures"][:3])
    r = verify_rec(fixture("control", forked=True))
    BASELINES["forked"] = r["passed"] and not r["failures"]
    check("R7-0d. BASELINE forked: a genuine-fork fixture also passes with ZERO failures",
          BASELINES["forked"] and r.get("longest_fork_run_recomputed") == 60,
          [r["failures"][:2], r.get("longest_fork_run_recomputed")])
    g = verify_rec(gate_g_copy())
    check("R7-0e. and the historical Gate G base is NOT clean, so it is not used as a base here",
          (not g["passed"]) and len(g["failures"]) == 7, len(g["failures"]))


def mutated(mut, cond="control", forked=False, resync=True):
    rec = fixture(cond, forked)
    mut(rec)
    return recov(rec) if resync else rec


def must_fail(label, rec, substr):
    """Credit a mutation ONLY when a mutation-specific failure appears.

    The displayed detail is the matching failure, so the evidence shown is always the intended
    mutation rather than some unrelated pre-existing complaint."""
    r = verify_rec(rec)
    matching = [f for f in r["failures"] if substr in f]
    check(label, (not r["passed"]) and bool(matching),
          matching[:1] or ["NO MATCH for %r; got: %s" % (substr, r["failures"][:2])])
    return r


# ============================================================ 1-8  time window and cadence
def test_1_2_window():
    def before_start(r):
        s = [x for x in r["samples"] if x["phase"] == "mining"][0]
        s["t_mono"] = r["phase_boundaries"]["mining_start_mono"] - 500.0
        s["scheduled_mono"] = s["t_mono"]
        s["late_by_s"] = 0.0
    must_fail("R7-1. a sample BEFORE mining_start_mono fails",
              mutated(before_start), "OUTSIDE the sealed run window")

    def after_end(r):
        s = [x for x in r["samples"] if x["phase"] == "post_stop"][-1]
        s["t_mono"] = r["phase_boundaries"]["post_end_mono"] + 100000.0
        s["scheduled_mono"] = s["t_mono"]
        s["late_by_s"] = 0.0
    must_fail("R7-2. a sample at/after post_end_mono fails",
              mutated(after_end), "OUTSIDE the sealed run window")


def test_3_schedule_contradictions():
    cases = {
        "phase_clock removed": (lambda r: r.pop("phase_clock", None),
                                "phase_clock.mining_start_mono"),
        "post_end_mono removed": (lambda r: r["phase_boundaries"].pop("post_end_mono", None),
                                  "phase_boundaries.post_end_mono"),
        "phase_clock disagrees with boundaries": (
            lambda r: r["phase_clock"].update(
                post_start_mono=r["phase_clock"]["post_start_mono"] + 9),
            "phase_clock.post_start_mono"),
        "nominal end disagrees with boundary": (
            lambda r: r["phase_boundaries"].update(
                nominal_mining_end_mono=r["phase_boundaries"]["boundary_mono"] + 3),
            "nominal_mining_end_mono"),
        "post_end != post_start + post_seconds": (
            lambda r: r["phase_boundaries"].update(
                post_end_mono=r["phase_boundaries"]["post_start_mono"] + 999.0),
            "post_end_mono"),
        "boundaries out of order": (
            lambda r: r["phase_boundaries"].update(
                post_start_mono=r["phase_boundaries"]["mining_start_mono"] - 1),
            "not ordered"),
        "mine_seconds contradicts the interval": (lambda r: r.update(mine_seconds=17.0),
                                                  "disagrees with mine_seconds"),
        "mine_seconds_actual falsified": (lambda r: r.update(mine_seconds_actual=1.0),
                                          "actual mining interval"),
    }
    for label, (mut, sub) in cases.items():
        must_fail(f"R7-3. {label} fails", mutated(mut), sub)


def test_4_5_sample_times():
    cases = {
        "scheduled_mono removed": (lambda s: s.pop("scheduled_mono", None),
                                   "scheduled_mono is missing"),
        "t_mono removed": (lambda s: s.pop("t_mono", None), "t_mono is missing"),
        "t_mono NaN": (lambda s: s.update(t_mono=float("nan")), "t_mono is missing or not a"),
        "late_by_s removed": (lambda s: s.pop("late_by_s", None), "late_by_s is missing"),
        "late_by_s falsified": (lambda s: s.update(late_by_s=99.0), "late_by_s 99.0"),
        "observed before its scheduled slot": (
            lambda s: s.update(scheduled_mono=s["t_mono"] + 5.0, late_by_s=-5.0),
            "BEFORE its scheduled slot"),
    }
    for label, (mut, sub) in cases.items():
        def apply(r, _m=mut):
            for sm in r["samples"]:
                if sm["phase"] == "mining":
                    _m(sm)
                    break
        must_fail(f"R7-4. {label} fails", mutated(apply), sub)

    def dup_t(r):
        mi = [s for s in r["samples"] if s["phase"] == "mining"]
        mi[1]["t_mono"] = mi[0]["t_mono"]
        mi[1]["late_by_s"] = round(mi[1]["t_mono"] - mi[1]["scheduled_mono"], 4)
    must_fail("R7-5. duplicate t_mono fails", mutated(dup_t), "not strictly after")

    def dup_s(r):
        mi = [s for s in r["samples"] if s["phase"] == "mining"]
        mi[1]["scheduled_mono"] = mi[0]["scheduled_mono"]
        mi[1]["late_by_s"] = round(mi[1]["t_mono"] - mi[1]["scheduled_mono"], 4)
    must_fail("R7-5b. duplicate scheduled_mono fails", mutated(dup_s), "scheduled_mono")

    def backwards(r):
        mi = [s for s in r["samples"] if s["phase"] == "mining"]
        mi[2]["t_mono"] = mi[0]["t_mono"] - 1.0
        mi[2]["scheduled_mono"] = mi[2]["t_mono"]
        mi[2]["late_by_s"] = 0.0
    must_fail("R7-5c. a backwards t_mono fails", mutated(backwards), "not strictly after")


def test_6_7_burst_and_distribution():
    def burst(r, also):
        pb = r["phase_boundaries"]
        mi = [s for s in r["samples"] if s["phase"] == "mining"]
        po = [s for s in r["samples"] if s["phase"] == "post_stop"]
        for i, s in enumerate(mi):
            s["t_mono"] = pb["mining_start_mono"] + i * 0.01
            if also:
                s["scheduled_mono"] = s["t_mono"]
                s["late_by_s"] = 0.0
            else:
                s["late_by_s"] = round(s["t_mono"] - s["scheduled_mono"], 4)
        for i, s in enumerate(po):
            s["t_mono"] = pb["post_start_mono"] + i * 0.01
            if also:
                s["scheduled_mono"] = s["t_mono"]
                s["late_by_s"] = 0.0
            else:
                s["late_by_s"] = round(s["t_mono"] - s["scheduled_mono"], 4)
        r["verdicts"]["recovery_first_sample_t"] = 0.0
    must_fail("R7-6. rows compressed into a 0.6 s burst fail",
              mutated(lambda r: burst(r, False)), "actual")
    must_fail("R7-6b. the same burst with scheduled_mono and late_by_s edited to match also fails",
              mutated(lambda r: burst(r, True)), "unobserved")

    def cut_start(r):
        lo = r["phase_boundaries"]["mining_start_mono"]
        r["samples"] = [s for s in r["samples"]
                        if not (s["phase"] == "mining" and s["t_mono"] < lo + 300)]
    must_fail("R7-7. an unsampled start of the mining phase fails",
              mutated(cut_start), "the start of the phase is unobserved")

    def cut_end(r):
        hi = r["phase_boundaries"]["post_end_mono"]
        r["samples"] = [s for s in r["samples"]
                        if not (s["phase"] == "post_stop" and s["t_mono"] > hi - 300)]
    must_fail("R7-7b. an unsampled end of the post_stop phase fails",
              mutated(cut_end), "the end of the phase is unobserved")

    must_fail("R7-7c. a phase with no scheduled observation at all fails",
              mutated(lambda r: r.update(
                  samples=[s for s in r["samples"] if s["phase"] != "post_stop"])),
              "no scheduled observation retained")


def test_8_event_phase_derived():
    def relabel(r):
        pb = r["phase_boundaries"]
        ev = r["miner_evidence"]["h1"]["events"]
        ev[-1]["dispatch_mono"] = pb["post_start_mono"] + 1.0     # genuinely post_stop
        ev[-1]["completed_mono"] = ev[-1]["dispatch_mono"] + 0.01
        ev[-1]["phase"] = "mining"                                 # the lie
        ap = json.loads(json.dumps(r["attempts_by_phase"]))
        ap["h1"]["mining"] = ap["h1"].get("mining", 0)
        r["attempts_by_phase"] = ap
    must_fail("R7-8. a post_stop event relabelled mining fails on its dispatch time",
              mutated(relabel), "dispatch_mono")

    must_fail("R7-8b. an event without a dispatch time fails",
              mutated(lambda r: r["miner_evidence"]["h1"]["events"][5].pop("dispatch_mono", None)),
              "no finite dispatch_mono")
    must_fail("R7-8c. a non-contiguous event sequence fails",
              mutated(lambda r: r["miner_evidence"]["h2"]["events"][7].update(seq=999)),
              "not contiguous")

    def bad_counts(r):
        ap = json.loads(json.dumps(r["attempts_by_phase"]))
        ap["atk"]["mining"] = ap["atk"].get("mining", 0) + 7
        r["attempts_by_phase"] = ap
    must_fail("R7-8d. a falsified attempts_by_phase fails", mutated(bad_counts),
              "attempts_by_phase")


# ============================================================ 9-13  branch geometry
def test_9_10_11_geometry():
    """All geometry mutations run on a SYNTHETIC forked fixture with valid current-schema
    geometry, proved clean by the baseline gate."""
    cases = {
        "a branch node removed": (lambda e: e.pop("atk", None), "node set"),
        "an extra branch node": (lambda e: e.update(ghost={"tip": "0" * 64}), "node set"),
        "height removed": (lambda e: [e[n].pop("height", None) for n in ("h1", "h2", "atk")],
                           "height is missing"),
        "anchor_height removed": (lambda e: e["h1"].pop("anchor_height", None),
                                  "anchor_height is missing"),
        "anchor_hash removed": (lambda e: e["h1"].pop("anchor_hash", None),
                                "anchor_hash is missing"),
        "chain_len removed": (lambda e: e["h1"].pop("chain_len", None), "chain_len is missing"),
        "chain_digest removed": (lambda e: e["h1"].pop("chain_digest", None),
                                 "chain_digest is missing"),
        "bogus anchor_height": (lambda e: e["h1"].update(anchor_height=-99),
                                "anchor_height is missing or not"),
        "chain_len tampered": (lambda e: e["h1"].update(chain_len=99), "chain_len"),
        "a differing-tip sequence removed": (lambda e: e["h2"].pop("anchored_hashes", None),
                                             "sequence is required"),
        "non-hex hash in the sequence": (
            lambda e: e["h1"].update(anchored_hashes=["zz"] + list(e["h1"]["anchored_hashes"][1:])),
            "non-64-hex"),
        "duplicate hash in the sequence": (
            lambda e: e["h1"].update(
                anchored_hashes=list(e["h1"]["anchored_hashes"]) + [e["h1"]["anchored_hashes"][0]]),
            "duplicate hashes"),
        "sequence not starting at the anchor": (
            lambda e: e["h1"].update(
                anchored_hashes=["1" * 64] + list(e["h1"]["anchored_hashes"][1:])),
            "chain_digest does not match"),
        "sequence not ending at the tip": (
            lambda e: e["h1"].update(
                anchored_hashes=list(e["h1"]["anchored_hashes"][:-1]) + ["2" * 64]),
            "chain_digest does not match"),
        "nodes with different anchors": (lambda e: e["h2"].update(anchor_hash="7" * 64),
                                         "common anchor"),
    }
    for label, (mut, sub) in cases.items():
        def apply(r, _m=mut):
            for sm in r["samples"]:
                if sm.get("branch_readable") and isinstance(sm.get("branch_evidence"), dict):
                    _m(sm["branch_evidence"])
        must_fail(f"R7-9. {label} fails", mutated(apply, forked=True), sub)

    def tip_disagree(r):
        for sm in r["samples"]:
            if sm.get("branch_readable"):
                sm["tips"]["h1"]["tip"] = "5" * 64
    must_fail("R7-9p. a tips/branch_evidence tip disagreement fails",
              mutated(tip_disagree, forked=True), "tip disagrees")

    def geom(r):
        for sm in r["samples"]:
            if sm.get("branch_readable"):
                e = sm["branch_evidence"]["h1"]
                e["height"] = e["height"] + 5
                sm["tips"]["h1"]["height"] = e["height"]
    must_fail("R7-10. height/anchor/length geometry mismatch fails",
              mutated(geom, forked=True), "height - anchor_height")


def lengthen_fork(r, shared_n=3, tail_n=3):
    """Give the forked samples chains that DIVERGE MID-CHAIN, as the real Gate G chains do.

    Two shapes matter here. If h1 and h2 share everything except their final block, inserting
    h1's tip before h2's endpoint genuinely produces a chain that extends h1 -- the verifier is
    right to call that lag, and the lie is caught by the common-ancestor comparison instead. Gate
    G's 630-element chains diverge well before their tips, so the injected tip lands after the
    divergence and the FORK VERDICT itself must flip. This builds that second shape."""
    shared = ["%064x" % (0xC0 + i) for i in range(shared_n)]
    h1_tail = ["%064x" % (0xD0 + i) for i in range(tail_n)]
    h2_tail = ["%064x" % (0xE0 + i) for i in range(tail_n)]
    for sm in r["samples"]:
        if not sm.get("branch_readable"):
            continue
        be = sm["branch_evidence"]
        forked = be["h1"]["tip"] != be["h2"]["tip"]
        for name in ("h1", "h2", "atk"):
            tip = be[name]["tip"]
            tail = h2_tail if (forked and name == "h2") else h1_tail
            seq = [ANCH] + shared + tail + [tip]
            be[name]["anchored_hashes"] = seq
            be[name]["chain_len"] = len(seq)
            be[name]["chain_digest"] = hashlib.sha256("".join(seq).encode()).hexdigest()
            be[name]["height"] = be[name]["anchor_height"] + len(seq)
            sm["tips"][name]["height"] = be[name]["height"]
        # last common index: anchor + shared when the tails diverge, else the whole chain
        n_common = (1 + len(shared)) if forked else (1 + len(shared) + len(h1_tail) + 1)
        sm["h1_h2_common_ancestor"] = be["h1"]["anchor_height"] + n_common - 1
    return r


def test_12_13_prefix():
    base = lengthen_fork(fixture("control", forked=True))
    r0 = verify_rec(recov(base))
    check("R7-12base. the lengthened forked fixture is itself clean before mutation",
          r0["passed"] and not r0["failures"], r0["failures"][:3])

    def inject_tip(r):
        n = 0
        for sm in r["samples"]:
            if sm.get("h1_h2_genuinely_forked"):
                h1seq = sm["branch_evidence"]["h1"]["anchored_hashes"]
                h2 = sm["branch_evidence"]["h2"]
                seq = list(h2["anchored_hashes"])
                seq.insert(len(seq) - 1, h1seq[-1])
                h2["anchored_hashes"] = seq
                h2["chain_len"] = len(seq)
                h2["chain_digest"] = hashlib.sha256("".join(seq).encode()).hexdigest()
                h2["height"] = h2["anchor_height"] + len(seq)
                sm["tips"]["h2"]["height"] = h2["height"]
                sm["h1_h2_genuinely_forked"] = False
                n += 1
        r["verdicts"]["longest_h1_h2_fork_run_samples"] = 0
        r["verdicts"]["PARTITION"] = False
    rec = lengthen_fork(fixture("control", forked=True))
    inject_tip(rec)
    must_fail("R7-12. the injected-tip mutation cannot turn a real fork into lag",
              recov(rec), "h1_h2_genuinely_forked")

    def same_len(r):
        """Swap a MID-chain element for the peer's tip: same length, same endpoint, same anchor,
        recomputed digest -- only the fork verdict is falsified."""
        for sm in r["samples"]:
            if sm.get("h1_h2_genuinely_forked"):
                e = sm["branch_evidence"]["h2"]
                seq = list(e["anchored_hashes"])
                seq[-2] = sm["branch_evidence"]["h1"]["anchored_hashes"][-1]
                e["anchored_hashes"] = seq
                e["chain_digest"] = hashlib.sha256("".join(seq).encode()).hexdigest()
                sm["h1_h2_genuinely_forked"] = False
        r["verdicts"]["longest_h1_h2_fork_run_samples"] = 0
        r["verdicts"]["PARTITION"] = False
    rec2 = lengthen_fork(fixture("control", forked=True))
    same_len(rec2)
    must_fail("R7-12b. a same-length replacement attack fails",
              recov(rec2), "h1_h2_genuinely_forked")

    A1, B1 = "%064x" % 0xA1, "%064x" % 0xB1
    forked, n_common = SAMPV.lag_or_fork([ANCH, A1], [ANCH, B1])
    check("R7-13. two divergent extensions of one anchor are a FORK", forked is True)
    lag, n2 = SAMPV.lag_or_fork([ANCH], [ANCH, A1])
    check("R7-13b. a complete prefix is LAG, not a fork", lag is False and n2 == 1)
    memb, _ = SAMPV.lag_or_fork([ANCH, B1, A1], [ANCH, A1])
    check("R7-13c. containing the peer's tip WITHOUT being a prefix is still a fork",
          memb is True)
    same, n3 = SAMPV.lag_or_fork([ANCH, A1], [ANCH, A1])
    check("R7-13d. identical sequences are not forked", same is False and n3 == 2)


# ============================================================ 14  start identity
def test_14_start_identity():
    cases = {
        "start_identical removed": (lambda r: r.pop("start_identical", None),
                                    "start_identical is missing"),
        "start_identical not a boolean": (lambda r: r.update(start_identical="yes"),
                                          "start_identical is missing or not"),
        "three differing node starts, flag true": (
            lambda r: r["start_state"].update(
                h2=dict(r["start_state"]["h2"], height=999, tip_hash="9" * 64)),
            "start_identical"),
        "a malformed start field": (lambda r: r["start_state"]["atk"].pop("genesis_hash", None),
                                    "genesis_hash"),
        "a non-integer height": (lambda r: r["start_state"]["h1"].update(height="31"),
                                 "height is missing or not an integer"),
        "start_state missing a node": (lambda r: r["start_state"].pop("atk", None),
                                       "start_state node set"),
    }
    for label, (mut, sub) in cases.items():
        must_fail(f"R7-14. {label} fails", mutated(mut), sub)

    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        other = {"genesis_hash": "9" * 64, "height": 77, "tip_hash": "e" * 64,
                 "tip_difficulty": 1, "cumulative_difficulty": 77}
        for r in recs[:3]:
            r["start_state"] = {n: dict(other) for n in ("h1", "h2", "atk")}
        for p_, r in zip(paths, recs):
            json.dump(r, open(p_, "w"))
        out = SV.validate(recs, verifier_results={
            f"{r.get('condition')}#{r.get('replicate')}": {"passed": True, "failures": []}
            for r in recs})
        check("R7-14g. one triplet starting from a different tip invalidates the series",
              (not out["series_valid"])
              and any("one starting chain state" in x for x in out["invalid_reasons"]),
              [x for x in out["invalid_reasons"] if "starting" in x][:1])


# ============================================================ 15  topology
def test_15_topology():
    cases = {
        "a missing required edge in the adjacency": (
            lambda s: (s["adjacency"]["h1"].pop("h2", None),
                       s["adjacency"]["h2"].pop("h1", None)), "conformance"),
        "a one-sided required edge": (lambda s: s["adjacency"]["h2"].pop("h1", None),
                                      "conformance"),
        "an RPC error": (lambda s: s.update(rpc_errors=["h1: injected"]), "rpc_errors"),
        "an unresolved active peer": (lambda s: s.update(unresolved=[{"node": "h1"}]),
                                      "unresolved"),
        "adjacency missing entirely": (lambda s: s.pop("adjacency", None),
                                       "no adjacency evidence"),
        "rpc_errors missing entirely": (lambda s: s.pop("rpc_errors", None), "rpc_errors"),
    }
    for label, (mut, sub) in cases.items():
        def apply(r, _m=mut):
            for sm in r["samples"]:
                if sm.get("topology_observed"):
                    _m(sm)
                    break
        must_fail(f"R7-15. {label} fails even with topology_conformant=true",
                  mutated(apply), sub)

    must_fail("R7-15g. a full mesh judged as STAR fails on the forbidden edge",
              mutated(lambda r: r.update(topology="star")), "forbidden")


# ============================================================ 16  coverage structure
def test_16_coverage_structure():
    cases = {
        "top-level sample expected": (
            lambda r: r["sample_coverage"].update(expected={"mining": 999, "post_stop": 999}),
            "sample_coverage.expected"),
        "top-level branch expected": (
            lambda r: r["branch_coverage"].update(expected={"mining": 999, "post_stop": 999}),
            "branch_coverage.expected"),
        "branch phase errors": (
            lambda r: r["branch_coverage"]["phases"]["mining"].update(errors=["fabricated"]),
            "branch_coverage.phases.mining"),
        "sample phase conformant count": (
            lambda r: r["sample_coverage"]["phases"]["post_stop"].update(conformant=999),
            "sample_coverage.phases.post_stop"),
        "sample phase usable_fraction": (
            lambda r: r["sample_coverage"]["phases"]["mining"].update(usable_fraction=0.123),
            "sample_coverage.phases.mining"),
        "branch phase readable_fraction": (
            lambda r: r["branch_coverage"]["phases"]["post_stop"].update(readable_fraction=0.5),
            "branch_coverage.phases.post_stop"),
        "an extra invented phase": (
            lambda r: r["sample_coverage"]["phases"].update(ghost={"observed": 1}),
            "sample_coverage.phases"),
    }
    for label, (mut, sub) in cases.items():
        # these mutate the coverage report itself, so they must NOT be resynced afterwards
        must_fail(f"R7-16. a falsified {label} fails",
                  mutated(mut, resync=False), sub)


# ============================================================ 17  side-effect-free checkers
def make_bundle(td):
    b = os.path.join(td, "bundle")
    os.makedirs(os.path.join(b, "raw"), exist_ok=True)
    prov = Provenance(b, harness=SS.HARNESS, binary=BIN, driver_argv=["python3", "x"])
    prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
    prov.copy_inputs(["docs/round2/PREREGISTRATION.md",
                      "docs/round2/OPERATIONAL_PREREGISTRATION.md"], kind="prereg")
    prov.copy_inputs(SS.HARNESS, dest_subdir="inputs/harness", kind="harness_copy")
    paths, recs = build_series(b)
    validity, _, _ = SS.finalize_series(paths, recs, b, prov=prov)
    for p_ in paths:
        prov.add_output(p_, kind="raw")
    prov.m["series_valid"] = validity["series_valid"]
    prov.m["replay_gate"] = validity.get("replay_gate")
    prov.m["aborted"] = None
    prov.m["status"] = "COMPLETED"
    prov.finish()
    return b, validity


def inventory(root):
    out = {}
    for r, _, fs in os.walk(root):
        for f in fs:
            q = os.path.join(r, f)
            out[os.path.relpath(q, root)] = (os.path.getsize(q),
                                             hashlib.sha256(open(q, "rb").read()).hexdigest())
    return out


def raw_files(bundle):
    d = os.path.join(bundle, "raw")
    return [os.path.join(d, f) for f in sorted(os.listdir(d))]


def run_bundled(bundle, script, *args, home=None):
    """Run a checker CARRIED IN the bundle with ORDINARY python3 -- no -B, no PYTHONPATH, no
    PYTHONDONTWRITEBYTECODE -- so the CODE must be what keeps the bundle clean."""
    exe = os.path.join(bundle, "inputs", "harness", script)
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONDONTWRITEBYTECODE")}
    if home:
        env["HOME"] = home
    p = subprocess.run([sys.executable, exe] + list(args), capture_output=True, text=True,
                       cwd=os.path.dirname(bundle), env=env)
    return p.returncode, (p.stdout + p.stderr)


def test_17_idempotent_checkers():
    with tempfile.TemporaryDirectory() as td:
        b, validity = make_bundle(td)
        moved = os.path.join(td, "elsewhere", "relocated")
        os.makedirs(os.path.dirname(moved), exist_ok=True)
        shutil.copytree(b, moved)
        # a genuinely EMPTY home: the relocated checker must not read any live wallet or dotfile
        home = os.path.join(td, "sterile_home")
        os.makedirs(home)
        before = inventory(moved)

        rc0, out0 = run_bundled(moved, "bundle_verify.py", moved, "--isolated", home=home)
        check("R17. the relocated bundle verifies under a sterile empty HOME",
              rc0 == 0 and "[PASS]" in out0, out0.strip().splitlines()[:2])
        rc1, out1 = run_bundled(moved, "evidence_verify.py", *raw_files(moved), home=home)
        check("R17b. the bundled PRODUCER verifier runs under a sterile HOME",
              rc1 == 0, out1.strip().splitlines()[-2:])
        rc2, out2 = run_bundled(moved, "sample_verify.py", *raw_files(moved), home=home)
        check("R17c. the bundled SAMPLE verifier runs under a sterile HOME "
              "(pre-M this died on ~/.meepcoin-devnet/wallets/walletA.address.txt)",
              rc2 == 0 and "FileNotFoundError" not in out2, out2.strip().splitlines()[-2:])
        rc3, out3 = run_bundled(moved, "series_validate.py", *raw_files(moved), home=home)
        check("R17d. the bundled series validator runs BOTH verifiers under a sterile HOME",
              "producer verifier" in out3 and "sample verifier" in out3
              and "FileNotFoundError" not in out3, out3.strip().splitlines()[:1])

        after = inventory(moved)
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(k for k in before if k in after and before[k] != after[k])
        check("R17e. running every bundled checker ADDS no file", not added, added[:5])
        check("R17f. it REMOVES no file", not removed, removed[:5])
        check("R17g. it MODIFIES no file", not changed, changed[:5])
        check("R17h. no __pycache__ or .pyc appears anywhere in the bundle",
              not [k for k in after if "__pycache__" in k or k.endswith(".pyc")],
              [k for k in after if "__pycache__" in k][:3])
        rc5, out5 = run_bundled(moved, "bundle_verify.py", moved, "--isolated", home=home)
        check("R17i. the bundle still verifies afterwards, in any order",
              rc5 == 0 and "[PASS]" in out5, out5.strip().splitlines()[:2])


# ============================================================ 18  Gate G, the ONE historical use
def test_18_gate_g():
    """Gate G is immutable pre-K evidence and the CURRENT verifier must REJECT it.

    This is the ONLY test that uses the historical record. It asserts the exact seven current
    findings and their categories."""
    src = glob.glob(os.path.join(GATE_G, "raw", "*.json"))[0]
    before = inventory(GATE_G)
    with tempfile.TemporaryDirectory() as td:
        tmp = os.path.join(td, os.path.basename(src))
        shutil.copy2(src, tmp)
        r = SAMPV.verify_file(tmp)
        import evidence_verify as EVV
        pv = EVV.verify(tmp)
    cats = {"clock": [], "close_map": [], "post_end_dispatch": [], "phase_counts": [],
            "other": []}
    for f in r["failures"]:
        if "phase_clock.post_end_mono" in f:
            cats["clock"].append(f)
        elif "dispatch_scheduled_close_mono covers" in f:
            cats["close_map"].append(f)
        elif "at or after the sealed post end" in f:
            cats["post_end_dispatch"].append(f)
        elif "attempts_by_phase" in f:
            cats["phase_counts"].append(f)
        else:
            cats["other"].append(f)
    check("R18. the historical Gate G record is REJECTED by the current verifier",
          not r["passed"], r["failures"][:2])
    check("R18b. exactly one missing post-end clock finding", len(cats["clock"]) == 1,
          cats["clock"])
    check("R18c. exactly one incomplete scheduled-close-membership finding",
          len(cats["close_map"]) == 1, cats["close_map"])
    check("R18d. exactly three post-end dispatch findings",
          len(cats["post_end_dispatch"]) == 3, [f[:60] for f in cats["post_end_dispatch"]])
    check("R18e. h1 contributes two of them and h2 one",
          sum(1 for f in cats["post_end_dispatch"] if f.startswith("h1:")) == 2
          and sum(1 for f in cats["post_end_dispatch"] if f.startswith("h2:")) == 1,
          [f[:12] for f in cats["post_end_dispatch"]])
    check("R18f. exactly two consequent phase-count findings",
          len(cats["phase_counts"]) == 2, cats["phase_counts"])
    check("R18g. nothing else -- exactly seven findings in total",
          len(r["failures"]) == 7 and not cats["other"], r["failures"])
    check("R18h. its producer attribution is still sound; timing is not that verifier's gate",
          pv.get("passed") is True, (pv.get("failures") or [])[:2])
    check("R18i. verifying Gate G added or changed NOTHING inside it",
          inventory(GATE_G) == before)


# ============================================================ 19  positive series
def test_19_positive():
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        validity, vres, sres = SS.finalize_series(paths, recs, td, prov=None)
        check("R19. a complete genuine nine-record series is valid",
              validity["series_valid"] is True, validity["invalid_reasons"][:3])
        check("R19b. all nine producer and sample verifiers pass",
              all(v.get("passed") for v in vres.values())
              and all(v.get("passed") for v in sres.values()),
              [k for k, v in sres.items() if not v.get("passed")])
        check("R19c. the replay gate is NOT_TRIGGERED",
              validity.get("replay_gate") == "NOT_TRIGGERED", validity.get("replay_gate"))
        check("R19d. every record shares one derived start tuple",
              len({tuple(v) for v in validity["start_tuples"].values() if v}) == 1,
              validity["start_tuples"])

    negatives = {
        "a burst-compressed record": lambda r: [
            sm.update(t_mono=r["phase_boundaries"]["mining_start_mono"] + i * 0.01,
                      scheduled_mono=r["phase_boundaries"]["mining_start_mono"] + i * 0.01,
                      late_by_s=0.0)
            for i, sm in enumerate([s for s in r["samples"] if s["phase"] == "mining"])],
        "a hidden fork": lambda r: [
            sm["branch_evidence"]["h2"].update(tip="b" * 64) for sm in r["samples"]
            if sm.get("branch_readable")],
        "a non-identical start": lambda r: r["start_state"].update(
            h2=dict(r["start_state"]["h2"], height=999)),
        "a contradicted topology": lambda r: [
            sm["adjacency"]["h1"].pop("h2", None) for sm in r["samples"]
            if sm.get("adjacency")],
    }
    for label, mut in negatives.items():
        with tempfile.TemporaryDirectory() as td:
            paths, recs = build_series(td)
            mut(recs[0])
            json.dump(recs[0], open(paths[0], "w"))
            validity, _, _ = SS.finalize_series(paths, recs, td, prov=None)
            check(f"R19e. {label} prevents series_valid",
                  validity["series_valid"] is False, validity["invalid_reasons"][:2])


# ============================================================ 21  non-masking self-test
def test_21_non_masking():
    """Prove a credited mutation is credited because of ITS OWN validator.

    With the mutation-specific validator disabled, the same mutated record must PASS. If it still
    failed, the credit would be coming from something else -- which is exactly how mutating the
    already-invalid Gate G record produced ~55 non-discriminating assertions before this rewrite.
    """
    def relabel(r):
        pb = r["phase_boundaries"]
        ev = r["miner_evidence"]["h1"]["events"]
        ev[-1]["dispatch_mono"] = pb["post_end_mono"] + 100.0
        ev[-1]["completed_mono"] = ev[-1]["dispatch_mono"] + 0.01
    rec = mutated(relabel)
    r_on = verify_rec(rec)
    check("R21. with its validator ACTIVE the out-of-window dispatch is caught",
          (not r_on["passed"])
          and any("at or after the sealed post end" in f for f in r_on["failures"]),
          r_on["failures"][:1])

    orig = SAMPV.check_event_phases
    try:
        SAMPV.check_event_phases = lambda rec_, res_, fail_, sch_: {}
        r_off = verify_rec(rec)
    finally:
        SAMPV.check_event_phases = orig
    check("R21b. with ONLY that validator disabled the same record PASSES -- so the credit came "
          "from that check and not from a pre-existing baseline defect",
          r_off["passed"], r_off["failures"][:3])

    g = verify_rec(gate_g_copy())
    check("R21c. by contrast the historical Gate G base fails before ANY mutation, which is why "
          "it is no longer used as a mutation base",
          (not g["passed"]) and len(g["failures"]) == 7, len(g["failures"]))


def test_22_log_archive_restore():
    """Reconstruct Gate K's ignored daemon logs from its committed sidecar archive.

    Git does not track the .log files, so a fresh checkout has the bundle without its logs. This
    proves the committed archive really does restore them: the sidecar hash is checked FIRST, the
    member list is rejected if it contains absolute paths, parent traversal or unexpected names,
    only the three expected relative members are extracted into a DISPOSABLE copy, each restored
    log is compared with the sealed SHA256SUMS, and the copied isolated checker is then run.
    Gate K itself is never written to."""
    import tarfile
    gk = os.path.join(REPO, "results/SMOKE_20260825_gateK")
    arc = gk + "__daemon_logs.tar.gz"
    side = arc + ".sha256"
    check("R22. the Gate K log archive and its hash sidecar are committed",
          os.path.exists(arc) and os.path.exists(side), [arc, side])
    want = open(side, encoding="utf-8").read().split()[0]
    got = hashlib.sha256(open(arc, "rb").read()).hexdigest()
    check("R22b. the archive matches its sidecar hash BEFORE anything is extracted",
          want == got, [want[:16], got[:16]])

    sealed = {}
    for line in open(os.path.join(gk, "SHA256SUMS"), encoding="utf-8"):
        parts = [x for x in line.rstrip(chr(10)).split("  ") if x]
        if len(parts) >= 2 and parts[-1].endswith(".log"):
            sealed[parts[-1]] = parts[0]
    check("R22c. the bundle seals exactly three daemon logs", len(sealed) == 3, sorted(sealed))

    with tarfile.open(arc, "r:gz") as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        unsafe = [n for n in names
                  if os.path.isabs(n) or ".." in n.split("/") or n.startswith("/")]
        check("R22d. no archive member is absolute or traverses upward", not unsafe, unsafe[:3])
        files = [m for m in members if m.isfile()]
        expected = set(sealed)
        got_names = {m.name for m in files}
        check("R22e. the archive contains exactly the three expected relative log members",
              got_names == expected, sorted(got_names ^ expected))
        with tempfile.TemporaryDirectory() as td:
            moved = os.path.join(td, "fresh_checkout_bundle")
            # a bundle WITHOUT its logs, as a fresh checkout would have it
            shutil.copytree(gk, moved, ignore=shutil.ignore_patterns("*.log"))
            missing = [n for n in expected if not os.path.exists(os.path.join(moved, n))]
            check("R22f. the simulated fresh checkout is missing all three logs",
                  len(missing) == 3, missing)
            for m in files:
                if m.name in expected:
                    tf.extract(m, moved)
            ok = []
            for n, h in sealed.items():
                q = os.path.join(moved, n)
                ok.append(os.path.exists(q)
                          and hashlib.sha256(open(q, "rb").read()).hexdigest() == h)
            check("R22g. every restored log matches its sealed SHA256SUMS entry", all(ok), ok)
            home = os.path.join(td, "sterile_home2")
            os.makedirs(home)
            rc, out = run_bundled(moved, "bundle_verify.py", moved, "--isolated", home=home)
            check("R22h. the reconstructed bundle verifies with its own copied checker",
                  rc == 0 and "[PASS]" in out, out.strip().splitlines()[:2])
    check("R22i. Gate K itself was not modified by the reconstruction",
          hashlib.sha256(open(arc, "rb").read()).hexdigest() == want)


def test_20_preregistered():
    doc = open(os.path.join(REPO, "docs/round2/OPERATIONAL_PREREGISTRATION.md"),
               encoding="utf-8").read()
    check("R20. section 11 carries its TRUTHFUL added-on date",
          "Deriving the record instead of reading it (added 2026-08-25, after the Gate G smoke"
          in doc)
    check("R20a2. the document states the dating correction explicitly",
          "was added by Commit I on 2026-08-25, not on 2026-08-15" in doc)
    check("R20b. it states the closed time window",
          "post_end_mono" in doc and "counts toward neither phase" in doc)
    check("R20c. it states that coverage is a distribution, not a row count",
          "not a row count" in doc and "distinct scheduled slot" in doc)
    check("R20d. it states the exact-prefix lag rule",
          "exact prefix of the other" in doc and "cannot be forged by insertion" in doc)
    check("R20e. it states the series-level start rule",
          "share one derived start tuple" in doc)
    check("R20f. it states that topology is recomputed from the adjacency",
          "never the source of" in doc and "topology.conformance()" in doc)
    check("R20g. it states that a post-seal verifier must not touch the bundle",
          "dont_write_bytecode" in doc and "not** weakened" in doc)
    check("R20h. the earlier thresholds are explicitly unchanged", "are unchanged" in doc)


def main():
    print("NON-EVIDENCE round-7 harness tests: discriminating mutation coverage\n")
    baseline_gate()
    for fn in (test_1_2_window, test_3_schedule_contradictions, test_4_5_sample_times,
               test_6_7_burst_and_distribution, test_8_event_phase_derived,
               test_9_10_11_geometry, test_12_13_prefix, test_14_start_identity,
               test_15_topology, test_16_coverage_structure, test_17_idempotent_checkers,
               test_18_gate_g, test_19_positive, test_21_non_masking,
               test_22_log_archive_restore, test_20_preregistered):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round7", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round7.py",)),
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
