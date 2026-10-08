#!/usr/bin/env python3
"""Round-8 harness tests: the MINIMUM P0 launch gate.

NON-EVIDENCE. These validate the harness, never the protocol. Every attack below was first
reproduced as a PASS on the pre-K verifier using disposable copies of the real Gate G record;
Gate G on disk is never modified by this suite.

Scope, deliberately narrowed (see OPERATIONAL_PREREGISTRATION.md sections 12 and 13):

  P0-1  actual observations are checked, not only their plan. Preserving Gate G's honest
        schedules while moving all 12 mining observations into the final 0.11 s of mining
        (max lateness 179.8795 s) and all 12 post observations into the final 0.11 s of
        post-stop (165.1095 s) previously passed with ZERO failures.
  P0-2  the sealed window is closed at both ends. PhaseClock gained post_end_mono, h1/h2 gained
        an exact scheduled close there, and a dispatch at/after post end is now rejected instead
        of being coerced back to post_stop. Gate G itself contains three such dispatches.

Everything else found alongside these -- raw-connection-row reconstruction, wider topology schema
strictness, branch-anchor binding to the start snapshot, exhaustive overrun reconciliation and
optional-field strictness -- is recorded in section 13 as a deferred backlog and is NOT tested
here.

Usage: python3 node/tests_round8.py [--out=docs/round2/tests_round8.json]
"""
import copy, glob, json, os, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage as COV
import sample_verify as SAMPV
import symmetric_series as SS
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import build_series, full_record, one_sample, resync_coverage

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round8.json")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_G = os.path.join(REPO, "results/SMOKE_20260815_gateG")


def gate_g_copy():
    """A DISPOSABLE in-memory copy of the real Gate G record; the file is only ever READ."""
    return json.load(open(glob.glob(os.path.join(GATE_G, "raw", "*.json"))[0], encoding="utf-8"))


def verify_rec(rec):
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        return SAMPV.verify_file(p)


def caught(rec, substr=""):
    r = verify_rec(rec)
    return (not r["passed"]) and (not substr or any(substr in f for f in r["failures"])), r


def resync(rec):
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


def clean_fixture(cond="control"):
    """A schema-complete synthetic record that passes the current verifier."""
    return full_record(cond, 1)


# ===================================================== P0-1  actual observations, not the plan
def burst(rec, phase, keep_schedules=True):
    """Move a phase's OBSERVATIONS into the final 0.11 s while leaving its plan honest."""
    pb = rec["phase_boundaries"]
    end = pb["boundary_mono"] if phase == "mining" else pb["post_end_mono"]
    rows = [s for s in rec["samples"] if s["phase"] == phase]
    for i, s in enumerate(rows):
        s["t_mono"] = end - 0.12 + i * 0.01
        if not keep_schedules:
            s["scheduled_mono"] = s["t_mono"]
        s["late_by_s"] = round(s["t_mono"] - s["scheduled_mono"], 4)
    if phase == "post_stop" and rows:
        rec["verdicts"]["recovery_first_sample_t"] = round(
            rows[0]["t_mono"] - pb["post_start_mono"], 1)
    return rec


def test_1_end_bursts():
    for phase in ("mining", "post_stop"):
        rec = burst(clean_fixture(), phase)
        hit, r = caught(resync(rec), "cadence interval or more")
        check(f"R8-1. an end-burst of the {phase} OBSERVATIONS fails, honest plan and all",
              hit, r["failures"][:1])
    rec = clean_fixture()
    burst(rec, "mining")
    burst(rec, "post_stop")
    hit, r = caught(resync(rec), "cadence interval or more")
    check("R8-1c. both phases bursted together fails", hit, r["failures"][:1])

    # and the same attack on the REAL Gate G schedules, the exact case Regression testing reproduced
    g = gate_g_copy()
    pb = g["phase_boundaries"]
    mi = [s for s in g["samples"] if s["phase"] == "mining"]
    po = [s for s in g["samples"] if s["phase"] == "post_stop"]
    for i, s in enumerate(mi):
        s["t_mono"] = pb["boundary_mono"] - 0.12 + i * 0.01
        s["late_by_s"] = round(s["t_mono"] - s["scheduled_mono"], 4)
    for i, s in enumerate(po):
        s["t_mono"] = pb["post_end_mono"] - 0.12 + i * 0.01
        s["late_by_s"] = round(s["t_mono"] - s["scheduled_mono"], 4)
    hit, r = caught(resync(g), "cadence interval or more")
    check("R8-1d. the real Gate G end-burst (179.8795 s / 165.1095 s late) fails", hit,
          r["failures"][:1])


def test_2_slots_and_window():
    rec = clean_fixture()
    mi = [s for s in rec["samples"] if s["phase"] == "mining"]
    mi[1]["t_mono"] = mi[0]["t_mono"] + 0.001
    mi[1]["late_by_s"] = round(mi[1]["t_mono"] - mi[1]["scheduled_mono"], 4)
    hit, r = caught(resync(rec), "actual")
    check("R8-2. two observations in ONE real slot fail", hit, r["failures"][:1])

    rec = clean_fixture()
    s0 = [s for s in rec["samples"] if s["phase"] == "mining"][0]
    s0["t_mono"] = s0["scheduled_mono"] + rec["sample_seconds"] + 0.5
    s0["late_by_s"] = round(s0["t_mono"] - s0["scheduled_mono"], 4)
    hit, r = caught(resync(rec), "cadence interval or more")
    check("R8-2b. lateness of a full interval, correctly reported, still fails", hit,
          r["failures"][:1])

    rec = clean_fixture()
    s0 = [s for s in rec["samples"] if s["phase"] == "mining"][0]
    s0["scheduled_mono"] = rec["phase_boundaries"]["mining_start_mono"] - 1000.0
    s0["late_by_s"] = round(s0["t_mono"] - s0["scheduled_mono"], 4)
    hit, r = caught(resync(rec), "OUTSIDE the sealed run window")
    check("R8-2c. a scheduled time before the start fails even with honest lateness", hit,
          r["failures"][:1])

    rec = clean_fixture()
    last = [s for s in rec["samples"] if s["phase"] == "post_stop"][-1]
    last["scheduled_mono"] = rec["phase_boundaries"]["post_end_mono"] + 1.0
    last["t_mono"] = last["scheduled_mono"] + 0.001
    last["late_by_s"] = 0.001
    hit, r = caught(resync(rec), "OUTSIDE the sealed run window")
    check("R8-2d. a scheduled time after the end fails", hit, r["failures"][:1])

    rec = clean_fixture()
    pb = rec["phase_boundaries"]
    s0 = [s for s in rec["samples"] if s["phase"] == "mining"][-1]
    s0["t_mono"] = pb["boundary_mono"] + 0.2          # observed in the transition
    s0["late_by_s"] = round(s0["t_mono"] - s0["scheduled_mono"], 4)
    hit, r = caught(resync(rec), "do not all agree")
    check("R8-2e. a scheduled/observed phase disagreement fails", hit, r["failures"][:1])


# ===================================================== P0-2  the closed window
def test_4_dispatch_window():
    pe = clean_fixture()["phase_boundaries"]["post_end_mono"]
    for label, at in (("exactly at post_end", pe),
                      ("post_end + 0.001", pe + 0.001),
                      ("post_end + 100", pe + 100.0)):
        rec = clean_fixture()
        ev = rec["miner_evidence"]["h1"]["events"]
        ev[-1]["dispatch_mono"] = at
        ev[-1]["completed_mono"] = at + 0.01
        hit, r = caught(resync(rec), "at or after the sealed post end")
        check(f"R8-4. a dispatch {label} fails", hit, r["failures"][:1])

    rec = clean_fixture()
    ev = rec["miner_evidence"]["h1"]["events"]
    ev[-1]["dispatch_mono"] = pe - 0.001
    ev[-1]["completed_mono"] = pe + 5.0                # in flight across the boundary
    ev[-1]["phase"] = "post_stop"
    resync(rec)
    r = verify_rec(rec)
    check("R8-4d. a dispatch just BEFORE post end that completes after it stays valid",
          not any("post end" in f for f in r["failures"]),
          [f for f in r["failures"] if "post end" in f][:1])

    rec = clean_fixture()
    ev = rec["miner_evidence"]["h1"]["events"]
    ev[0]["dispatch_mono"] = rec["phase_boundaries"]["mining_start_mono"] - 1.0
    hit, r = caught(resync(rec), "BEFORE mining started")
    check("R8-4e. a dispatch before mining start fails", hit, r["failures"][:1])


def test_5_clock_and_closes():
    cases = {
        "phase_clock.post_end_mono removed":
            lambda r: r["phase_clock"].pop("post_end_mono", None),
        "phase_clock.post_end_mono wrong":
            lambda r: r["phase_clock"].update(post_end_mono=r["phase_clock"]["post_end_mono"] + 7),
        "h1 scheduled close removed":
            lambda r: r["phase_clock"]["dispatch_scheduled_close_mono"].pop("h1", None),
        "h2 scheduled close wrong":
            lambda r: r["phase_clock"]["dispatch_scheduled_close_mono"].update(
                h2=r["phase_boundaries"]["boundary_mono"]),
        "an extra node in the close map":
            lambda r: r["phase_clock"]["dispatch_scheduled_close_mono"].update(ghost=1.0),
    }
    for label, mut in cases.items():
        rec = clean_fixture()
        mut(rec)
        hit, r = caught(resync(rec))
        check(f"R8-5. {label} fails", hit, r["failures"][:1])

    rec = clean_fixture("none")
    rec["phase_clock"]["dispatch_scheduled_close_mono"]["atk"] = \
        rec["phase_boundaries"]["boundary_mono"]
    hit, r = caught(resync(rec), "expected exactly")
    check("R8-5f. an attacker close under condition NONE fails", hit, r["failures"][:1])
    r_ok = verify_rec(clean_fixture("none"))
    check("R8-5g. NONE with only h1/h2 closes passes", r_ok["passed"], r_ok["failures"][:2])


def test_6_completion():
    cases = {
        "completed_mono removed": lambda e: e.pop("completed_mono", None),
        "completed_mono NaN": lambda e: e.update(completed_mono=float("nan")),
        "completed before dispatch": lambda e: e.update(
            completed_mono=e["dispatch_mono"] - 5.0),
    }
    for label, mut in cases.items():
        rec = clean_fixture()
        mut(rec["miner_evidence"]["h1"]["events"][10])
        hit, r = caught(resync(rec))
        check(f"R8-6. {label} fails", hit, r["failures"][:1])


# ===================================================== PhaseClock unit behaviour
def test_7_phase_clock():
    c = SS.PhaseClock(1000.0, 180.0)
    check("R8-7. a fresh clock has no post end yet", c.post_end_mono is None)
    check("R8-7b. and nothing before mining start is inside the window",
          c.within_window(999.0) is False and c.phase_of(999.0) == "before_start")
    c.set_post_start(1180.5, 180.0)
    check("R8-7c. opening the post window seals the end",
          c.post_end_mono == 1360.5, c.post_end_mono)
    c.set_post_start(9999.0, 5.0)                     # a second call must be ignored entirely
    check("R8-7d. the sealed post schedule is write-once",
          c.post_end_mono == 1360.5 and c.post_start_mono == 1180.5,
          [c.post_start_mono, c.post_end_mono])
    check("R8-7e. phases are derived across the whole closed window",
          [c.phase_of(x) for x in (999.0, 1000.0, 1179.9, 1180.2, 1180.5, 1360.4, 1360.5)]
          == ["before_start", "mining", "mining", "transition", "post_stop", "post_stop",
              "after_end"],
          [c.phase_of(x) for x in (999.0, 1000.0, 1179.9, 1180.2, 1180.5, 1360.4, 1360.5)])
    check("R8-7f. within_window excludes the closed right edge",
          c.within_window(1360.4) is True and c.within_window(1360.5) is False)
    c.schedule_close("h1", c.post_end_mono)
    check("R8-7g. an honest miner may dispatch up to, but not at, post end",
          c.may_dispatch("h1", 1360.49) is True and c.may_dispatch("h1", 1360.5) is False)
    check("R8-7h. the sealed end is exported for the record",
          c.export()["post_end_mono"] == 1360.5)


def test_8_driver_wiring():
    src = open(os.path.join(REPO, "node/symmetric_series.py"), encoding="utf-8").read()
    check("R8-8. the driver seals the post end from the same clock",
          "clock.set_post_start(post_start_mono, POST_S)" in src)
    check("R8-8b. and schedule-closes h1/h2 exactly there",
          'for _n in ("h1", "h2"):' in src and 'clock.schedule_close(_n, clock.post_end_mono)'
          in src)
    check("R8-8c. the recorded boundary comes from the clock, not a recomputation",
          '"post_end_mono": clock.post_end_mono,' in src)
    check("R8-8d. the sampler refuses to begin a sample outside the window",
          "if not self.clock.within_window(t_mono):" in src)


# ===================================================== positives still hold
def test_9_positive():
    r = verify_rec(clean_fixture())
    check("R8-9. an honest complete record still passes", r["passed"], r["failures"][:2])
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        validity, vres, sres = SS.finalize_series(paths, recs, td, prov=None)
        check("R8-9b. the genuine nine-record series is still valid",
              validity["series_valid"] is True, validity["invalid_reasons"][:3])
        check("R8-9c. all nine of each verifier pass",
              all(v.get("passed") for v in vres.values())
              and all(v.get("passed") for v in sres.values()),
              [k for k, v in sres.items() if not v.get("passed")])


def test_10_documented():
    doc = open(os.path.join(REPO, "docs/round2/OPERATIONAL_PREREGISTRATION.md"),
               encoding="utf-8").read()
    check("R8-10. section 12 is dated truthfully as an August-25 addition",
          "## 12. Closing the experiment window (added 2026-08-25, after the Gate G smoke" in doc)
    check("R8-10b. it states the lateness and actual-slot rules",
          "strictly less than one `sample_seconds` interval" in doc
          and "distinct actual slot" in doc)
    check("R8-10c. it states why actual-gap floors are not used",
          "14.9996 s actual gap" in doc)
    check("R8-10d. it states the expected close membership",
          "attacker at mining end, H1/H2 at post" in doc)
    check("R8-10e. it records Gate G as historical and not grandfathered",
          "not** grandfathered" in doc and "exactly **seven** findings" in doc)
    check("R8-10e2. and it lists the scheduled-close-membership finding the prose used to omit",
          "covering only the attacker" in doc)
    check("R8-10f. the deferred backlog is recorded, not silently dropped",
          "## 13. Deferred verification backlog" in doc
          and "Raw-connection-row reconstruction" in doc
          and "Branch anchor bound to the start snapshot" in doc)
    check("R8-10g. the earlier thresholds are restated as unchanged",
          "are **unchanged**" in doc)


def main():
    print("NON-EVIDENCE round-8 harness tests: the minimum P0 launch gate\n")
    for fn in (test_1_end_bursts, test_2_slots_and_window, test_4_dispatch_window,
               test_5_clock_and_closes, test_6_completion, test_7_phase_clock,
               test_8_driver_wiring, test_9_positive, test_10_documented):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round8", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round8.py",)),
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
