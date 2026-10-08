#!/usr/bin/env python3
"""Gates Q1-Q14 for the NON-EVIDENCE cadence qualification.

These gates are frozen in docs/round2/OPERATIONAL_PREREGISTRATION.md section 16, written before
the qualification was launched and before any of its output was seen. This file is the executable
form of that section. It is a CHECKER: it launches nothing, changes nothing, and never authorises
a rerun.

WHAT THIS IS NOT

Not an experiment. Not evidence. Not a replacement for any Gate-N record. Nothing about the
timestamp hypothesis may be read out of a qualification -- it only asks whether the path-parity
build holds its configured cadence, symmetrically, for three short matched pairs.

The six-record shape carries no NONE arm, so the nine-record series validator will report triplet
and equilibrium reasons against it. That is expected and is NOT a Q failure. The qualification is
judged by Q1-Q14 and by nothing else.

Usage: python3 node/cadence_qualify.py <bundle-dir> [--trace=env_trace.json] [--out=verdict.json]
"""
import glob, json, os, sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True

import env_trace as ET
import sample_verify as SAMPV

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_N = os.path.join(REPO, "results", "FULLMESH_20260826_gateN")
GATE_N_SUMS = "ddfb1c60c2f319ef2dfea8056962b1a0e92f79553fccc82c611f85f8302e4880"
GATE_N_ARCHIVE = "79f4fa82ec333c112248b7178d63b7693b4b744d6d0bf6af503a26313d75cf2b"
GATE_N_FILES = 66

EXACT_TOL = Fraction(1, 50)
EXACT_SHARE_CAP = Fraction(85, 1000)
BIN_S = 60.0
MINE_S, POST_S, SAMPLE_S = 180, 180, 15.0
RATES = {"total": 45.0, "third": 3.6, "honest": 20.7}
FLOOR = 0.80
THIRD_BIN_FLOOR = 173          # ceil(0.80 * 3.6 * 60) == ceil(172.8)
HONEST_BIN_FLOOR = 994         # ceil(0.80 * 20.7 * 60) == ceil(993.6)
STAGES = ("height", "template", "timestamp_window", "candidate")
WANT_MODE = {"control": "control_sham", "attack": "adaptive"}


def rid(r):
    return "%s#%s" % (r.get("condition"), r.get("replicate"))


def mining_events(r, miner):
    ev = (r.get("miner_evidence") or {}).get(miner) or {}
    return [e for e in (ev.get("events") or []) if e.get("phase") == "mining"]


def bins(r, miner):
    """Raw dispatch counts in each whole 60 s bin of the mining phase.

    Counted from the sealed mining_start_mono, from the raw dispatch times -- never from a stored
    aggregate, and never from an average scaled down to a bin."""
    pb = r.get("phase_boundaries") or {}
    t0 = pb.get("mining_start_mono")
    if not isinstance(t0, (int, float)):
        return None
    n = int(MINE_S // BIN_S)
    out = [0] * n
    for e in mining_events(r, miner):
        d = e.get("dispatch_mono")
        if not isinstance(d, (int, float)):
            continue
        b = int((d - t0) // BIN_S)
        if 0 <= b < n:
            out[b] += 1
    return out


def dev(x, y):
    if x + y == 0:
        return None
    return Fraction(2 * abs(x - y), x + y)


class Q:
    def __init__(self):
        self.gates = []

    def gate(self, name, title, ok, detail=None):
        self.gates.append({"gate": name, "title": title, "passed": bool(ok),
                           "detail": detail})
        return bool(ok)

    @property
    def failed(self):
        return [g for g in self.gates if not g["passed"]]


def qualify(bundle, trace_path=None):
    q = Q()
    raws = sorted(glob.glob(os.path.join(bundle, "raw", "*.json")))
    recs = []
    for p in raws:
        try:
            recs.append(json.load(open(p, encoding="utf-8")))
        except Exception as e:
            q.gate("Q0", "every raw record parses", False, f"{p}: {type(e).__name__}: {e}")
    by = {rid(r): r for r in recs}

    # ---- Q1: one launch, no reruns, no replacements ----------------------------------
    manifests = sorted(glob.glob(os.path.join(bundle, "manifest.json")))
    attempts = sorted({r.get("attempt") for r in recs})
    dirs = sorted(os.path.basename(d) for d in glob.glob(os.path.join(bundle, "*"))
                  if os.path.isdir(d))
    q.gate("Q1", "exactly one launch, zero reruns, zero replacement or excluded records",
           len(manifests) == 1 and attempts == [1] and len(raws) == 6,
           {"manifests": len(manifests), "attempt_values": attempts, "raw_files": len(raws),
            "bundle_subdirs": dirs})

    # ---- Q2: shape --------------------------------------------------------------------
    want = {"control#1", "control#2", "control#3", "attack#1", "attack#2", "attack#3"}
    topo = sorted({r.get("topology") for r in recs})
    q.gate("Q2", "exactly six records, CONTROL and ATTACK only, full mesh",
           set(by) == want and len(recs) == 6 and topo == ["full_mesh"],
           {"records": sorted(by), "missing": sorted(want - set(by)),
            "unexpected": sorted(set(by) - want), "topologies": topo})

    # ---- Q3: timing -------------------------------------------------------------------
    bad = []
    for r in recs:
        pb = r.get("phase_boundaries") or {}
        a, b = pb.get("mining_start_mono"), pb.get("boundary_mono")
        iv = (b - a) if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None
        if (r.get("mine_seconds") != MINE_S or r.get("post_seconds") != POST_S
                or float(r.get("sample_seconds") or 0) != SAMPLE_S
                or iv is None or abs(iv - MINE_S) > 2.0):
            bad.append({"record": rid(r), "mine_seconds": r.get("mine_seconds"),
                        "post_seconds": r.get("post_seconds"),
                        "sample_seconds": r.get("sample_seconds"),
                        "derived_interval_s": round(iv, 3) if iv is not None else None})
    q.gate("Q3", "180 s mining, 180 s post, 15 s cadence, derived interval within 2 s", not bad,
           bad or "all six records")

    # ---- Q4: configured rates ---------------------------------------------------------
    bad = [{"record": rid(r), "configured_rates": r.get("configured_rates")}
           for r in recs if r.get("configured_rates") != RATES]
    q.gate("Q4", "configured rates exactly 45.0 total / 3.6 third / 20.7 honest", not bad,
           bad or RATES)

    # ---- Q5: mode binding -------------------------------------------------------------
    bad = []
    for r in recs:
        want_m = WANT_MODE.get(r.get("condition"))
        got = r.get("third_miner_mode")
        ev_mode = ((r.get("miner_evidence") or {}).get("atk") or {}).get("mode")
        if got != want_m or ev_mode != want_m:
            bad.append({"record": rid(r), "record_mode": got, "miner_mode": ev_mode,
                        "required": want_m})
    q.gate("Q5", "CONTROL runs control_sham, ATTACK runs adaptive, record and miner agree",
           not bad, bad or "all six records")

    # ---- Q6/Q7: the offline path-parity and telemetry checks --------------------------
    failures, schemas, stage_bad = {}, {}, []
    for p, r in zip(raws, recs):
        res = SAMPV.verify_file(p)
        if not res.get("passed"):
            failures[rid(r)] = res["failures"][:4]
        schemas[rid(r)] = res.get("miner_schema")
        atk = (r.get("miner_evidence") or {}).get("atk") or {}
        for c in atk.get("preparation_cycles") or []:
            if c.get("status") != "prepared":
                continue
            if sorted(c.get("stage_s") or {}) != sorted(STAGES):
                stage_bad.append({"record": rid(r), "cycle": c.get("cycle"),
                                  "timed": sorted(c.get("stage_s") or {})})
    q.gate("Q6", "sample_verify passes all six on the current miner schema, and every prepared "
                 "third-miner cycle in BOTH arms timed all four stages",
           not failures and set(schemas.values()) == {"current"} and not stage_bad,
           {"verifier_failures": failures, "schemas": schemas,
            "cycles_with_wrong_stage_set": stage_bad[:5]})

    words = ("no telemetry row", "duplicate preparation-cycle", "orphaned telemetry",
             "contradictory telemetry", "missing, reordered or fabricated",
             "contradicts the cycle", "no integer cycle id")
    tel = {k: [f for f in v if any(w in f for w in words)] for k, v in failures.items()}
    tel = {k: v for k, v in tel.items() if v}
    q.gate("Q7", "zero missing, duplicate, orphaned or contradictory cycle findings",
           not tel, tel or "none across six records")

    # ---- Q8: miner health -------------------------------------------------------------
    bad = []
    for r in recs:
        for n, ev in (r.get("miner_evidence") or {}).items():
            st = ev.get("stats") or {}
            if (not st.get("healthy") or st.get("fatal_error")
                    or st.get("candidate_attempts") != ev.get("event_count")):
                bad.append({"record": rid(r), "miner": n, "healthy": st.get("healthy"),
                            "end_reason": st.get("end_reason"),
                            "fatal_error": st.get("fatal_error"),
                            "attempts": st.get("candidate_attempts"),
                            "events": ev.get("event_count")})
    q.gate("Q8", "every miner healthy, cleanly terminated, one event per attempt", not bad,
           bad or "18 miners across six records")

    # ---- Q9: per-bin raw attempt floors ----------------------------------------------
    bad, seen = [], {}
    for r in recs:
        present = set(r.get("miner_evidence") or {})
        for n, floor in (("atk", THIRD_BIN_FLOOR), ("h1", HONEST_BIN_FLOOR),
                         ("h2", HONEST_BIN_FLOOR)):
            if n not in present:
                # a miner the condition does not run is absent, not idle. Q2 already requires the
                # qualification to carry no such record; scoring a floor against a miner that was
                # never started would be scoring a zero that is not a measurement.
                continue
            b = bins(r, n)
            seen.setdefault(rid(r), {})[n] = b
            if b is None:
                bad.append({"record": rid(r), "miner": n, "bins": None,
                            "why": "no mining_start_mono"})
            elif min(b) < floor:
                bad.append({"record": rid(r), "miner": n, "bins": b, "floor": floor})
    q.gate("Q9", "every 60 s bin at or above the 80%% floor (third >= %d, honest >= %d)"
           % (THIRD_BIN_FLOOR, HONEST_BIN_FLOOR), not bad, bad or seen)

    # ---- Q10: exact per-bin pair deviation --------------------------------------------
    bad, table = [], {}
    for rep in (1, 2, 3):
        c, a = by.get("control#%d" % rep), by.get("attack#%d" % rep)
        if c is None or a is None:
            bad.append({"replicate": rep, "why": "the pair is incomplete"})
            continue
        cb, ab = bins(c, "atk"), bins(a, "atk")
        if cb is None or ab is None:
            bad.append({"replicate": rep, "why": "bins cannot be derived"})
            continue
        row = []
        for b, (x, y) in enumerate(zip(cb, ab)):
            d = dev(x, y)
            row.append({"bin": b, "control": x, "attack": y,
                        "exact": None if d is None else "%d/%d" % (d.numerator, d.denominator),
                        "percent": None if d is None else round(100 * float(d), 8),
                        "within": bool(d is not None and d <= EXACT_TOL)})
            if d is None or d > EXACT_TOL:
                bad.append({"replicate": rep, "bin": b, "control": x, "attack": y,
                            "exact": None if d is None else
                            "%d/%d" % (d.numerator, d.denominator)})
        table["rep%d" % rep] = row
    q.gate("Q10", "exact per-60s-bin third-miner deviation <= 1/50 for every replicate",
           not bad, {"failures": bad, "bins": table})

    # ---- Q11: exact totals -------------------------------------------------------------
    bad, tot = [], {}
    for rep in (1, 2, 3):
        c, a = by.get("control#%d" % rep), by.get("attack#%d" % rep)
        if c is None or a is None:
            bad.append({"replicate": rep, "why": "the pair is incomplete"})
            continue
        tc, ta = len(mining_events(c, "atk")), len(mining_events(a, "atk"))
        gc = sum(len(mining_events(c, n)) for n in (c.get("miner_evidence") or {}))
        ga = sum(len(mining_events(a, n)) for n in (a.get("miner_evidence") or {}))
        d3, dt = dev(tc, ta), dev(gc, ga)
        tot["rep%d" % rep] = {
            "third": {"control": tc, "attack": ta,
                      "exact": None if d3 is None else "%d/%d" % (d3.numerator, d3.denominator),
                      "percent": None if d3 is None else round(100 * float(d3), 10)},
            "total": {"control": gc, "attack": ga,
                      "exact": None if dt is None else "%d/%d" % (dt.numerator, dt.denominator),
                      "percent": None if dt is None else round(100 * float(dt), 10)}}
        for label, d in (("third", d3), ("total", dt)):
            if d is None or d > EXACT_TOL:
                bad.append({"replicate": rep, "which": label,
                            "exact": None if d is None else
                            "%d/%d" % (d.numerator, d.denominator)})
    q.gate("Q11", "exact third-miner and TOTAL mining deviation <= 1/50 per replicate", not bad,
           {"failures": bad, "totals": tot})

    # ---- Q12: share cap ---------------------------------------------------------------
    bad, shares = [], {}
    for r in recs:
        counts = {n: len(mining_events(r, n)) for n in (r.get("miner_evidence") or {})}
        s = sum(counts.values())
        if s == 0:
            bad.append({"record": rid(r), "why": "no mining attempts"})
            continue
        sh = Fraction(counts.get("atk", 0), s)
        shares[rid(r)] = {"atk": counts.get("atk", 0), "total": s,
                          "exact": "%d/%d" % (sh.numerator, sh.denominator),
                          "value": round(float(sh), 12)}
        if sh > EXACT_SHARE_CAP:
            bad.append({"record": rid(r), "exact": "%d/%d" % (sh.numerator, sh.denominator)})
    q.gate("Q12", "exact third-miner share <= 85/1000 on every record", not bad,
           {"failures": bad, "shares": shares})

    # ---- Q13: environment trace STRUCTURE (never its values) --------------------------
    if not trace_path or not os.path.exists(trace_path):
        q.gate("Q13", "the environment trace passes its structure gate", False,
               f"no trace at {trace_path!r}")
    else:
        f = ET.verify_trace(trace_path)
        q.gate("Q13", "the environment trace passes its structure gate", not f,
               {"structural_failures": f[:8],
                "note": "observed values are covariates; nothing measured here may exclude a "
                        "record, invalidate a replicate or authorise a rerun"})

    # ---- Q14: NON-EVIDENCE labelling and Gate N untouched ------------------------------
    import hashlib
    files = [p for p in glob.glob(os.path.join(GATE_N, "**", "*"), recursive=True)
             if os.path.isfile(p)]
    pyc = [p for p in files if p.endswith(".pyc") or "__pycache__" in p]

    def sha(p):
        try:
            return hashlib.sha256(open(p, "rb").read()).hexdigest()
        except OSError:
            return None
    sums = sha(os.path.join(GATE_N, "SHA256SUMS"))
    # The daemon-log archive is a SIBLING of the bundle directory, not a file inside it -- the
    # first version of this checker globbed inside GATE_N, found nothing, and failed Q14 on the
    # 2026-08-27 qualification while Gate N was demonstrably untouched. The gate was correct to
    # fail on a hash it could not produce; the lookup was wrong. Fixed here for future rounds;
    # the recorded verdict of that qualification is NOT reissued.
    arch = sha(GATE_N + "__daemon_logs.tar.gz")
    name_ok = os.path.basename(os.path.abspath(bundle)).startswith("CADENCEQ_")
    q.gate("Q14", "the bundle is a NON-EVIDENCE CADENCEQ bundle and Gate N is untouched",
           name_ok and len(files) == GATE_N_FILES and not pyc and sums == GATE_N_SUMS
           and arch == GATE_N_ARCHIVE,
           {"bundle": os.path.basename(os.path.abspath(bundle)),
            "gate_n_archive_path": GATE_N + "__daemon_logs.tar.gz",
            "gate_n_files": len(files), "gate_n_pyc": len(pyc),
            "gate_n_sha256sums": sums, "gate_n_archive": arch,
            "expected": {"files": GATE_N_FILES, "sha256sums": GATE_N_SUMS,
                         "archive": GATE_N_ARCHIVE}})
    return q


def main(argv):
    arg = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in argv if "=" in a}
    pos = [a for a in argv if not a.startswith("--")]
    if not pos:
        print(__doc__)
        return 2
    bundle = pos[0]
    q = qualify(bundle, arg.get("--trace"))
    print("CADENCE QUALIFICATION -- NON-EVIDENCE. Not an experiment, not a Gate-N replacement,")
    print("and no claim about the timestamp hypothesis may be read out of it.\n")
    for g in q.gates:
        print("  [%s] %-4s %s" % ("PASS" if g["passed"] else "FAIL", g["gate"], g["title"]))
    ok = not q.failed
    print("\nQUALIFICATION: %s (%d/%d gates)"
          % ("PASSED" if ok else "FAILED", len(q.gates) - len(q.failed), len(q.gates)))
    if not ok:
        print("Failing gates:", ", ".join(g["gate"] for g in q.failed))
        print("A failure does NOT authorise a rerun. The output is preserved exactly as produced.")
    doc = {"kind": "cadence_qualification", "non_evidence": True, "bundle": bundle,
           "trace": arg.get("--trace"), "passed": ok,
           "gates_passed": len(q.gates) - len(q.failed), "gates_total": len(q.gates),
           "preregistration": "docs/round2/OPERATIONAL_PREREGISTRATION.md section 16",
           "disposition": "a failed gate does not authorise a rerun, no gate may be relaxed "
                          "after seeing output, and no record may be excluded to make one pass",
           "gates": q.gates}
    out = arg.get("--out")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        print("verdict ->", out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
