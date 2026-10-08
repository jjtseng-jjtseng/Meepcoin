#!/usr/bin/env python3
"""Series-level validity, computed in code rather than asserted in prose.

A finalized manifest with status=COMPLETED means only that the driver reached its last line. It
does NOT mean the series is evidence: the driver can complete while individual conditions carry
status ERROR, while a matched pair fails the rate rule, or while sample coverage was inadequate.

This module emits a machine-readable `series_valid` boolean plus explicit `invalid_reasons`.

Usage: python3 node/series_validate.py <summary.json|raw records...>
"""
import json, os, sys
from fractions import Fraction

# F: a bundled verifier must NEVER add a file to the sealed bundle it is checking. Running the
# copied series validator used to emit inputs/harness/__pycache__/*.pyc, after which the very
# next isolated bundle verification failed on unlisted files. Suppressing bytecode BEFORE the
# sibling imports below keeps post-seal verification side-effect-free and repeatable in any
# order. `python3 -B` / PYTHONDONTWRITEBYTECODE stay useful as defence in depth, but the code
# must not depend on the caller remembering them.
sys.dont_write_bytecode = True

REQUIRED_PER_CONDITION = 3
RATE_TOL = 0.02          # matched CONTROL/ATTACK candidate-attempt agreement (DISPLAY ONLY)
THIRD_SHARE_CAP = 0.085  # committed cap on the third miner's achieved share (DISPLAY ONLY)

# The frozen thresholds as EXACT rationals. These, not the floats above, decide every scientific
# gate. Writing them as Fraction(1, 50) and Fraction(85, 1000) rather than Fraction(str(0.02)) is
# deliberate: the binary double nearest 0.02 is 0.020000000000000000416..., so a pair sitting
# exactly on the boundary would otherwise be judged against a number that is not one fiftieth.
# The floats are retained only for printing the threshold in human-readable messages.
EXACT_TOL = Fraction(1, 50)
EXACT_SHARE_CAP = Fraction(85, 1000)


def load(paths):
    """Load raw condition records.

    A summary alone is NOT sufficient: it strips per_node, so the NONE equilibrium gate cannot be
    evaluated from it. When handed a summary, the authoritative raw records listed beside it are
    loaded instead."""
    recs = []
    for p in paths:
        d = json.load(open(p, encoding="utf-8"))
        if isinstance(d, dict) and "conditions" in d:
            raw_dir = os.path.join(os.path.dirname(os.path.abspath(p)), "raw")
            loaded = []
            if os.path.isdir(raw_dir):
                for f in sorted(os.listdir(raw_dir)):
                    if f.endswith(".json"):
                        q = os.path.join(raw_dir, f)
                        rr = json.load(open(q, encoding="utf-8"))
                        rr["_path"] = q
                        loaded.append(rr)
            if loaded:
                recs += loaded
            else:
                recs += [dict(c, _from_summary=True) for c in d["conditions"]
                         if isinstance(c, dict)]
        else:
            d["_path"] = p
            recs.append(d)
    return recs


REQUIRED_FIELDS = [
    ("status", "run status"),
    ("sample_coverage", "sample-coverage report"),
    ("branch_coverage", "branch-evidence coverage report"),
    ("verdicts", "topology verdicts"),
    ("log_capture", "daemon-log capture report"),
    ("attribution_exact", "producer-attribution exactness flag"),
    ("mining_phase_total_attempts", "mining-phase attempt total"),
    ("mining_phase_rate_by_miner", "per-miner mining-phase rates"),
    ("threads_quiescent", "thread quiescence flag"),
    ("all_daemons_exited", "daemon exit flag"),
    ("blob_archive", "blob archive report"),
    ("start_state", "identical start state"),
    ("phase_boundaries", "phase boundaries"),
]


def validate(recs, verifier_results=None):
    """Strictly fail closed. A missing field is a FAILURE, never an implicit pass."""
    out = {"series_valid": False, "invalid_reasons": [], "counted": {}, "records": [],
           "pairs": [], "duplicates": []}
    reasons = out["invalid_reasons"]
    vres = verifier_results or {}
    by = {"none": [], "control": [], "attack": []}
    seen = {}
    topologies, series_ids = set(), set()

    for r in recs:
        c, rep = r.get("condition"), r.get("replicate")
        key = (c, rep)
        rid = f"{c}#{rep}"
        out["records"].append({"condition": c, "replicate": rep, "status": r.get("status"),
                               "attempt_id": r.get("attempt_id")})
        if key in seen:
            out["duplicates"].append(rid)
            reasons.append(f"{rid}: duplicate condition/replicate record")
        seen[key] = r
        topologies.add(r.get("topology"))
        if r.get("attempt_id"):
            series_ids.add(str(r.get("attempt_id")).split("#")[0])

        # ---- absence is failure ----
        for field, label in REQUIRED_FIELDS:
            if field not in r:
                reasons.append(f"{rid}: missing {label} ({field})")

        # --- strict types: presence is not enough, and null/str/list must not evade a gate ---
        def need_true(field):
            if r.get(field) is not True:
                reasons.append(f"{rid}: {field} is {r.get(field)!r}, required literal True")

        def need_dict(field):
            if not isinstance(r.get(field), dict) or not r.get(field):
                reasons.append(f"{rid}: {field} is not a non-empty dict "
                               f"({type(r.get(field)).__name__})")
                return False
            return True

        for f in ("threads_quiescent", "all_daemons_exited", "attribution_exact",
                  "mining_attempts_counter_agrees", "start_identical"):
            if f in r:
                need_true(f)
        for f in ("sample_coverage", "verdicts", "log_capture", "blob_archive", "start_state",
                  "phase_boundaries"):
            if f in r:
                need_dict(f)
        ba = r.get("blob_archive")
        if isinstance(ba, dict):
            for k in ("requested", "archived", "missing_count"):
                if not isinstance(ba.get(k), int):
                    reasons.append(f"{rid}: blob_archive.{k} is not an integer")
            if isinstance(ba.get("missing"), list) and ba.get("missing"):
                reasons.append(f"{rid}: blob_archive.missing is non-empty")
        if r.get("status") != "OK":
            reasons.append(f"{rid}: status {r.get('status')}")
        if r.get("start_identical") is not True:
            reasons.append(f"{rid}: start_identical is not true ({r.get('start_identical')!r})")
        elif start_tuple(r) is None:
            reasons.append(f"{rid}: start_identical claims true but the three nodes' start_state "
                           f"cannot be derived to one common value")
        cov = r.get("sample_coverage")
        if isinstance(cov, dict) and not cov.get("adequate"):
            reasons.append(f"{rid}: inadequate sample coverage {cov.get('failures')}")
        # Branch-evidence coverage is a SEPARATE preregistered gate. It is required to be present:
        # a record that never accounted for branch readability cannot be counted, because every
        # fork/PARTITION/RECOVERY verdict is derived from branch-readable samples only.
        bcov = r.get("branch_coverage")
        if not isinstance(bcov, dict):
            reasons.append(f"{rid}: missing branch-evidence coverage report (branch_coverage)")
        elif not bcov.get("adequate"):
            reasons.append(f"{rid}: inadequate branch-evidence coverage {bcov.get('failures')}")
        v = r.get("verdicts") or {}
        if not v.get("topology_conformant_throughout"):
            reasons.append(f"{rid}: topology not conformant throughout")
        lc = r.get("log_capture")
        if isinstance(lc, dict) and not lc.get("all_present"):
            reasons.append(f"{rid}: daemon logs incomplete {lc.get('missing')}")
        if r.get("threads_quiescent") is False:
            reasons.append(f"{rid}: threads were not quiescent at evidence capture")
        if r.get("all_daemons_exited") is False:
            reasons.append(f"{rid}: not every daemon exited")
        ba = r.get("blob_archive")
        if isinstance(ba, dict):
            if ba.get("missing_count"):
                reasons.append(f"{rid}: blob archive missing {ba['missing_count']} blocks")
            if ba.get("archived") != ba.get("requested"):
                reasons.append(f"{rid}: blob archive archived {ba.get('archived')} of "
                               f"{ba.get('requested')}")
        if r.get("attribution_exact") is False:
            reasons.append(f"{rid}: producer attribution not exact "
                           f"(ambiguous={r.get('ambiguous_accepted_count')}, "
                           f"unknown={r.get('unknown_outcome_count')})")
        elif "attribution_exact" not in r:
            reasons.append(f"{rid}: pre-correction schema -- no miner_evidence/producer_of, so "
                           f"producer-attributed aggregates are NOT independently reproducible")
        # offline verifier must have PASSED for every counted record
        vr = vres.get(rid) or vres.get(str(r.get("attempt_id")))
        if vr is None:
            reasons.append(f"{rid}: no offline verifier result supplied")
        elif not vr.get("passed"):
            reasons.append(f"{rid}: offline verifier FAILED ({(vr.get('failures') or [None])[0]})")
        if r.get("mining_attempts_counter_agrees") is False:
            reasons.append(f"{rid}: mining attempts recomputed from events disagree with counters")
        for msg in interval_integrity(r):
            reasons.append(f"{rid}: {msg}")
        # The third miner's MODE is bound to the condition. control_sham and adaptive walk the
        # same preparation path and differ only in whether the computed candidate is applied;
        # sample_verify checks that path per record, and this binds the declared mode to the arm.
        want_mode = {"control": "control_sham", "attack": "adaptive"}.get(r.get("condition"))
        got_mode = r.get("third_miner_mode")
        if want_mode and got_mode is not None and got_mode != want_mode:
            reasons.append(f"{rid}: third_miner_mode {got_mode!r} != {want_mode!r} required by "
                           f"condition {r.get('condition')}")
        if r.get("condition") == "none" and got_mode is not None:
            reasons.append(f"{rid}: a NONE record must declare no third_miner_mode, got "
                           f"{got_mode!r}")
        if r.get("condition") in ("control", "attack"):
            # EXACT: integer attacker attempts / integer total attempts, from the event stream.
            # The stored mining_phase_third_share is rounded to 5 decimals for display and must
            # never decide this gate.
            ex_sh = exact_third_share(r)
            stored_sh = r.get("mining_phase_third_share")
            if ex_sh is None:
                reasons.append(f"{rid}: third-miner share cannot be derived from the events")
            else:
                if ex_sh > EXACT_SHARE_CAP:
                    mc = mining_counts(r)
                    reasons.append(
                        f"{rid}: third share {float(ex_sh):.12f} "
                        f"({mc.get('atk', 0)}/{sum(mc.values())}) exceeds cap {THIRD_SHARE_CAP}")
                agree = stored_matches_derived(stored_sh, ex_sh, 5)
                if stored_sh is None:
                    reasons.append(f"{rid}: third-miner share missing")
                elif agree is False:
                    reasons.append(
                        f"{rid}: stored third share {stored_sh} disagrees with the raw events "
                        f"({float(ex_sh):.12f})")
        # The TOTAL attempt gate derives its counts from the events; the stored aggregate is a
        # display field. It is an integer, so it carries no rounding error and must match the
        # stream exactly -- a disagreement is a forgery signal, never a scientific finding.
        stored_tot = r.get("mining_phase_total_attempts")
        derived_tot = sum(mining_counts(r).values())
        if stored_tot is None:
            reasons.append(f"{rid}: mining_phase_total_attempts missing")
        elif not isinstance(stored_tot, int) or isinstance(stored_tot, bool):
            reasons.append(f"{rid}: mining_phase_total_attempts {stored_tot!r} is not an integer")
        elif stored_tot != derived_tot:
            reasons.append(f"{rid}: stored total attempts {stored_tot} disagrees with the raw "
                           f"events ({derived_tot})")
        if r.get("status") == "OK" and c in by:
            by[c].append(r)

    # A series must be ONE generation of the harness. Half the records carrying preparation-cycle
    # telemetry and half not is two experiments, and the path-parity claim would hold for only
    # some of them.
    gens = {r.get("condition") in ("control", "attack") and (r.get("third_miner_mode") is not None)
            for r in recs if r.get("condition") in ("control", "attack")}
    if len(gens) > 1:
        with_mode = sorted(f"{r.get('condition')}#{r.get('replicate')}" for r in recs
                           if r.get("third_miner_mode") is not None)
        reasons.append(f"the series mixes harness generations: {with_mode} declare a third-miner "
                       f"mode and the other control/attack records do not")

    # P0-1: identity must be complete on every record, and structurally consistent
    for r in recs:
        rid = f"{r.get('condition')}#{r.get('replicate')}"
        for k in ("series_id", "triplet_id", "matched_replicate_id", "attempt_id",
                  "condition", "replicate", "topology"):
            if r.get(k) in (None, ""):
                reasons.append(f"{rid}: identity field {k} missing or empty")
    tids = {r.get("triplet_id") for r in recs if r.get("triplet_id")}
    out["triplet_ids"] = sorted(tids)
    if tids and len(tids) != 3:
        reasons.append(f"{len(tids)} distinct triplet ids, expected exactly 3")
    repset = {r.get("replicate") for r in recs}
    if repset and repset != {1, 2, 3}:
        reasons.append(f"replicate set {sorted(x for x in repset if x is not None)} != {{1,2,3}}")
    for t in sorted(tids):
        members = sorted((r.get("condition") for r in recs if r.get("triplet_id") == t))
        if members != ["attack", "control", "none"]:
            reasons.append(f"triplet {t} members {members} != one each of none/control/attack")

    # Every counted record must begin from the SAME chain state. Nine records that each start
    # from a different tip are nine different experiments, not one series.
    starts = {}
    for r in recs:
        rid = f"{r.get('condition')}#{r.get('replicate')}"
        starts[rid] = start_tuple(r)
    distinct = {t for t in starts.values() if t is not None}
    out["start_tuples"] = {k: (list(v) if v else None) for k, v in starts.items()}
    if len(distinct) > 1:
        groups = {}
        for rid, t in starts.items():
            if t is not None:
                groups.setdefault(t, []).append(rid)
        reasons.append("records do not share one starting chain state: "
                       + "; ".join(f"{sorted(v)} start at height={k[1]} tip={str(k[2])[:12]}"
                                   for k, v in groups.items()))

    # P0-7: a PARTITION result may not validate without a corrected replay result
    part = [f"{r.get('condition')}#{r.get('replicate')}" for r in recs
            if (r.get("verdicts") or {}).get("PARTITION")]
    out["partition_records"] = part
    if part:
        rp = None
        for r in recs:
            rp = rp or r.get("replay_result")
        out["replay_gate"] = "REPLAY_REQUIRED"
        if not (isinstance(rp, dict) and rp.get("passed") is True and
                rp.get("complete") is True):
            reasons.append(f"PARTITION_PENDING_REPLAY: {part} recorded PARTITION but no complete, "
                           f"passing replay result is present -- the corrected replay is required "
                           f"before this series can validate")
    else:
        out["replay_gate"] = "NOT_TRIGGERED"

    if len(topologies) > 1:
        reasons.append(f"records span multiple topologies: {sorted(topologies)}")
    if topologies and not topologies <= {"full_mesh", "star"}:
        reasons.append(f"unknown topology value(s): {sorted(topologies)}")
    conds = {r.get("condition") for r in recs}
    if not conds <= {"none", "control", "attack"}:
        reasons.append(f"unknown condition value(s): {sorted(c for c in conds if c)}")
    sids = {r.get("series_id") for r in recs if r.get("series_id")}
    out["series_ids"] = sorted(sids)
    if len(sids) > 1:
        reasons.append(f"records span multiple series ids: {sorted(sids)}")
    aids = [r.get("attempt_id") for r in recs if r.get("attempt_id")]
    if len(aids) != len(set(aids)):
        reasons.append("duplicate attempt_id across records")
    if len(recs) != 9:
        reasons.append(f"{len(recs)} raw condition records, expected exactly 9")

    for c in ("none", "control", "attack"):
        reps = [r.get("replicate") for r in by[c]]
        out["counted"][c] = len(by[c])
        if len(set(reps)) != REQUIRED_PER_CONDITION or len(reps) != REQUIRED_PER_CONDITION:
            reasons.append(f"{c}: {len(reps)} valid records with {len(set(reps))} unique "
                           f"replicate ids, need exactly {REQUIRED_PER_CONDITION} unique")

    # ---- matched pairs: BOTH the total rate and the third-miner rate, separately ----
    ctl = {r.get("replicate"): r for r in by["control"]}
    atk = {r.get("replicate"): r for r in by["attack"]}
    for rep in sorted(set(ctl) | set(atk)):
        a, c = atk.get(rep), ctl.get(rep)
        if not a or not c:
            reasons.append(f"replicate {rep}: incomplete CONTROL/ATTACK pair")
            continue
        entry = {"replicate": rep}
        # EXACT: total mining attempts recomputed from the event streams. These are integers so
        # there is no rounding error, but mining_phase_total_attempts is still a STORED aggregate
        # and no stored field may decide a scientific gate on its own.
        ta, tc = sum(mining_counts(a).values()), sum(mining_counts(c).values())
        st_ta, st_tc = (a.get("mining_phase_total_attempts"),
                        c.get("mining_phase_total_attempts"))
        for side, stored, derived in (("control", st_tc, tc), ("attack", st_ta, ta)):
            if stored is not None and stored != derived:
                reasons.append(f"replicate {rep}: stored {side} total attempts {stored} "
                               f"disagrees with the {derived} recomputed from its events")
        if not isinstance(ta, int) or not isinstance(tc, int) or ta <= 0 or tc <= 0:
            reasons.append(f"replicate {rep}: attempt totals cannot be derived from the events "
                           f"as positive integers (control={tc!r} attack={ta!r})")
        else:
            # EXACT: symmetric deviation of two integer counts, compared with the frozen 1/50.
            # The previous form divided in binary float and compared against a float constant,
            # which can decide the boundary the wrong way even with exact integer inputs.
            dev = Fraction(2 * abs(tc - ta), tc + ta)
            entry.update({"control_attempts": tc, "attack_attempts": ta,
                          "total_deviation": round(float(dev), 12),
                          "total_deviation_exact": f"{dev.numerator}/{dev.denominator}",
                          "total_within_tolerance": dev <= EXACT_TOL})
            if dev > EXACT_TOL:
                reasons.append(f"replicate {rep}: TOTAL attempt deviation {float(dev):.10%} "
                               f"(exact {dev.numerator}/{dev.denominator}, from {tc} vs {ta} "
                               f"attempts) exceeds {float(EXACT_TOL):.0%}")
        # EXACT: derive both third-miner rates from integer mining-phase counts and each
        # record's own sealed interval. The stored mining_phase_rate_by_miner values are rounded
        # to 4 decimals for display and must never decide this gate.
        ex_ra, ex_rc = exact_third_rate(a), exact_third_rate(c)
        st_ra = (a.get("mining_phase_rate_by_miner") or {}).get("atk")
        st_rc = (c.get("mining_phase_rate_by_miner") or {}).get("atk")
        if ex_ra is None or ex_rc is None:
            reasons.append(f"replicate {rep}: third-miner rate cannot be derived from the events")
        else:
            dev3 = symmetric_deviation(ex_ra, ex_rc)
            na = mining_counts(a).get("atk", 0)
            nc = mining_counts(c).get("atk", 0)
            entry.update({"control_third_rate": st_rc, "attack_third_rate": st_ra,
                          "control_third_attempts": nc, "attack_third_attempts": na,
                          "control_third_rate_exact": float(ex_rc),
                          "attack_third_rate_exact": float(ex_ra),
                          "third_deviation": round(float(dev3), 12),
                          "third_within_tolerance": dev3 <= EXACT_TOL})
            if dev3 > EXACT_TOL:
                reasons.append(
                    f"replicate {rep}: THIRD-MINER rate deviation {float(dev3):.10%} "
                    f"(exact, from {nc} vs {na} attempts) exceeds "
                    f"{float(EXACT_TOL):.0%}")
            for side, stored, ex in (("control", st_rc, ex_rc), ("attack", st_ra, ex_ra)):
                if stored_matches_derived(stored, ex, 4) is False:
                    reasons.append(
                        f"replicate {rep}: stored {side} third-miner rate {stored} disagrees "
                        f"with the raw events ({float(ex):.10f})")
        out["pairs"].append(entry)

    # ---- NONE equilibrium, per node, explicit ----
    eq = []
    for r in by["none"]:
        pn = r.get("per_node")
        if not isinstance(pn, dict) or not pn:
            reasons.append(f"none#{r.get('replicate')}: per_node absent, cannot evaluate "
                           f"equilibrium")
            eq.append(False)
            continue
        eq.append(any((n or {}).get("equilibrium", {}).get("entered") for n in pn.values()))
    out["none_equilibrium_entered"] = sum(1 for e in eq if e)
    if len(by["none"]) and out["none_equilibrium_entered"] < 2:
        reasons.append(f"NONE reached equilibrium in only {out['none_equilibrium_entered']}/"
                       f"{len(by['none'])} replicates (need >=2)")

    out["series_valid"] = not reasons
    return out




START_FIELDS = ("genesis_hash", "height", "tip_hash", "tip_difficulty", "cumulative_difficulty")


def start_tuple(rec):
    """The canonical start state of a record, or None if it cannot be derived.

    Derived here as well as in sample_verify so the SERIES gate does not depend on a per-record
    verifier having run: every counted record must start from the same chain state, or the nine
    records are not one experiment."""
    st = rec.get("start_state")
    if not isinstance(st, dict) or not st:
        return None
    tuples = set()
    for n in ("h1", "h2", "atk"):
        d = st.get(n)
        if not isinstance(d, dict) or not d:
            return None
        tuples.add(tuple(d.get(f) for f in START_FIELDS))
    return next(iter(tuples)) if len(tuples) == 1 else None



# --------------------------------------------------------------------- exact scientific math
# A scientific gate must be decided from RAW SEALED PRIMITIVES -- integer attempt counts and the
# sealed mining interval -- never from a stored display aggregate. The driver rounds
# mining_phase_rate_by_miner to 4 decimals and mining_phase_third_share to 5 for human output
# (symmetric_series.py:696-698); comparing those rounded values against a frozen threshold can
# flip a verdict at the boundary in BOTH directions. Demonstrated counterexamples:
#
#   matched pair   C=3028 A=2968  exact 2.0013342228% (OVER)   rounded 1.9993395575% -> false PASS
#                  C=3030 A=2970  exact 2.0000000000% (within) rounded 2.0009899951% -> false FAIL
#   share cap      atk=3231 tot=38011  exact 0.085001710031307 (OVER) stored 0.085 -> false PASS
#
# Gate N (FULLMESH_20260826_gateN) is unaffected in verdict: its replicate-2 third-miner counts
# are CONTROL 3245 and ATTACK 3180, whose exact symmetric deviation is 130/6425 =
# 2.0233463035%, still above the frozen 2%. The historical sealed validator reported the rounded
# 2.0255%. Both fail; the series was and remains invalid. ATTACK#2 missed the admissible band by
# ONE attempt: 3181 would have given 1.9919078743%.
def mining_counts(rec):
    """Integer mining-phase attempts per miner, recomputed from the RAW event stream."""
    out = {}
    for name, m in (rec.get("miner_evidence") or {}).items():
        out[name] = sum(1 for e in (m.get("events") or [])
                        if e.get("phase") == "mining")
    return out


def _num(v):
    """A finite, non-boolean real number, or None. bool is rejected explicitly: in Python
    True == 1, so a boolean would otherwise sail through an isinstance(int) check."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v != v or v in (float("inf"), float("-inf")):
        return None
    return v


def mining_interval(rec):
    """The AUTHORITATIVE mining interval, derived from the sealed phase boundaries.

    mine_seconds_actual and mine_seconds are stored display/redundant fields; neither may decide a
    scientific gate. The interval that the attempt counts were actually accumulated over is
    boundary_mono - mining_start_mono, and that is what the exact rate arithmetic uses. The value
    is returned as a Fraction built from the serialized decimal text so no new binary-float
    rounding enters a threshold decision."""
    pb = rec.get("phase_boundaries")
    if not isinstance(pb, dict):
        return None
    start, end = _num(pb.get("mining_start_mono")), _num(pb.get("boundary_mono"))
    if start is None or end is None or not (end > start):
        return None
    return Fraction(str(end)) - Fraction(str(start))


def interval_integrity(rec):
    """Redundant interval fields cross-checked against the raw-derived interval.

    These never decide the scientific threshold; a disagreement is an independent fail-closed
    integrity reason. Returns a list of human-readable mismatches."""
    iv = mining_interval(rec)
    if iv is None:
        return ["mining interval cannot be derived from phase_boundaries"]
    out = []
    for field in ("mine_seconds_actual", "actual_mining_interval_s"):
        v = rec.get(field) if field in rec else (rec.get("phase_boundaries") or {}).get(field)
        if v is None:
            continue
        n = _num(v)
        if n is None:
            out.append(f"{field} is not a finite number ({v!r})")
        elif abs(Fraction(str(n)) - iv) > Fraction(1, 1000):
            out.append(f"{field} {v} disagrees with the {float(iv):.4f}s interval derived from "
                       f"phase_boundaries")
    nominal = _num(rec.get("mine_seconds"))
    if nominal is None:
        out.append("mine_seconds is missing or not a finite number")
    elif abs(Fraction(str(nominal)) - iv) > Fraction(1, 2):
        out.append(f"mine_seconds {nominal} disagrees with the {float(iv):.4f}s interval derived "
                   f"from phase_boundaries")
    return out


def exact_third_share(rec):
    """Exact attacker share as a Fraction of integer counts, or None if underivable."""
    m = mining_counts(rec)
    tot = sum(m.values())
    if not tot:
        return None
    return Fraction(m.get("atk", 0), tot)


def exact_third_rate(rec):
    """Exact attacker attempts per second as a Fraction, or None if underivable."""
    m = mining_counts(rec)
    iv = mining_interval(rec)          # already an exact Fraction from the sealed boundaries
    if iv is None or iv <= 0:
        return None
    return Fraction(m.get("atk", 0)) / iv


def symmetric_deviation(x, y):
    """2*|x-y| / (x+y), exact when x and y are Fractions."""
    tot = x + y
    if tot == 0:
        return Fraction(0)
    return abs(x - y) * 2 / tot


def stored_matches_derived(stored, derived, places):
    """A stored DISPLAY field must equal the correctly rounded derived value.

    Stored aggregates never decide a gate, but a stored value that disagrees with the raw events
    it claims to summarise is a forgery signal in its own right."""
    if stored is None or derived is None:
        return None
    try:
        return abs(float(stored) - round(float(derived), places)) < 10 ** -(places + 2)
    except (TypeError, ValueError):
        return False


def run_verifiers(raw_paths):
    """Run BOTH offline verifiers and merge them exactly once.

    The driver and the standalone CLI used to do different things: finalize_series() ran the
    producer verifier AND the sample verifier, while this module's CLI ran only the producer
    verifier, so `python3 series_validate.py <bundle>` could bless a series whose sample/rate
    evidence had never been checked. Both now call this one function.

    Returns (producer_results, sample_results, merged) where `merged` is what validate() consumes.
    """
    import evidence_verify as EVV
    import sample_verify as SAMPV
    vres, sres = {}, {}
    for q in raw_paths:
        if not q or not os.path.exists(q):
            continue
        r = EVV.verify(q)
        key = f"{r.get('condition')}#{r.get('replicate')}"
        r["digest"] = EVV.digest(r)
        vres[key] = r
        sr = SAMPV.verify_file(q)
        sr["digest"] = SAMPV.digest(sr)
        sres[key] = sr
    merged = {}
    for key, r in vres.items():
        sr = sres.get(key) or {}
        ok = bool(r.get("passed")) and bool(sr.get("passed"))
        reasons = list(r.get("failures") or [])
        reasons += [f"sample verifier: {x}" for x in (sr.get("failures") or [])]
        merged[key] = {"passed": ok, "failures": reasons,
                       "producer_digest": r.get("digest"), "sample_digest": sr.get("digest")}
    return vres, sres, merged


def main(argv):
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    recs = load(paths)
    # The offline verifier must pass for every counted record, so it is run here on the records
    # actually loaded -- including the raw records discovered beside a summary -- rather than
    # trusting a flag inside the record itself.
    try:
        vres, sres, merged = run_verifiers([rr.get("_path") for rr in recs])
    except Exception as e:
        print(f"verifiers could not be run: {type(e).__name__}: {e}")
        vres, sres, merged = {}, {}, {}
    print(f"producer verifier: {sum(1 for v in vres.values() if v.get('passed'))}/{len(vres)} "
          f"passed;  sample verifier: "
          f"{sum(1 for v in sres.values() if v.get('passed'))}/{len(sres)} passed")
    res = validate(recs, verifier_results=merged)
    print(json.dumps({k: v for k, v in res.items() if k != "records"}, indent=1))
    print(f"\nSERIES_VALID = {res['series_valid']}")
    for r in res["invalid_reasons"]:
        print(f"  ! {r}")
    return 0 if res["series_valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
