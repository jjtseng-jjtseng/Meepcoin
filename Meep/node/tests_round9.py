#!/usr/bin/env python3
"""Round-9 harness tests: scientific gates must decide on EXACT raw primitives.

NON-EVIDENCE. These validate the harness, never the protocol.

The defect (found by Regression testing after Commit O): series_validate.py decided two frozen scientific
thresholds from DISPLAY aggregates that symmetric_series.py had already rounded.

  symmetric_series.py:696   mining_phase_third_share  = round(atk/total, 5)
  symmetric_series.py:698   mining_phase_rate_by_miner = {n: round(count/interval, 4)}
  series_validate.py:184    third-share cap compared the rounded share
  series_validate.py:295    matched-pair 2% rule compared the rounded rates

Rounding can flip a frozen threshold in BOTH directions, proven below with integer counts:

  matched pair  C=3028 A=2968  exact 2.0013342228% (OVER)   rounded 1.9993395575% -> false PASS
                C=3030 A=2970  exact 2.0000000000% (within) rounded 2.0009899951% -> false FAIL
  share cap     atk=3231 tot=38011  exact 0.085001710031307 (OVER) stored 0.085 -> false PASS

GATE N IS UNAFFECTED IN VERDICT AND IS NEVER MODIFIED. Its replicate-2 third-miner counts are
CONTROL 3245 and ATTACK 3180: exact deviation 130/6425 = 2.0233463035%, still above the frozen
2%. The sealed historical validator reported the rounded 2.0255%. Both fail. ATTACK#2 missed the
admissible band by ONE attempt -- 3181 gives 1.9919078743%.

The frozen 2%, 8.5%, 900 s, 420 s, configured rates, topology, equilibrium, PARTITION and retry
rules are unchanged by this suite and by the repair it covers.

Usage: python3 node/tests_round9.py [--out=docs/round2/tests_round9.json]
"""
import glob, json, os, subprocess, sys, tempfile, time
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import series_validate as SV
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import build_series, full_record

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round9.json")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_N = os.path.join(REPO, "results/FULLMESH_20260826_gateN")
MINE_S = 900.0


def series_with(third_counts):
    """A disposable nine-record series whose attacker mining counts are exactly as requested.

    third_counts maps (condition, replicate) -> integer attacker mining attempts."""
    recs = []
    for rep in (1, 2, 3):
        for cond in ("none", "control", "attack"):
            n = third_counts.get((cond, rep))
            kw = {} if n is None else {"third_rate": n / MINE_S}
            recs.append(full_record(cond, rep, **kw))
    return recs


def counts_of(recs):
    # a real NONE record omits the atk miner entirely, so this must not assume the key
    return {("%s#%s" % (r["condition"], r["replicate"])):
            sum(1 for e in ((r["miner_evidence"].get("atk") or {}).get("events") or [])
                if e.get("phase") == "mining")
            for r in recs}


def validate(recs):
    """Run the real validator with all per-record verifier gates satisfied, so the only thing
    that can fail is the scientific arithmetic under test."""
    vres = {"%s#%s" % (r["condition"], r["replicate"]): {"passed": True, "failures": []}
            for r in recs}
    return SV.validate(recs, verifier_results=vres)


def reasons_matching(out, needle):
    return [x for x in out["invalid_reasons"] if needle in x]


# ------------------------------------------------------------------ baseline
def test_0_baseline():
    recs = series_with({})
    out = validate(recs)
    check("R9-0. BASELINE: an unmutated matched nine-record fixture is VALID with zero reasons",
          out["series_valid"] is True and not out["invalid_reasons"],
          out["invalid_reasons"][:3])
    c = counts_of(recs)
    check("R9-0b. and its CONTROL/ATTACK attacker counts are identical per replicate",
          all(c["control#%d" % r] == c["attack#%d" % r] for r in (1, 2, 3)),
          {k: v for k, v in c.items() if not k.startswith("none")})


# ------------------------------------------------------------------ the 2% matched-pair gate
def test_1_matched_pair_boundary():
    # exactly 2.000000%: 2*|3030-2970|/(3030+2970) = 120/6000 = 0.02 -> admissible (<=)
    ex = Fraction(2 * abs(3030 - 2970), 3030 + 2970)
    check("R9-1. arithmetic check: C=3030 A=2970 is EXACTLY 2%",
          ex == Fraction(2, 100), float(ex))
    out = validate(series_with({("control", 2): 3030, ("attack", 2): 2970}))
    check("R9-1b. a pair exactly AT 2% is admissible and the series stays valid",
          out["series_valid"] is True and not reasons_matching(out, "THIRD-MINER"),
          out["invalid_reasons"][:2])

    # immediately below
    out = validate(series_with({("control", 2): 3030, ("attack", 2): 2971}))
    check("R9-1c. a pair immediately BELOW 2% is admissible",
          not reasons_matching(out, "THIRD-MINER"), out["invalid_reasons"][:2])

    # immediately above
    out = validate(series_with({("control", 2): 3030, ("attack", 2): 2969}))
    check("R9-1d. a pair immediately ABOVE 2% is rejected",
          bool(reasons_matching(out, "THIRD-MINER")) and out["series_valid"] is False,
          reasons_matching(out, "THIRD-MINER")[:1])


def test_2_rounding_would_flip():
    """The two cases where the OLD rounded path disagreed with exact arithmetic."""
    # false PASS under rounding: exact is OVER 2%, rounded is under
    nc, na = 3028, 2968
    ex = Fraction(2 * abs(nc - na), nc + na)
    rc, ra = round(nc / MINE_S, 4), round(na / MINE_S, 4)
    rounded = abs(ra - rc) / ((ra + rc) / 2)
    check("R9-2. C=3028 A=2968: exact is OVER 2% while the rounded path is under",
          ex > Fraction(2, 100) and rounded <= 0.02,
          "exact %.10f%% rounded %.10f%%" % (100 * float(ex), 100 * rounded))
    out = validate(series_with({("control", 2): nc, ("attack", 2): na}))
    check("R9-2b. the corrected validator REJECTS it (the old path would have passed it)",
          bool(reasons_matching(out, "THIRD-MINER")) and out["series_valid"] is False,
          reasons_matching(out, "THIRD-MINER")[:1])

    # false FAIL under rounding: exact is exactly 2%, rounded is over
    nc, na = 3030, 2970
    rc, ra = round(nc / MINE_S, 4), round(na / MINE_S, 4)
    rounded = abs(ra - rc) / ((ra + rc) / 2)
    check("R9-2c. C=3030 A=2970: exact is exactly 2% while the rounded path is over",
          Fraction(2 * abs(nc - na), nc + na) == Fraction(2, 100) and rounded > 0.02,
          "rounded %.10f%%" % (100 * rounded))
    out = validate(series_with({("control", 2): nc, ("attack", 2): na}))
    check("R9-2d. the corrected validator ACCEPTS it (the old path would have failed it)",
          not reasons_matching(out, "THIRD-MINER"), out["invalid_reasons"][:2])


def test_3_forged_stored_rate():
    """A forged display field must not decide the SCIENTIFIC gate in either direction.

    It is not inert: series_validate reports a stored value that disagrees with the events it
    claims to summarise as its own invalid reason, so a forged record is still refused -- as a
    forgery, on the forgery's own evidence, and never as a rate finding."""
    recs = series_with({("control", 2): 3030, ("attack", 2): 2969})   # genuinely OVER 2%
    for r in recs:
        if (r["condition"], r["replicate"]) == ("attack", 2):
            r["mining_phase_rate_by_miner"]["atk"] = 3.3667      # forged to look matched
    out = validate(recs)
    check("R9-3. a forged stored rate cannot BLESS a genuinely over-tolerance pair",
          bool(reasons_matching(out, "THIRD-MINER")) and out["series_valid"] is False,
          reasons_matching(out, "THIRD-MINER")[:1])
    check("R9-3b. and the forgery itself is reported against the raw events",
          bool(reasons_matching(out, "disagrees with the raw events")),
          reasons_matching(out, "disagrees with the raw events")[:1])

    recs = series_with({})                                            # genuinely matched
    for r in recs:
        if (r["condition"], r["replicate"]) == ("attack", 2):
            r["mining_phase_rate_by_miner"]["atk"] = 9.9999      # forged to look mismatched
    out = validate(recs)
    check("R9-3c. a forged stored rate cannot raise a THIRD-MINER rate finding against a "
          "genuinely matched pair",
          not reasons_matching(out, "THIRD-MINER rate deviation"),
          reasons_matching(out, "THIRD-MINER")[:1])
    check("R9-3d. it is refused as a forgery instead, on the raw events",
          bool(reasons_matching(out, "disagrees with the raw events")),
          reasons_matching(out, "disagrees with the raw events")[:1])


# ------------------------------------------------------------------ the 8.5% share gate
def test_4_share_cap_boundary():
    def share_series(atk, honest_each):
        """One CONTROL record with an exact attacker share; the rest matched and clean."""
        recs = []
        for rep in (1, 2, 3):
            for cond in ("none", "control", "attack"):
                if (cond, rep) == ("control", 1):
                    recs.append(full_record(cond, rep, third_rate=atk / MINE_S,
                                            honest_rate=honest_each / MINE_S))
                else:
                    recs.append(full_record(cond, rep))
        return recs

    # An exact share just OVER the cap that the driver's round(.,5) reports as exactly 0.085.
    # tot - atk must be even so the two honest miners can realise it, and the counts below are
    # asserted against the generated stream: a declared pair the fixture cannot actually produce
    # would prove nothing about the gate. (3231/38010 was declared in the first draft of this
    # test; the honest split is fractional there, the stream really carried 38009, and 3231/38009
    # rounds to 0.08501 -- so that fixture never exercised the false-pass path at all.)
    atk, tot = 3231, 38011
    honest = (tot - atk) // 2
    ex = Fraction(atk, tot)
    check("R9-4. arithmetic check: atk=%d tot=%d is OVER 0.085 but rounds to 0.085" % (atk, tot),
          ex > Fraction(85, 1000) and round(atk / tot, 5) == 0.085,
          "exact %.15f stored %.5f" % (float(ex), round(atk / tot, 5)))
    recs = share_series(atk, honest)
    got = counts_of(recs)["control#1"]
    tot_got = sum(sum(1 for e in r["miner_evidence"][n]["events"] if e["phase"] == "mining")
                  for r in recs if (r["condition"], r["replicate"]) == ("control", 1)
                  for n in r["miner_evidence"])
    check("R9-4a. the FIXTURE really produces those counts in its own event stream",
          (got, tot_got) == (atk, tot)
          and Fraction(got, tot_got) > Fraction(85, 1000)
          and round(got / tot_got, 5) == 0.085,
          "generated atk=%d tot=%d exact=%.15f round5=%.5f"
          % (got, tot_got, got / tot_got, round(got / tot_got, 5)))
    out = validate(recs)
    check("R9-4b. the corrected validator REJECTS the over-cap share (old path passed it)",
          bool(reasons_matching(out, "exceeds cap")) and out["series_valid"] is False,
          [reasons_matching(out, "exceeds cap")[:1], "atk=%d tot=%d" % (got, tot_got)])

    # a share comfortably under the cap must stay admissible
    out = validate(series_with({}))
    check("R9-4c. a normal in-band share raises no cap reason",
          not reasons_matching(out, "exceeds cap"), out["invalid_reasons"][:2])


def test_5_forged_stored_share():
    recs = series_with({})
    for r in recs:
        if (r["condition"], r["replicate"]) == ("control", 1):
            r["mining_phase_third_share"] = 0.5          # forged, raw events unchanged
    out = validate(recs)
    check("R9-5. a forged stored share cannot raise a cap finding against an in-band record",
          not reasons_matching(out, "exceeds cap"),
          reasons_matching(out, "exceeds cap")[:1])
    check("R9-5b. but the forgery is surfaced against the raw events",
          bool(reasons_matching(out, "disagrees with the raw events")),
          reasons_matching(out, "disagrees with the raw events")[:1])


# ------------------------------------------------------------------ Gate N, read-only
def test_6_gate_n_unchanged():
    """The corrected arithmetic must leave the historical verdict intact. READ-ONLY."""
    raws = sorted(glob.glob(os.path.join(GATE_N, "raw", "*.json")))
    check("R9-6. Gate N still has nine raw records on disk", len(raws) == 9, len(raws))
    recs = [json.load(open(q, encoding="utf-8")) for q in raws]
    c = counts_of(recs)
    check("R9-6b. its replicate-2 attacker counts are CONTROL 3245 and ATTACK 3180",
          c["control#2"] == 3245 and c["attack#2"] == 3180,
          [c["control#2"], c["attack#2"]])
    ex = Fraction(2 * abs(3245 - 3180), 3245 + 3180)
    check("R9-6c. the exact deviation is 130/6425 = 2.0233463035%, still above 2%",
          ex == Fraction(130, 6425) and ex > Fraction(2, 100),
          "%.10f%%" % (100 * float(ex)))
    better = Fraction(2 * abs(3245 - 3181), 3245 + 3181)
    check("R9-6d. it missed the band by ONE attempt: 3181 would have been admissible",
          better <= Fraction(2, 100), "%.10f%%" % (100 * float(better)))
    out = validate(recs)
    check("R9-6e. the corrected validator still reports series_valid FALSE",
          out["series_valid"] is False, out["series_valid"])
    m = reasons_matching(out, "THIRD-MINER")
    check("R9-6f. for exactly the replicate-2 third-miner rule, now stated exactly",
          len(m) == 1 and "2.0233463035%" in m[0] and "3245 vs 3180" in m[0], m[:1])
    check("R9-6g. and that is still the ONLY invalid reason",
          len(out["invalid_reasons"]) == 1, out["invalid_reasons"])


def test_7_audited_gates_still_exact():
    """Gates that were already exact must not have regressed."""
    recs = series_with({})
    out = validate(recs)
    p2 = [p for p in out["pairs"] if p["replicate"] == 2][0]
    check("R9-7. the TOTAL attempt gate still uses integer counts",
          isinstance(p2["control_attempts"], int) and isinstance(p2["attack_attempts"], int),
          [p2["control_attempts"], p2["attack_attempts"]])
    check("R9-7b. the pair record now also carries the exact third-miner attempt counts",
          isinstance(p2.get("control_third_attempts"), int)
          and isinstance(p2.get("attack_third_attempts"), int),
          [p2.get("control_third_attempts"), p2.get("attack_third_attempts")])
    check("R9-7c. and the exact rates alongside the rounded display values",
          "control_third_rate_exact" in p2 and "attack_third_rate_exact" in p2,
          sorted(k for k in p2 if "third" in k))


# ------------------------------------------------ the TOTAL matched-attempt gate, exactly
def total_series(hc, ha, atk=3240):
    """A nine-record series whose replicate-2 TOTAL attempt counts are set precisely.

    The attacker count is held IDENTICAL in both arms so the third-miner rule stays silent and
    the only gate under test is the TOTAL one; the honest miners carry the difference."""
    recs = []
    for rep in (1, 2, 3):
        for cond in ("none", "control", "attack"):
            if rep == 2 and cond in ("control", "attack"):
                h = hc if cond == "control" else ha
                recs.append(full_record(cond, rep, third_rate=atk / MINE_S,
                                        honest_rate=h / MINE_S))
            else:
                recs.append(full_record(cond, rep))
    return recs


def totals_of(recs, rid):
    for r in recs:
        if "%s#%s" % (r["condition"], r["replicate"]) == rid:
            return sum(sum(1 for e in v["events"] if e.get("phase") == "mining")
                       for v in r["miner_evidence"].values())
    return None


def test_8_total_gate_is_exact():
    """The TOTAL rule now derives integer counts from the events and compares with Fraction(1,50).

    HONEST SCOPE. Unlike the rate gate -- where the driver's round(., 4) demonstrably flipped the
    verdict in both directions -- no float-vs-exact flip is reachable here at experiment
    magnitudes: the counts are integers, so two distinct ratios differ by at least 1/(50*S) with
    S ~ 8e4, roughly ten orders of magnitude above a double's resolution near 0.02. This gate was
    repaired for its TRUST CLASS, not for a demonstrated numerical error: it read the stored
    aggregate mining_phase_total_attempts and compared in binary float against a float constant.
    What follows therefore proves the boundary behaviour and the derivation, and does not claim a
    flip that does not exist."""
    # 2*|40400-39600| / 80000 = 1600/80000 = 1/50, exactly at the frozen tolerance
    hc, ha = 18580, 18180
    recs = total_series(hc, ha)
    tc, ta = totals_of(recs, "control#2"), totals_of(recs, "attack#2")
    ex = Fraction(2 * abs(tc - ta), tc + ta)
    check("R9-8. the fixture really produces totals exactly AT the 2% boundary",
          (tc, ta) == (40400, 39600) and ex == Fraction(1, 50),
          "control=%s attack=%s exact=%s" % (tc, ta, ex))
    out = validate(recs)
    p2 = [x for x in out["pairs"] if x["replicate"] == 2][0]
    check("R9-8b. a TOTAL deviation exactly AT 2% is admissible (<=, not <)",
          not reasons_matching(out, "TOTAL attempt deviation")
          and p2["total_within_tolerance"] is True, out["invalid_reasons"][:2])
    check("R9-8c. and the pair carries the deviation as an exact rational, not only a float",
          p2.get("total_deviation_exact") == "1/50", p2.get("total_deviation_exact"))

    # one honest attempt further apart -> 802/39999 > 1/50
    recs = total_series(hc, ha - 1)
    tc, ta = totals_of(recs, "control#2"), totals_of(recs, "attack#2")
    ex = Fraction(2 * abs(tc - ta), tc + ta)
    check("R9-8d. arithmetic check: two attempts further apart is over the band",
          ex > Fraction(1, 50), "%s = %.12f%%" % (ex, 100 * float(ex)))
    out = validate(recs)
    check("R9-8e. and the validator REJECTS it, naming the counts it derived",
          bool(reasons_matching(out, "TOTAL attempt deviation"))
          and out["series_valid"] is False
          and ("%d vs %d" % (tc, ta)) in reasons_matching(out, "TOTAL attempt deviation")[0],
          reasons_matching(out, "TOTAL attempt deviation")[:1])

    # one honest attempt closer -> 798/40001 < 1/50
    recs = total_series(hc, ha + 1)
    out = validate(recs)
    check("R9-8f. two attempts closer stays admissible",
          not reasons_matching(out, "TOTAL attempt deviation"), out["invalid_reasons"][:2])


def test_9_total_gate_ignores_the_stored_aggregate():
    """mining_phase_total_attempts is a display field and must decide nothing."""
    recs = total_series(18580, 18179)                    # genuinely OVER the band
    for r in recs:
        if (r["condition"], r["replicate"]) == ("attack", 2):
            r["mining_phase_total_attempts"] = 40400     # forged to look matched
    out = validate(recs)
    check("R9-9. a forged stored total cannot BLESS a genuinely over-band pair",
          bool(reasons_matching(out, "TOTAL attempt deviation"))
          and out["series_valid"] is False,
          reasons_matching(out, "TOTAL attempt deviation")[:1])

    recs = series_with({})                               # genuinely matched
    for r in recs:
        if (r["condition"], r["replicate"]) == ("attack", 2):
            r["mining_phase_total_attempts"] = 1         # forged to look wildly mismatched
    out = validate(recs)
    check("R9-9b. and a forged stored total raises no TOTAL finding against matched events",
          not reasons_matching(out, "TOTAL attempt deviation"),
          reasons_matching(out, "TOTAL")[:1])
    check("R9-9c. the forgery is refused on its own evidence instead",
          bool(reasons_matching(out, "disagrees with the raw events")),
          reasons_matching(out, "disagrees with the raw events")[:1])


# ------------------------------------------------ the mining interval, from sealed boundaries
def test_10_interval_from_raw_boundaries():
    rec = full_record("control", 1)
    iv = SV.mining_interval(rec)
    pb = rec["phase_boundaries"]
    check("R9-10. the interval is derived from boundary_mono - mining_start_mono",
          isinstance(iv, Fraction)
          and iv == Fraction(str(pb["boundary_mono"])) - Fraction(str(pb["mining_start_mono"])),
          [str(iv), pb["mining_start_mono"], pb["boundary_mono"]])
    check("R9-10b. an honest record raises no interval-integrity reason",
          SV.interval_integrity(rec) == [], SV.interval_integrity(rec))

    # the redundant stored fields cannot substitute for the boundaries
    for field, forged in (("mine_seconds_actual", 450.0), ("mine_seconds", 450.0)):
        bad = full_record("control", 1)
        bad[field] = forged
        check("R9-10c. a forged %s does not move the derived interval" % field,
              SV.mining_interval(bad) == iv, [str(SV.mining_interval(bad)), str(iv)])
        check("R9-10d. and it is reported as an integrity mismatch (%s)" % field,
              any(field in m for m in SV.interval_integrity(bad)),
              SV.interval_integrity(bad))

    bad = full_record("control", 1)
    bad["phase_boundaries"]["actual_mining_interval_s"] = 450.0
    check("R9-10e. a forged actual_mining_interval_s inside phase_boundaries is caught too",
          any("actual_mining_interval_s" in m for m in SV.interval_integrity(bad)),
          SV.interval_integrity(bad))

    # non-numbers and impossible orderings must fail closed, never default to a number
    for pb_mut, why in (({"boundary_mono": None}, "null boundary"),
                        ({"mining_start_mono": True}, "boolean start"),
                        ({"boundary_mono": float("nan")}, "NaN boundary"),
                        ({"boundary_mono": 0.0}, "end not after start")):
        bad = full_record("control", 1)
        bad["phase_boundaries"].update(pb_mut)
        check("R9-10f. %s -> no interval is derived and the record is not silently rated" % why,
              SV.mining_interval(bad) is None and SV.exact_third_rate(bad) is None,
              [str(SV.mining_interval(bad)), str(SV.exact_third_rate(bad))])

    bad = full_record("control", 1)
    bad.pop("phase_boundaries")
    out = validate([bad] + [r for r in series_with({}) if
                            (r["condition"], r["replicate"]) != ("control", 1)])
    check("R9-10g. a record with no phase_boundaries makes the series invalid, not unrated",
          out["series_valid"] is False
          and bool(reasons_matching(out, "mining interval cannot be derived")),
          out["invalid_reasons"][:2])


def test_11_forged_interval_cannot_rescue_a_pair():
    """The old path read mine_seconds_actual; a forged one could have hidden a real mismatch."""
    recs = series_with({("control", 2): 3245, ("attack", 2): 3180})    # the Gate N deficit
    out = validate(recs)
    check("R9-11. the honest fixture reproduces the Gate N rejection",
          bool(reasons_matching(out, "THIRD-MINER")), reasons_matching(out, "THIRD-MINER")[:1])
    # forge the ATTACK arm's stored interval so its stored RATE would look matched
    for r in recs:
        if (r["condition"], r["replicate"]) == ("attack", 2):
            r["mine_seconds_actual"] = 900.0 * 3180 / 3245
    out = validate(recs)
    check("R9-11b. forging mine_seconds_actual does NOT rescue the pair",
          bool(reasons_matching(out, "THIRD-MINER")) and out["series_valid"] is False,
          reasons_matching(out, "THIRD-MINER")[:1])
    check("R9-11c. and the forged interval is itself reported",
          bool(reasons_matching(out, "mine_seconds_actual")),
          reasons_matching(out, "mine_seconds_actual")[:1])


def main():
    print("NON-EVIDENCE round-9 harness tests: exact arithmetic for frozen scientific gates\n")
    for fn in (test_0_baseline, test_1_matched_pair_boundary, test_2_rounding_would_flip,
               test_3_forged_stored_rate, test_4_share_cap_boundary, test_5_forged_stored_share,
               test_6_gate_n_unchanged, test_7_audited_gates_still_exact,
               test_8_total_gate_is_exact,
               test_9_total_gate_ignores_the_stored_aggregate,
               test_10_interval_from_raw_boundaries,
               test_11_forged_interval_cannot_rescue_a_pair):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round9", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round9.py",)),
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
