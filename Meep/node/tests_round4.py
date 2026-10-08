#!/usr/bin/env python3
"""Round-4 harness tests. NON-EVIDENCE: they validate the harness, never the protocol.

Covers the final pre-long-run gate:

  P0-1  identity present on the record and cross-checked against events
  P0-2  POSITIVE nine-record end-to-end finalization reaching series_valid=true, plus negatives
  P0-3  lifecycle safety (init before try, no UnboundLocalError, daemon counts)
  P0-4  phase clock: fixed boundaries, atomic dispatch close, transition phase
  P0-5  anchored lag-vs-fork, canonical validation, recovery run start
  P0-6  configured-rate floors
  P0-7  PARTITION without replay can never validate

Usage: python3 node/tests_round4.py [--out=docs/round2/tests_round4.json]
"""
import hashlib, io, json, os, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import branch_evidence as BE
import bundle_verify as BV
import sample_verify as SAMPV
import series_validate as SV
import symmetric_series as SS
from provenance import Provenance
from tests_round2 import synth_record, check, RESULTS, report_metadata, CORE_SOURCES

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round4.json")
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERIES = "TESTSERIES"


def full_record(cond, rep, mine_s=900.0, third_rate=3.6, honest_rate=20.7, partition=False,
                drop_identity=False, bad_event_series=False, drop_atk=False, starve_atk=None):
    """A schema-complete record whose stored aggregates agree with its own events."""
    rec = synth_record()
    tid = f"{SERIES}#rep{rep}"
    ident = {"series_id": SERIES, "triplet_id": tid, "matched_replicate_id": tid,
             "attempt_id": f"ns_{cond}{rep}_a1", "condition": cond, "replicate": rep,
             "topology": "full_mesh"}
    rec.update(ident)
    if drop_identity:
        rec.pop("series_id", None)
    ev = rec["miner_evidence"]
    if cond == "none" or drop_atk:
        ev["atk"]["events"] = []
    want = {"h1": honest_rate, "h2": honest_rate,
            "atk": (starve_atk if starve_atk is not None else third_rate)}
    for n, m in ev.items():
        target = int(want[n] * mine_s) if (n != "atk" or cond != "none") else 0
        if drop_atk and n == "atk":
            target = 0
        base = list(m["events"])
        out, seq = [], 0
        while len(out) < target:
            for e in (base or [{"outcome": "REJECTED", "block_id": None,
                                "blob_sha256": "0" * 64}]):
                if len(out) >= target:
                    break
                seq += 1
                _d = seq * (mine_s / (target + 1.0))
                e2 = dict(e, miner=n, seq=seq, phase="mining",
                          dispatch_mono=_d, completed_mono=_d + 0.01, **ident)
                if e2.get("outcome") == "ACCEPTED" and seq > len(m.get("block_ids") or []) * 2:
                    e2 = dict(e2, outcome="REJECTED", block_id=None)
                out.append(e2)
        if bad_event_series and n == "h1" and out:
            out[0] = dict(out[0], series_id="OTHER_SERIES")
        m["events"] = out
        m["event_count"] = len(out)
        m["block_ids"] = sorted({e["block_id"] for e in out
                                 if e.get("outcome") == "ACCEPTED" and e.get("block_id")})
        m["stats"] = {"candidate_attempts": len(out),
                      "local_accepted": sum(1 for e in out if e.get("outcome") == "ACCEPTED")}
    pof = {}
    for n, m in ev.items():
        for b in m["block_ids"]:
            pof[b] = n
    rec["producer_of"] = pof
    seq_hdrs = rec["canonical_headers"]["h1"]
    keep = [b for b in seq_hdrs if b["hash"] in pof]
    rec["canonical_headers"]["h1"] = keep
    blocks, work = {}, {}
    for b in keep:
        p = pof.get(b["hash"], "unattributed")
        blocks[p] = blocks.get(p, 0) + 1
        work[p] = work.get(p, 0) + b["difficulty"]
    totw = sum(work.values()) or 1
    import evidence_verify as EV
    occ = EV.rolling_occupancy(keep, pof)
    rec["per_node"] = {"h1": {
        "accepted_work": {p: {"blocks": blocks[p], "work": work[p],
                              "work_share": round(work[p] / totw, 5)} for p in work},
        "max_window_occupancy": {p: max([w.get(p, 0) for w in occ] or [0])
                                 for p in ("h1", "h2", "atk", "unattributed")},
        "canonical_blocks_after_start": len(keep),
        "equilibrium": {"entered": True}}}
    rec["blob_archive"] = {"requested": len(keep), "archived": len(keep), "missing_count": 0,
                           "missing": []}
    real = {n: len(m["events"]) for n, m in ev.items()}
    tot = sum(real.values())
    rec.update({
        "status": "OK", "mine_seconds": mine_s, "mine_seconds_actual": mine_s,
        "configured_rates": {
            "total": honest_rate * 2 + (0.0 if (cond == "none" or drop_atk) else third_rate),
            "third": (0.0 if cond == "none" else third_rate), "honest": honest_rate},
        "mining_phase_attempts": real, "mining_attempts_from_events": real,
        "mining_phase_total_attempts": tot, "mining_attempts_counter_agrees": True,
        "mining_phase_rate_by_miner": {n: round(v / mine_s, 4) for n, v in real.items()},
        # the driver rounds this to 5 decimals for display (symmetric_series.py:696); the
        # fixture must store it the same way or it will not look like a real record
        "mining_phase_third_share": round(real["atk"] / tot, 5) if tot else 0.0,
        "threads_quiescent": True, "all_daemons_exited": True, "start_identical": True,
        # a real, derivable start state: the three nodes must be provably identical
        "start_state": {n: dict(START_TUPLE) for n in ("h1", "h2", "atk")},
        "sample_coverage": {"adequate": True},
        "log_capture": {"all_present": True},
        "attribution_exact": True,
        "verdicts": {"topology_conformant_throughout": True, "PARTITION": partition,
                     "longest_h1_h2_fork_run_samples": 20 if partition else 0,
                     "RECOVERY": True},
        "samples": build_samples(mine_s, 420.0, 15.0, partition, post0=mine_s + 1.0),
    })
    rec["post_seconds"] = 420.0
    rec["sample_seconds"] = 15.0
    post0 = mine_s + 1.0
    rec["phase_boundaries"] = {"mining_start_mono": 0.0,
                               "boundary_mono": mine_s,
                               "nominal_mining_end_mono": mine_s,
                               "post_start_mono": post0,
                               "post_end_mono": post0 + 420.0,
                               "transition_latency_s": 1.0,
                               "actual_mining_interval_s": round(mine_s, 4)}
    # the sealed clock the sampler and the miners shared; it must agree with the boundaries
    rec["phase_clock"] = {"mining_start_mono": 0.0, "mining_end_mono": mine_s,
                          "post_start_mono": post0, "post_end_mono": post0 + 420.0,
                          # attacker closes at mining end (only when it runs); the honest miners
                          # close at post end
                          "dispatch_scheduled_close_mono": (
                              {"h1": post0 + 420.0, "h2": post0 + 420.0}
                              if (cond == "none" or drop_atk) else
                              {"atk": mine_s, "h1": post0 + 420.0, "h2": post0 + 420.0}),
                          "dispatch_closed_mono": {"atk": mine_s}}
    rec["mine_seconds_actual"] = round(mine_s, 4)
    mining = [x for x in rec["samples"] if x.get("phase") == "mining"]
    rec["verdicts"]["longest_h1_h2_fork_run_samples"] = (
        sum(1 for x in mining if x.get("h1_h2_genuinely_forked")))
    post = [x for x in rec["samples"] if x.get("phase") == "post_stop"]
    rec["verdicts"]["RECOVERY"] = len(post) >= 3
    rec["verdicts"]["recovery_first_qualifying_index"] = 0 if len(post) >= 3 else None
    rec["verdicts"]["recovery_first_sample_t"] = (
        round(post[0]["t_mono"] - rec["phase_boundaries"]["post_start_mono"], 1)
        if len(post) >= 3 else None)
    return resync_coverage(rec)


GEN = "9" * 64
ANCHOR_H = 30
ANCH = "c" * 64
TIP_A, TIP_B = "a" * 64, "b" * 64
START_TUPLE = {"genesis_hash": GEN, "height": 31, "tip_hash": "d" * 64,
               "tip_difficulty": 1, "cumulative_difficulty": 31}


def _seq(tip, n_after=1):
    """An anchored sequence [anchor, ... , tip] of length n_after+1, all distinct 64-hex."""
    mid = ["%064x" % (0xA00 + i) for i in range(n_after - 1)]
    return [ANCH] + mid + [tip]


def _be(tip, n_after=1):
    seq = _seq(tip, n_after)
    return {"tip": tip, "height": ANCHOR_H + len(seq), "anchor_height": ANCHOR_H,
            "anchor_hash": ANCH, "cum": 100, "chain_len": len(seq),
            "chain_digest": hashlib.sha256("".join(seq).encode()).hexdigest(),
            "anchored_hashes": seq}


def _adjacency(nodes=("h1", "h2", "atk")):
    """A full-mesh adjacency in the shape topology.snapshot() produces."""
    adj = {}
    for a in nodes:
        adj[a] = {b: [{"direction": "out", "peer_id": "p", "state": "normal"}]
                  for b in nodes if b != a}
    return adj


def one_sample(phase, t_mono, forked=False, readable=True, topo_ok=True, topo_obs=True,
               atk_tip=None, scheduled=None, topology="full_mesh"):
    """A schema-complete sample carrying evidence a verifier can fully re-derive from."""
    import topology as _T
    sc = t_mono if scheduled is None else scheduled
    sm = {"phase": phase, "t_mono": t_mono, "t": 1700000000.0 + t_mono,
          "scheduled_mono": sc, "late_by_s": round(t_mono - sc, 4),
          "topology_observed": topo_obs, "topology_error": None,
          "branch_readable": readable, "branch_error": None}
    if topo_obs:
        adj = _adjacency()
        if not topo_ok:
            adj["h1"].pop("h2", None)
            adj["h2"].pop("h1", None)
        conf = _T.conformance({"adjacency": adj, "rpc_errors": [], "unresolved": []},
                              ["h1", "h2", "atk"], topology)
        sm.update({"adjacency": adj, "rpc_errors": [], "unresolved": [],
                   "conformance": conf, "topology_conformant": conf["conformant"],
                   "links": sorted({tuple(sorted((a, b))) for a, ps in adj.items() for b in ps}),
                   "links_missing": conf["missing"],
                   "links_forbidden_present": conf["forbidden_present"]})
    else:
        sm.update({"topology_conformant": False,
                   "topology_error": "RuntimeError: injected"})
    if not readable:
        sm.update({"branch_error": "InconsistentView: injected", "tips": None,
                   "all_same_tip": None, "h1_h2_genuinely_forked": None,
                   "branch_evidence": None, "tips_differ": None})
        return sm
    h2_tip = TIP_B if forked else TIP_A
    a_tip = atk_tip or TIP_A
    be = {"h1": _be(TIP_A), "h2": _be(h2_tip), "atk": _be(a_tip)}
    tips = {n: {"height": be[n]["height"], "tip": be[n]["tip"]} for n in be}
    differ = len({be[n]["tip"] for n in be}) > 1
    # the last block h1 and h2 agree on: the whole chain when tips match, the anchor when the
    # final element differs
    ha, hb = be["h1"]["anchored_hashes"], be["h2"]["anchored_hashes"]
    n_common = 0
    for x, y in zip(ha, hb):
        if x != y:
            break
        n_common += 1
    sm.update({"tips": tips, "branch_evidence": be, "tips_differ": differ,
               "all_same_tip": not differ,
               "h1_h2_genuinely_forked": TIP_A != h2_tip,
               "h1_h2_common_ancestor": ANCHOR_H + n_common - 1 if n_common else None})
    return sm


def build_samples(mine_s, post_s, sample_s, partition=False, start=0.0, post0=None):
    """A COMPLETE schedule: every slot the sampler would actually have taken.

    The fixture must be able to survive an honest cadence check, not merely an honest row count.
    """
    out = []
    for i in range(int(mine_s // sample_s)):
        out.append(one_sample("mining", start + i * sample_s, forked=partition))
    p0 = (start + mine_s + 1.0) if post0 is None else post0
    for i in range(int(post_s // sample_s)):
        out.append(one_sample("post_stop", p0 + i * sample_s))
    return out


def build_events(rec, mine_s, post_start, post_end, sample_of=None):
    """Give every miner event a dispatch_mono consistent with its stored phase."""
    for name, m in rec["miner_evidence"].items():
        rows = m.get("events") or []
        n = len(rows)
        for i, e in enumerate(rows):
            e["seq"] = i + 1
            e["phase"] = "mining"
            e["dispatch_mono"] = (i + 1) * (mine_s / (n + 1.0)) if n else 0.0
    return rec


def resync_coverage(rec):
    """Recompute BOTH stored coverage reports after a test substitutes the sample list.

    Tests that swap in a hand-built sample list must not leave the fixture's coverage report
    describing the samples it replaced -- that would be a fixture bug masquerading as a
    verifier disagreement."""
    import coverage as _COV
    ms = rec.get("mine_seconds", 900.0)
    ps = rec.get("post_seconds", 420.0)
    ss = rec.get("sample_seconds", 15.0)
    rec["sample_coverage"] = _COV.evaluate(rec["samples"], ms, ps, ss, _COV.TOPO_MIN_FRACTION,
                                           _COV.TOPO_MIN_SAMPLES, _COV.TOPO_MAX_NONCONFORMANT)
    rec["branch_coverage"] = _COV.branch_evaluate(rec["samples"], ms, ps, ss,
                                                  _COV.BRANCH_MAX_UNREADABLE,
                                                  _COV.BRANCH_MIN_FRACTION,
                                                  _COV.BRANCH_MIN_SAMPLES)
    rec["attempts_by_phase"] = {
        n: {"mining": sum(1 for e in m["events"] if e.get("phase") == "mining"),
            "transition": sum(1 for e in m["events"] if e.get("phase") == "transition"),
            "post_stop": sum(1 for e in m["events"] if e.get("phase") == "post_stop")}
        for n, m in (rec.get("miner_evidence") or {}).items()}
    rec["verdicts"] = dict(rec.get("verdicts") or {},
                           sample_coverage_adequate=rec["sample_coverage"]["adequate"],
                           branch_coverage_adequate=rec["branch_coverage"]["adequate"])
    return rec


def build_series(td, overrides=None):
    """Write nine schema-complete raw records and return (paths, records)."""
    raw = os.path.join(td, "raw")
    os.makedirs(raw, exist_ok=True)
    paths, recs = [], []
    for rep in (1, 2, 3):
        for cond in ("none", "control", "attack"):
            r = full_record(cond, rep, **((overrides or {}).get((cond, rep)) or {}))
            p = os.path.join(raw, f"{SERIES}__{cond}_{rep}.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(r, f)
            paths.append(p)
            recs.append(r)
    return paths, recs


def test_p0_2_positive_pipeline():
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        validity, vres, sres = SS.finalize_series(paths, recs, td, prov=None)
        bad_v = [k for k, v in vres.items() if not v.get("passed")]
        bad_s = [k for k, v in sres.items() if not v.get("passed")]
        check("P0-2. all nine producer verifiers pass in the real finalizer",
              not bad_v, f"failing={bad_v[:2]} first={(vres.get(bad_v[0]) or {}).get('failures', [])[:2] if bad_v else ''}")
        check("P0-2b. all nine sample/rate verifiers pass",
              not bad_s, f"failing={bad_s[:2]} first={(sres.get(bad_s[0]) or {}).get('failures', [])[:2] if bad_s else ''}")
        check("P0-2c. nine-record finalization reaches series_valid=TRUE",
              validity["series_valid"], validity["invalid_reasons"][:3])
        check("P0-2d. the replay gate reports NOT_TRIGGERED with no partition",
              validity.get("replay_gate") == "NOT_TRIGGERED", validity.get("replay_gate"))
        check("P0-2e. verifier_results.json is retained in the bundle",
              os.path.exists(os.path.join(td, "verifier_results.json")))

    # ---- negatives ----
    for label, kw, expect in [
        ("missing series_id", {("control", 2): {"drop_identity": True}}, "identity"),
        ("mismatched event identity", {("attack", 1): {"bad_event_series": True}}, "series_id"),
        ("missing attacker evidence", {("attack", 3): {"drop_atk": True}}, "atk"),
        ("attacker below the rate floor", {("control", 1): {"starve_atk": 0.5}}, "floor"),
        ("PARTITION with no replay", {("attack", 2): {"partition": True}}, "REPLAY"),
    ]:
        with tempfile.TemporaryDirectory() as td:
            paths, recs = build_series(td, overrides=kw)
            validity, vres, sres = SS.finalize_series(paths, recs, td, prov=None)
            allr = " ".join(validity["invalid_reasons"]) + " " + " ".join(
                f for v in list(vres.values()) + list(sres.values()) for f in v.get("failures", []))
            check(f"P0-2 negative: {label} makes the series invalid",
                  (not validity["series_valid"]) and expect.lower() in allr.lower(),
                  validity["invalid_reasons"][:2] or allr[:160])


def test_p0_4_phase_clock():
    c = SS.PhaseClock(1000.0, 900)
    check("P0-4. mining phase before the fixed end", c.phase_of(1500.0) == "mining")
    check("P0-4b. transition between mining end and proven quiescence",
          c.phase_of(1900.5) == "transition")
    c.close_dispatch("atk", 1900.0)
    check("P0-4c. dispatch closed atomically at the boundary",
          c.may_dispatch("atk", 1899.9) and not c.may_dispatch("atk", 1900.1))
    check("P0-4d. an honest miner keeps dispatching after the boundary",
          c.may_dispatch("h1", 1950.0))
    c.set_post_start(1902.0)
    check("P0-4e. post_stop only after proven quiescence",
          c.phase_of(1901.0) == "transition" and c.phase_of(1903.0) == "post_stop")
    check("P0-4f. an in-flight pre-boundary dispatch is still mining",
          c.phase_of(1899.99) == "mining")
    e = c.export()
    check("P0-4g. the clock is serialized for offline checking",
          e["mining_end_mono"] == 1900.0 and e["post_start_mono"] == 1902.0)


def test_p0_5_branch():
    """Lag vs genuine fork, decided from complete anchored sequences.

    The evidence here is full geometry -- anchor, length, digest, endpoints -- because the
    verifier now requires it and decides lag by EXACT PREFIX rather than hash membership."""
    A1 = "%064x" % 0xA1
    B1 = "%064x" % 0xB1

    def geo(tip, seq):
        return {"tip": tip, "height": ANCHOR_H + len(seq), "anchor_height": ANCHOR_H,
                "anchor_hash": ANCH, "cum": 100, "chain_len": len(seq),
                "chain_digest": hashlib.sha256("".join(seq).encode()).hexdigest(),
                "anchored_hashes": list(seq)}

    # h1 sits on the shared anchor; h2 is one block ahead on the SAME chain -> lag
    lag = {"h1": geo(ANCH, [ANCH]), "h2": geo(A1, [ANCH, A1])}
    # h1 and h2 each extended the anchor differently -> genuine fork
    fork = {"h1": geo(A1, [ANCH, A1]), "h2": geo(B1, [ANCH, B1])}

    def sample(be, stored, i=0):
        sm = one_sample("mining", i * 15.0)
        full = dict(be)
        full["atk"] = dict(be["h1"])
        sm["branch_evidence"] = full
        sm["tips"] = {n: {"height": v["height"], "tip": v["tip"]} for n, v in full.items()}
        differ = len({v["tip"] for v in full.values()}) > 1
        sm["tips_differ"], sm["all_same_tip"] = differ, not differ
        sm["h1_h2_genuinely_forked"] = stored
        sm["h1_h2_common_ancestor"] = None
        return sm

    with tempfile.TemporaryDirectory() as td:
        for label, be, stored, ok in [
                ("node at the shared anchor is LAGGING, not forked", lag, False, True),
                ("a real fork after the anchor is a fork", fork, True, True),
                ("stored says forked but evidence says lagging", lag, True, False)]:
            rec = full_record("control", 1)
            rec["samples"] = [sample(be, stored, i) for i in range(60)] + [
                one_sample("post_stop", rec["phase_boundaries"]["post_start_mono"] + j * 15.0)
                for j in range(28)]
            rec["verdicts"] = dict(rec["verdicts"], PARTITION=False,
                                   longest_h1_h2_fork_run_samples=60 if stored else 0)
            resync_coverage(rec)
            p = os.path.join(td, label.replace(" ", "_")[:40] + ".json")
            json.dump(rec, open(p, "w"))
            r = SAMPV.verify_file(p)
            got = not any("genuinely_forked" in f for f in r["failures"])
            check(f"P0-5. {label}", got == ok, r["failures"][:2])

        # differing tips whose sequences are absent cannot be decided
        rec = full_record("control", 1)
        und = []
        for i in range(60):
            sm = one_sample("mining", i * 15.0)
            for n, tp in (("h1", A1), ("h2", B1), ("atk", A1)):
                e = dict(sm["branch_evidence"][n])
                e["tip"] = tp
                e.pop("anchored_hashes", None)
                sm["branch_evidence"][n] = e
                sm["tips"][n] = {"height": e["height"], "tip": tp}
            sm["tips_differ"], sm["all_same_tip"] = True, False
            sm["h1_h2_genuinely_forked"] = True
            sm["h1_h2_common_ancestor"] = None
            und.append(sm)
        rec["samples"] = und + [
            one_sample("post_stop", rec["phase_boundaries"]["post_start_mono"] + j * 15.0)
            for j in range(28)]
        resync_coverage(rec)
        p = os.path.join(td, "undecidable.json")
        json.dump(rec, open(p, "w"))
        r = SAMPV.verify_file(p)
        check("P0-5d. differing tips without saved chains are undecidable, not a fork",
              (not r["passed"]) and any("sequence is required" in f for f in r["failures"]),
              r["failures"][:2])

        # recovery run start: an unreadable sample must break the run
        rec = full_record("control", 1)
        base_t = rec["phase_boundaries"]["post_start_mono"]
        rec["samples"] = [one_sample("mining", i * 15.0) for i in range(60)] + [
            one_sample("post_stop", base_t + 0.0),
            one_sample("post_stop", base_t + 15.0, readable=False),
            one_sample("post_stop", base_t + 30.0),
            one_sample("post_stop", base_t + 45.0)]
        rec["verdicts"] = dict(rec["verdicts"], RECOVERY=True)
        resync_coverage(rec)
        p = os.path.join(td, "recov.json")
        json.dump(rec, open(p, "w"))
        r = SAMPV.verify_file(p)
        check("P0-5e. same-tip/unreadable/same-tip/same-tip is NOT a recovery run",
              r.get("recovery_recomputed") is False, r["failures"][:2])
    src = io.open(os.path.join(REPO, "node/branch_evidence.py"), encoding="utf-8").read()
    check("P0-5f. node_view anchors at start_height-1", "anchor_h = max(0, start_height - 1)" in src)
    # P0-5g: BEHAVIOURAL, not a source-text grep. Each fixture serves a specific malformed view
    # and canonical() must refuse it rather than return a chain that reads as coherent.
    class HdrDaemon:
        """Serves crafted headers so a malformed paginated view can be exercised offline."""
        def __init__(self, hdrs):
            self.hdrs, self.rpc = hdrs, "http://127.0.0.1:1/"

    def chain(lo, hi):
        out, prev = [], "p" * 64
        for h in range(lo, hi + 1):
            hh = f"{h:064d}"
            out.append({"height": h, "hash": hh, "prev_hash": prev, "timestamp": 1700000000 + h,
                        "difficulty": 1, "cumulative_difficulty": h})
            prev = hh
        return out

    import live_median_boundary as _L
    orig_rpc = BE.rpc
    cases = {
        "a missing header": (lambda c: c[:-1], "expected"),
        "a wrong height": (lambda c: [dict(b, height=b["height"] + 5) if i == 2 else b
                                      for i, b in enumerate(c)], "out of order"),
        "a broken prev_hash": (lambda c: [dict(b, prev_hash="z" * 64) if i == 3 else b
                                          for i, b in enumerate(c)], "prev_hash break"),
        "an empty chunk": (lambda c: [], "empty chunk"),
    }
    for label, (mangle, want) in cases.items():
        served = mangle(chain(30, 40))
        BE.rpc = lambda url, m, params, timeout=0, _s=served: {"result": {"headers": _s}}
        try:
            BE.canonical(HdrDaemon(served), 30, 40, expect_tip=f"{40:064d}", strict=True)
            got = "NO ERROR RAISED"
        except BE.InconsistentView as e:
            got = str(e)
        finally:
            BE.rpc = orig_rpc
        check(f"P0-5g. canonical() REJECTS {label}", want in got, got[:90])
    served = chain(30, 40)
    BE.rpc = lambda url, m, params, timeout=0, _s=served: {"result": {"headers": _s}}
    try:
        BE.canonical(HdrDaemon(served), 30, 40, expect_tip="f" * 64, strict=True)
        got = "NO ERROR RAISED"
    except BE.InconsistentView as e:
        got = str(e)
    finally:
        BE.rpc = orig_rpc
    check("P0-5g. canonical() REJECTS a view whose last hash is not the captured tip",
          "captured tip" in got, got[:90])
    BE.rpc = lambda url, m, params, timeout=0, _s=chain(30, 40): {"result": {"headers": _s}}
    try:
        ok = BE.canonical(HdrDaemon(served), 30, 40, expect_tip=f"{40:064d}", strict=True)
    finally:
        BE.rpc = orig_rpc
    check("P0-5g. canonical() ACCEPTS a complete, ordered, linked view with the right tip",
          len(ok) == 11 and ok[-1]["hash"] == f"{40:064d}", len(ok))


def test_p0_3_lifecycle():
    src = io.open(os.path.join(REPO, "node/symmetric_series.py"), encoding="utf-8").read()
    i_init = src.index('run_label = f"{cond}#{rep}#a{attempt}"')
    i_try = src.index(chr(10) + "    try:" + chr(10), i_init)
    check("P0-3. run_label is initialised BEFORE the try block", i_init < i_try)
    check("P0-3b. miners/sampler/clock initialised before the try",
          src.index("miners, samp, clock = {}, None, None") < i_try)
    check("P0-3c. cleanup joins every created thread before stopping daemons",
          src.index("joined[n] = {") < src.index('ds[n].stop(clean_wait=20.0)'))
    check("P0-3d. zero started daemons cannot mean all_daemons_exited",
          "len(ds) == daemons_expected and stop_records and" in src)
    check("P0-3e. cleanup errors are recorded, not swallowed", 'rec["cleanup_errors"]' in src)


def test_p1_bundle_relative():
    """A copied bundle must verify from its own contents alone."""
    with tempfile.TemporaryDirectory() as td:
        b = os.path.join(td, "bundle")
        os.makedirs(os.path.join(b, "raw"))
        prov = Provenance(b, harness=["node/topology.py"], binary=BIN,
                          driver_argv=["python3", "x"])
        prov.m["SMOKE_RUN"] = "unit"
        prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
        rawp = os.path.join(b, "raw", "c.json")
        json.dump({"condition": "control", "replicate": 1}, open(rawp, "w"))
        prov.add_output(rawp, kind="raw")
        json.dump({"producer_verifier": {"control#1": {"passed": True}},
                   "sample_verifier": {"control#1": {"passed": True}}},
                  open(os.path.join(b, "verifier_results.json"), "w"))
        prov.add_output(os.path.join(b, "verifier_results.json"), kind="verifier_results")
        prov.add_run("control#1#a1", {"h1": ["d"], "h2": ["d"], "atk": ["d"]})
        prov.finish()
        r0 = BV.verify(b)
        check("P1. the original bundle verifies", r0["passed"], r0["failures"][:2])
        import shutil
        b2 = os.path.join(td, "copied", "bundle")
        os.makedirs(os.path.dirname(b2))
        shutil.copytree(b, b2)
        r1 = BV.verify(b2, isolated=True)
        check("P1b. an ISOLATED copy verifies from its own contents alone",
              r1["passed"], r1["failures"][:3])
        check("P1c. isolated mode reports which entries are external identities",
              isinstance(r1.get("external_identity_entries"), int),
              r1.get("external_identity_entries"))
        check("P1d. the manifest carries an explicit log-durability statement",
              isinstance(prov.m.get("durability"), dict)
              and prov.m["durability"].get("offsite_backup") is False
              and "NOT replicated" in prov.m["durability"]["statement"],
              (prov.m.get("durability") or {}).get("offsite_backup"))
        sums = open(os.path.join(b2, "SHA256SUMS"), encoding="utf-8").read().splitlines()
        tgts = [l.split("  ")[-1] for l in sums if l.strip()]
        check("P1e. no SHA256SUMS entry is an absolute path",
              tgts and not any(os.path.isabs(t) for t in tgts),
              [t for t in tgts if os.path.isabs(t)][:3])
        check("P1f. external identities are recorded in the manifest, not as checksum targets",
              isinstance(prov.m.get("external_identities"), dict)
              and any(prov.m["external_identities"].values()),
              sorted(prov.m.get("external_identities") or {}))


def test_p1_copied_inputs():
    """A MEASURED bundle must carry its preregistrations, not point at the live repository."""
    with tempfile.TemporaryDirectory() as td:
        b = os.path.join(td, "bundle")
        os.makedirs(os.path.join(b, "raw"))
        prov = Provenance(b, harness=["node/topology.py"], binary=BIN,
                          driver_argv=["python3", "x"])
        prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
        prov.m["series_valid"] = True
        for i in range(9):
            p = os.path.join(b, "raw", f"r{i}.json")
            json.dump({"i": i}, open(p, "w"))
            prov.add_output(p, kind="raw")
        json.dump({"producer_verifier": {"a": {"passed": True}},
                   "sample_verifier": {"a": {"passed": True}}},
                  open(os.path.join(b, "verifier_results.json"), "w"))
        prov.add_output(os.path.join(b, "verifier_results.json"), kind="verifier_results")
        prov.add_run("control#1#a1", {"h1": ["d"], "h2": ["d"], "atk": ["d"]})
        prov.finish()
        r_no = BV.verify(b)
        check("P1g. a measured bundle WITHOUT copied preregistrations fails",
              (not r_no["passed"])
              and any("preregistration" in f.lower() for f in r_no["failures"]),
              r_no["failures"][:3])

        copied = prov.copy_inputs(["docs/round2/PREREGISTRATION.md",
                                   "docs/round2/OPERATIONAL_PREREGISTRATION.md"], kind="prereg")
        prov.finish()
        r_yes = BV.verify(b)
        check("P1h. copying the preregistrations in satisfies the check",
              r_yes["passed"] and r_yes.get("copied_inputs") == 2,
              [r_yes["failures"][:3], r_yes.get("copied_inputs")])
        check("P1i. each copied input matches the repository file it came from",
              all(v.get("matches_source") for v in copied.values()),
              {k: v.get("matches_source") for k, v in copied.items()})
        # a copied input that is deleted afterwards must be caught, not silently accepted
        os.remove(os.path.join(b, list(copied.values())[0]["bundle_path"]))
        r_del = BV.verify(b)
        check("P1j. deleting a copied input fails the bundle",
              (not r_del["passed"]) and any("copied input" in f or "missing checksum" in f
                                            for f in r_del["failures"]),
              r_del["failures"][:3])


# --------------------------------------------------------------------------- P0-3 injection
class FakeProc:
    def __init__(self, exited=True):
        self._exited = exited
        self.pid = 4242

    def poll(self):
        return 0 if self._exited else None


class FakeDaemon:
    """Stands in for L.Daemon so a failure path can be driven without starting a real node."""
    CREATED = []
    FAIL_AT = None          # 0-based index of the constructor call that raises
    SYNC_FAIL = None        # node name whose wait_synced returns False
    STOP_EXITED = True      # what stop_record() reports
    STOP_RAISES = False

    def __init__(self, name, p2p, rpcp, fixed_diff=0, offline=False, extra=None, wipe=False,
                 data_dir=None):
        idx = len(FakeDaemon.CREATED)
        if FakeDaemon.FAIL_AT is not None and idx == FakeDaemon.FAIL_AT:
            raise RuntimeError(f"injected constructor failure on daemon #{idx}")
        self.name, self.rpc, self.data_dir = name, rpcp, data_dir
        self.argv = ["meepcoind.expgen", "--data-dir", str(data_dir), "--p2p-bind-port", str(p2p)]
        self.proc = FakeProc()
        self.stopped = False
        FakeDaemon.CREATED.append(self)

    def wait_synced(self, secs=120):
        # self.name is the data-directory name (r2_<attempt>_<node>); match the node suffix
        return FakeDaemon.SYNC_FAIL != self.name.split("_")[-1]

    def info(self):
        return {"height": 31, "top_block_hash": "a" * 64, "difficulty": 1,
                "incoming_connections_count": 2, "outgoing_connections_count": 2}

    def stop(self, clean_wait=5.0):
        if FakeDaemon.STOP_RAISES:
            raise RuntimeError("injected stop failure")
        self.stopped = True

    def stop_record(self):
        return {"exited": FakeDaemon.STOP_EXITED, "path": "injected", "name": self.name}


def _inject_env(td, monkey):
    """Point run_condition at throwaway dirs and fake daemons. Returns the Provenance."""
    import live_median_boundary as L
    dirs = {}

    def fake_fresh_copy(name, allow_existing=False):
        d = os.path.join(td, "dd", name)
        os.makedirs(os.path.join(d, "testnet", "lmdb"), exist_ok=True)
        open(os.path.join(d, "testnet", "meepcoind.log"), "w").write("injected log\n")
        dirs[name] = d
        return d

    monkey.append((SS, "fresh_copy", SS.fresh_copy))
    SS.fresh_copy = fake_fresh_copy
    monkey.append((L, "Daemon", L.Daemon))
    L.Daemon = FakeDaemon
    FakeDaemon.CREATED = []
    prov = Provenance(os.path.join(td, "evid"), harness=["node/topology.py"], binary=BIN,
                      driver_argv=["python3", "inject"])
    return prov


def _restore(monkey):
    for obj, name, orig in monkey:
        setattr(obj, name, orig)


def _run_injected(td, **fake):
    """Run one attempt with injected failures; returns (exception, partial_record)."""
    monkey = []
    for k, v in fake.items():
        setattr(FakeDaemon, k, v)
    try:
        prov = _inject_env(td, monkey)
        try:
            rec = SS.run_condition("control", 1, 41000, 1700000000, prov, attempt=1,
                                   evid_dir=os.path.join(td, "evid"),
                                   raw_dir=os.path.join(td, "evid", "raw"),
                                   series_id="INJ")
            return None, rec
        except BaseException as e:
            return e, getattr(e, "partial", None) or {}
    finally:
        _restore(monkey)
        for k in fake:
            setattr(FakeDaemon, k, {"FAIL_AT": None, "SYNC_FAIL": None,
                                    "STOP_EXITED": True, "STOP_RAISES": False}[k])


def test_p0_3_injection():
    """Drive the real cleanup path with real failures, not by reading the source."""
    with tempfile.TemporaryDirectory() as td:
        # (a) the FIRST daemon constructor raises -- cleanup must not mask it with a NameError
        exc, part = _run_injected(os.path.join(td, "a"), FAIL_AT=0)
        check("P0-3f. a first-daemon constructor failure surfaces the REAL error",
              isinstance(exc, RuntimeError) and "injected constructor failure" in str(exc)
              and not isinstance(exc, (NameError, UnboundLocalError)),
              f"{type(exc).__name__}: {exc}")
        check("P0-3g. a constructor failure on daemon #0 leaves no daemon constructed",
              len(FakeDaemon.CREATED) == 0, len(FakeDaemon.CREATED))
        check("P0-3g2. even a non-StageError failure preserves the post-cleanup record",
              isinstance(part, dict) and part.get("daemon_counts", {}).get("started") == 0
              and part.get("all_daemons_exited") is False,
              [part.get("daemon_counts"), part.get("all_daemons_exited")])

        # (b) a LATER daemon fails: the already-created daemons must still be stopped
        exc2, part2 = _run_injected(os.path.join(td, "b"), FAIL_AT=2)
        created = [d for d in FakeDaemon.CREATED]
        check("P0-3h. a later-daemon failure still stops the daemons already started",
              isinstance(exc2, RuntimeError) and len(created) == 2
              and all(d.stopped for d in created),
              [(d.name, d.stopped) for d in created])

        # (c) a sync timeout is a StageError whose partial now carries the CLEANUP facts
        exc3, part3 = _run_injected(os.path.join(td, "c"), SYNC_FAIL="h2")
        check("P0-3i. a sync timeout raises StageError at stage SETUP",
              isinstance(exc3, SS.StageError) and exc3.stage == "SETUP",
              f"{type(exc3).__name__} stage={getattr(exc3, 'stage', None)}")
        check("P0-3j. the preserved partial record contains the POST-cleanup facts",
              all(k in part3 for k in ("daemon_stop", "daemon_counts", "all_daemons_exited",
                                       "thread_cleanup", "log_capture", "cleanup_errors")),
              sorted(set(("daemon_stop", "daemon_counts", "all_daemons_exited", "thread_cleanup",
                          "log_capture", "cleanup_errors")) - set(part3)))
        check("P0-3k. a completed 3-daemon shutdown reports all_daemons_exited",
              part3.get("all_daemons_exited") is True
              and part3.get("daemon_counts", {}).get("started") == 3,
              part3.get("daemon_counts"))

        # (d) a daemon that never exits must NOT read as a clean shutdown
        exc4, part4 = _run_injected(os.path.join(td, "d"), SYNC_FAIL="h2", STOP_EXITED=False)
        check("P0-3l. a daemon that did not exit fails all_daemons_exited",
              part4.get("all_daemons_exited") is False,
              part4.get("daemon_counts"))

        # (e) a raising stop() is recorded as a cleanup error, never swallowed
        exc5, part5 = _run_injected(os.path.join(td, "e"), SYNC_FAIL="h2", STOP_RAISES=True)
        check("P0-3m. a raising daemon stop is recorded as a cleanup error",
              any("injected stop failure" in c for c in part5.get("cleanup_errors") or [])
              and part5.get("all_daemons_exited") is False,
              (part5.get("cleanup_errors") or [])[:2])

        # (f) log capture that cannot find a log fails CLOSED and marks the attempt invalid
        with tempfile.TemporaryDirectory() as td2:
            monkey = []
            try:
                prov = _inject_env(td2, monkey)
                import provenance as PV
                orig = PV.Provenance.copy_logs

                def boom(self, node_dirs, subdir="daemon_logs", require_all=True):
                    raise RuntimeError("injected log capture failure")
                PV.Provenance.copy_logs = boom
                FakeDaemon.SYNC_FAIL = "h2"
                try:
                    SS.run_condition("control", 1, 41200, 1700000000, prov, attempt=1,
                                     evid_dir=os.path.join(td2, "evid"),
                                     raw_dir=os.path.join(td2, "evid", "raw"), series_id="INJ")
                    e6, p6 = None, {}
                except BaseException as e:
                    e6, p6 = e, getattr(e, "partial", None) or {}
                finally:
                    PV.Provenance.copy_logs = orig
                    FakeDaemon.SYNC_FAIL = None
                check("P0-3n. a failed log capture fails closed and invalidates the attempt",
                      p6.get("log_capture", {}).get("all_present") is False
                      and p6.get("status") == "INVALID_LOG_CAPTURE"
                      and any("log capture" in c for c in p6.get("cleanup_errors") or []),
                      [p6.get("status"), (p6.get("cleanup_errors") or [])[:1]])
            finally:
                _restore(monkey)


class SlowDaemon:
    """A stub daemon whose submit is deliberately slow, so a submission STRADDLES the boundary."""
    def __init__(self, latency_s):
        self.latency_s = latency_s
        self.submits = []

    def height(self):
        return 31

    def template(self):
        return {"blocktemplate_blob": "00" * 96, "difficulty": 1, "prev_hash": "a" * 64}

    def timestamps(self, lo, hi):
        return [1700000000] * (hi - lo + 1)

    def submit_detailed(self, blob):
        t0 = time.time()
        time.sleep(self.latency_s)
        self.submits.append(time.monotonic())
        return {"outcome": "REJECTED", "block_id": None, "status": 200, "error": "too old",
                "submitted_wall": t0, "latency_s": self.latency_s,
                "blob_sha256": hashlib.sha256(bytes.fromhex(blob)).hexdigest(),
                "blob_bytes": len(blob) // 2}


def test_p0_4_inflight_live():
    """A REAL miner thread whose submission is still in flight when the boundary passes."""
    import sym_miner as SM
    import threading as _th
    orig_rebuild = SM.rebuild
    SM.rebuild = lambda blob, ts=None, nonce=0: blob
    try:
        stop = _th.Event()
        mine_s = 1.0
        start = time.monotonic()
        clock = SS.PhaseClock(start, mine_s)
        d = SlowDaemon(latency_s=0.35)
        # the third miner in a CONTROL replicate: it walks the full adaptive preparation path
        # and discards the candidate, so this also exercises the longer path under a boundary
        m = SM.SymMiner("atk", d, rate_per_s=6.0, mode=SM.MODE_CONTROL_SHAM, stop=stop,
                        identity={"series_id": "INJ"}, clock=clock)
        m.start()
        # close dispatch EXACTLY at the fixed boundary while a submit is in flight
        time.sleep(max(0.0, clock.mining_end_mono - time.monotonic()))
        clock.close_dispatch("atk", when=clock.mining_end_mono)
        stop.set()
        m.join(timeout=20)
        SM.rebuild = orig_rebuild
        check("P0-4h. the miner thread ended cleanly with no fatal error",
              m.fatal_error is None and not m.is_alive(),
              [m.fatal_error, m.end_reason, m.attempts])
        after = [e for e in m.events if e["dispatch_mono"] > clock.mining_end_mono]
        check("P0-4i. NO attempt was dispatched after the boundary was closed",
              not after, [len(m.events), len(after)])
        straddling = [e for e in m.events
                      if e["dispatch_mono"] < clock.mining_end_mono
                      and e["completed_mono"] > clock.mining_end_mono]
        check("P0-4j. a submission that COMPLETED after the boundary is still phase=mining",
              bool(straddling) and all(e["phase"] == "mining" for e in straddling),
              [len(straddling), sorted({e["phase"] for e in straddling})])
        check("P0-4k. every recorded event carries a dispatch-derived phase",
              m.events and all(e["phase"] == clock.phase_of(e["dispatch_mono"])
                               for e in m.events),
              len(m.events))
    finally:
        SM.rebuild = orig_rebuild


def test_p0_6_preregistered():
    """The floors must be PREREGISTERED, and the document must match the enforced constant."""
    doc = io.open(os.path.join(REPO, "docs/round2/OPERATIONAL_PREREGISTRATION.md"),
                  encoding="utf-8").read()
    pct = int(round(SAMPV.RATE_FLOOR_FRACTION * 100))
    check("P0-6a. the participation floors are preregistered in the operational document",
          "Participation floors" in doc and f"{pct} %" in doc, pct)
    check("P0-6b. the document states the per-miner AND total floors",
          "Per-miner achieved rate" in doc and "Total achieved rate" in doc
          and "Zero-attempt" in doc)
    check("P0-6c. the document states that NONE's absent attacker is not a violation",
          "absent attacker under" in doc and "is not a floor violation" in doc)
    check("P0-6d. the enforced expected-active sets match the document",
          SAMPV.EXPECTED_MINERS == {"none": {"h1", "h2"},
                                    "control": {"h1", "h2", "atk"},
                                    "attack": {"h1", "h2", "atk"}},
          SAMPV.EXPECTED_MINERS)
    check("P0-7a. the partition replay gate is preregistered",
          "PARTITION_PENDING_REPLAY" in doc and "REPLAY_REQUIRED" in doc)


def test_p0_4_scheduled_close_regression():
    """Regression for the defect the 2026-08-15 live smoke found.

    results/SMOKE_20260815_gateC recorded dispatch_closed_mono == boundary while an attacker
    attempt was dispatched 46.6 ms AFTER that boundary. The driver's boundary wait polls on a
    0.25 s tick, so close_dispatch() always runs late and backdates itself; a miner checking
    may_dispatch() inside that window was legitimately allowed through while the evidence
    claimed the window did not exist.
    """
    end = 1000.0
    c = SS.PhaseClock(end - 180.0, 180.0)
    check("P0-4l. WITHOUT a scheduled close the late-dispatch window exists (the found defect)",
          c.may_dispatch("atk", end + 0.0466) is True,
          "may_dispatch allowed a post-boundary dispatch before close_dispatch ran")
    c.schedule_close("atk", c.mining_end_mono)
    check("P0-4m. a SCHEDULED close refuses dispatch exactly at the boundary",
          c.may_dispatch("atk", c.mining_end_mono) is False)
    check("P0-4n. a SCHEDULED close refuses the 46.6 ms late dispatch that actually occurred",
          c.may_dispatch("atk", c.mining_end_mono + 0.0466) is False)
    check("P0-4o. a scheduled close still permits every pre-boundary dispatch",
          c.may_dispatch("atk", c.mining_end_mono - 1e-6) is True)
    check("P0-4p. honest miners are NOT closed at the boundary -- they mine through post_stop",
          c.may_dispatch("h1", c.mining_end_mono + 60.0) is True)
    check("P0-4q. the export separates the SCHEDULED close from the recorded one",
          c.export()["dispatch_scheduled_close_mono"] == {"atk": c.mining_end_mono}
          and c.export()["dispatch_closed_mono"] == {},
          c.export()["dispatch_scheduled_close_mono"])
    # the driver must register the scheduled close BEFORE it starts any miner thread
    src = io.open(os.path.join(REPO, "node/symmetric_series.py"), encoding="utf-8").read()
    check("P0-4r. the driver schedules the attacker close before starting the miners",
          src.index('clock.schedule_close("atk"') < src.index("for m in miners.values():"),
          "schedule_close precedes m.start()")


def test_p0_4_scheduled_close_is_clean():
    """Regression for the SECOND defect the live smoke found (SMOKE_20260815_gateC2).

    Once the attacker's close became scheduled, its normal exit reason changed from
    'stop_requested' to 'dispatch_closed'. healthy() accepted only the former, so the third
    miner was classified unhealthy, threads_quiescent went false and the attempt aborted at
    EVIDENCE_CAPTURE -- a harness fault presented as a failed run.
    """
    import sym_miner as SM

    class _M:
        healthy = SM.SymMiner.healthy
        CLEAN_END_REASONS = SM.SymMiner.CLEAN_END_REASONS

        def __init__(self, reason, fatal=None, attempts=5, events=5):
            self.end_reason, self.fatal_error = reason, fatal
            self.attempts, self.events = attempts, [0] * events

    check("P0-4s. a miner closed by the SCHEDULE is healthy",
          _M("dispatch_closed").healthy() is True)
    check("P0-4t. a miner stopped by its stop event is healthy",
          _M("stop_requested").healthy() is True)
    check("P0-4u. a miner that died of an exception is NOT healthy",
          _M("fatal_exception", fatal={"type": "RuntimeError"}).healthy() is False)
    check("P0-4v. a miner that ended for no recorded reason is NOT healthy",
          _M(None).healthy() is False)
    check("P0-4w. a miner whose events do not match its attempts is NOT healthy",
          _M("dispatch_closed", attempts=5, events=4).healthy() is False)
    check("P0-4x. a miner that never attempted anything is NOT healthy",
          _M("dispatch_closed", attempts=0, events=0).healthy() is False)


def test_p1_external_identity_reporting():
    """external_identity_entries must come from the MANIFEST, not from SHA256SUMS.

    Once external identities were moved out of SHA256SUMS, the old count was structurally 0 --
    it reported "no external identities" for a bundle whose manifest declared twenty.
    """
    with tempfile.TemporaryDirectory() as td:
        b = os.path.join(td, "bundle")
        os.makedirs(os.path.join(b, "raw"))
        prov = Provenance(b, harness=["node/topology.py"], binary=BIN,
                          driver_argv=["python3", "x"])
        prov.m["SMOKE_RUN"] = "unit"
        prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
        rawp = os.path.join(b, "raw", "c.json")
        json.dump({"condition": "control"}, open(rawp, "w"))
        prov.add_output(rawp, kind="raw")
        json.dump({"producer_verifier": {"a": {"passed": True}},
                   "sample_verifier": {"a": {"passed": True}}},
                  open(os.path.join(b, "verifier_results.json"), "w"))
        prov.add_output(os.path.join(b, "verifier_results.json"), kind="verifier_results")
        prov.add_run("control#1#a1", {"h1": ["d"], "h2": ["d"], "atk": ["d"]})
        prov.copy_inputs(["docs/round2/PREREGISTRATION.md"], kind="prereg")
        prov.finish()
        r = BV.verify(b)
        declared = sum(len(v) for v in (prov.m.get("external_identities") or {}).values())
        check("P1k. the bundle verifies and declares its external identities",
              r["passed"] and declared > 0, [r["failures"][:2], declared])
        check("P1l. external_identity_entries is the MANIFEST count, not the SHA256SUMS count",
              r["external_identity_entries"] == declared
              and r["out_of_bundle_checksum_entries"] == 0,
              [r["external_identity_entries"], declared,
               r["out_of_bundle_checksum_entries"]])
        check("P1m. the daemon binary is an external identity, never a checksum target",
              "daemon_binary" in (r.get("external_identities") or {}),
              sorted(r.get("external_identities") or {}))
        # a LEGACY bundle written with absolute paths must be caught, not silently accepted
        sp = os.path.join(b, "SHA256SUMS")
        lines = open(sp, encoding="utf-8").read().splitlines()
        lines.append(f"{'0' * 64}  daemon_binary  {os.path.abspath(BIN)}")
        nl = chr(10)
        with open(sp, "w", encoding="utf-8", newline=nl) as fh:
            fh.write(nl.join(lines) + nl)
        r2 = BV.verify(b)
        check("P1n. an absolute out-of-bundle checksum path fails the bundle",
              (not r2["passed"]) and r2.get("legacy_absolute_paths") is True
              and any("absolute" in f for f in r2["failures"]),
              r2["failures"][:3])


def test_p0_7_gate_is_sealed():
    """The replay gate is a machine gate, so it must reach the sealed artefacts."""
    src = io.open(os.path.join(REPO, "node/symmetric_series.py"), encoding="utf-8").read()
    i_sum = src.index('summary = os.path.join(evid, "summary.json")')
    check("P0-7b. summary.json records the replay gate",
          '"replay_gate": validity.get("replay_gate")' in src[i_sum:i_sum + 3000])
    check("P0-7c. summary.json records which records carried PARTITION",
          '"partition_records": validity.get("partition_records")' in src[i_sum:i_sum + 3000])
    check("P0-7d. the manifest records the replay gate",
          'prov.m["replay_gate"] = validity.get("replay_gate")' in src)
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td, overrides={("attack", 2): {"partition": True}})
        validity, _, _ = SS.finalize_series(paths, recs, td, prov=None)
        check("P0-7e. a PARTITION record sets REPLAY_REQUIRED in the validity output",
              validity.get("replay_gate") == "REPLAY_REQUIRED"
              and validity.get("partition_records") == ["attack#2"],
              [validity.get("replay_gate"), validity.get("partition_records")])


def main():
    print("NON-EVIDENCE round-4 harness tests\n")
    test_p0_2_positive_pipeline()
    test_p0_3_lifecycle()
    test_p0_4_phase_clock()
    test_p0_5_branch()
    test_p1_bundle_relative()
    test_p1_copied_inputs()
    test_p0_3_injection()
    test_p0_4_inflight_live()
    test_p0_6_preregistered()
    test_p0_4_scheduled_close_regression()
    test_p0_4_scheduled_close_is_clean()
    test_p1_external_identity_reporting()
    test_p0_7_gate_is_sealed()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                            text=True).stdout.strip()
    harness = {}
    for f in ("node/symmetric_series.py", "node/sample_verify.py", "node/bundle_verify.py",
              "node/evidence_verify.py", "node/series_validate.py", "node/sym_miner.py",
              "node/branch_evidence.py", "node/provenance.py", "node/tests_round4.py"):
        q = os.path.join(REPO, f)
        if os.path.exists(q):
            harness[f] = hashlib.sha256(open(q, "rb").read()).hexdigest()
    out = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "label": "NON-EVIDENCE harness tests -- validate the harness, never the protocol",
           "repo_commit_at_run": commit, "harness_sha256": harness, "daemon_binary": BIN,
           "daemon_binary_sha256": (hashlib.sha256(open(BIN, "rb").read()).hexdigest()
                                    if os.path.exists(BIN) else None),
           "command": " ".join(sys.argv), "live": False,
           "passed": passed, "total": len(RESULTS), "results": RESULTS}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(out, **report_metadata("round4", sys.argv, False,
                                             CORE_SOURCES
                                             + ("node/tests_round4.py",))),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
