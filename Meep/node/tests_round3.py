#!/usr/bin/env python3
"""Round-3 harness tests. NON-EVIDENCE: they validate the harness, never the protocol.

These cover the defects found after `af84b9f`:

  12  rate/phase recomputation from events, and the inflated-attempt fixture that previously
      passed every producer check while claiming 40,000 attempts on 160 real events
  12i-k  driver orchestration: no None-deref on a post-start failure, verifier wired before
      sealing, any non-OK condition aborts the series
  13  bundle verifier and detached final seal, with mutation cases

Usage: python3 node/tests_round3.py [--out=docs/round2/tests_round3.json]
"""
import hashlib, io, json, os, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bundle_verify as BV
import sample_verify as SAMPV
from provenance import Provenance
from tests_round2 import synth_record, check, RESULTS, report_metadata, CORE_SOURCES

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round3.json")
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def honest_record(mine_s=900):
    """A record whose stored aggregates agree with its own event stream."""
    rec = synth_record()
    rec["series_id"] = "SERIES_T"
    rec["triplet_id"] = f"SERIES_T#rep{rec.get('replicate', 1)}"
    rec["matched_replicate_id"] = rec["triplet_id"]
    rec["mine_seconds"] = mine_s
    # P0-1: identity must be present on EVERY event, not only on the record, so the record<->event
    # cross-check has something to compare against.
    for _n, _v in rec["miner_evidence"].items():
        for _e in _v["events"]:
            _e.setdefault("series_id", rec["series_id"])
            _e.setdefault("triplet_id", rec["triplet_id"])
            _e.setdefault("matched_replicate_id", rec["matched_replicate_id"])
            _e.setdefault("attempt_id", rec.get("attempt_id"))
            _e.setdefault("condition", rec.get("condition"))
            _e.setdefault("replicate", rec.get("replicate"))
            _e.setdefault("topology", rec.get("topology"))
    real = {n: sum(1 for e in v["events"] if e["phase"] == "mining")
            for n, v in rec["miner_evidence"].items()}
    rec["mining_phase_attempts"] = dict(real)
    rec["mining_attempts_from_events"] = dict(real)
    rec["mining_phase_total_attempts"] = sum(real.values())
    rec["mining_attempts_counter_agrees"] = True
    rec["mining_phase_rate_by_miner"] = {n: round(v / float(mine_s), 4) for n, v in real.items()}
    rec["mining_phase_third_share"] = real["atk"] / sum(real.values())
    # P0-6: the floors are evaluated against the CONFIGURED rates, so an honest synthetic record
    # has to declare configured rates its own event stream actually meets.
    rec["configured_rates"] = {"honest": round(min(real["h1"], real["h2"]) / float(mine_s), 6),
                               "third": round(real["atk"] / float(mine_s), 6),
                               "total": round(sum(real.values()) / float(mine_s), 6)}
    # a COMPLETE schedule under the current schema, built by the shared fixture helper
    from tests_round4 import build_samples, resync_coverage
    rec["post_seconds"] = 420.0
    rec["sample_seconds"] = 15.0
    # every event needs a dispatch time the sealed schedule can classify
    for _n, _m in rec["miner_evidence"].items():
        _rows = _m.get("events") or []
        for _i, _e in enumerate(_rows):
            _e["seq"] = _i + 1
            _e["phase"] = "mining"
            _e["dispatch_mono"] = (_i + 1) * (mine_s / (len(_rows) + 1.0)) if _rows else 0.0
            _e["completed_mono"] = _e["dispatch_mono"] + 0.01
    rec["start_identical"] = True
    rec["start_state"] = {n: {"genesis_hash": "9" * 64, "height": 31, "tip_hash": "d" * 64,
                              "tip_difficulty": 1, "cumulative_difficulty": 31}
                          for n in ("h1", "h2", "atk")}
    rec["samples"] = build_samples(mine_s, 420.0, 15.0, post0=mine_s + 1.0)
    rec["phase_boundaries"] = {"mining_start_mono": 0.0, "boundary_mono": mine_s,
                               "nominal_mining_end_mono": mine_s,
                               "post_start_mono": mine_s + 1.0,
                               "post_end_mono": mine_s + 1.0 + 420.0,
                               "actual_mining_interval_s": round(mine_s, 4)}
    rec["phase_clock"] = {"mining_start_mono": 0.0, "mining_end_mono": mine_s,
                          "post_start_mono": mine_s + 1.0,
                          "post_end_mono": mine_s + 1.0 + 420.0,
                          "dispatch_scheduled_close_mono": {
                              "atk": mine_s, "h1": mine_s + 421.0, "h2": mine_s + 421.0},
                          "dispatch_closed_mono": {"atk": mine_s}}
    rec["mine_seconds_actual"] = round(mine_s, 4)
    post = [x for x in rec["samples"] if x.get("phase") == "post_stop"]
    rec["verdicts"] = dict(rec.get("verdicts") or {}, RECOVERY=len(post) >= 3,
                           recovery_first_qualifying_index=0 if len(post) >= 3 else None,
                           recovery_first_sample_t=(
                               round(post[0]["t_mono"] - (mine_s + 1.0), 1)
                               if len(post) >= 3 else None),
                           longest_h1_h2_fork_run_samples=0)
    rec["verdicts"] = dict(rec["verdicts"], topology_conformant_throughout=True,
                           longest_h1_h2_fork_run_samples=0, PARTITION=False)
    resync_coverage(rec)
    return rec, real


def w(td, name, obj):
    p = os.path.join(td, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return p


def test_12_rates():
    with tempfile.TemporaryDirectory() as td:
        ok, real = honest_record()
        check("12. an honest record passes the rate verifier",
              SAMPV.verify_file(w(td, "honest.json", ok))["passed"],
              SAMPV.verify_file(w(td, "honest.json", ok))["failures"][:2])

        bad = json.loads(json.dumps(ok))
        bad["mining_phase_attempts"] = {"h1": 40000, "h2": 40000, "atk": 6000}
        bad["mining_attempts_from_events"] = bad["mining_phase_attempts"]
        bad["mining_phase_total_attempts"] = 86000
        r = SAMPV.verify_file(w(td, "inflated.json", bad))
        check("12a. a record claiming 40,000 attempts on a small event stream FAILS",
              (not r["passed"]) and any("recomputed" in f for f in r["failures"]),
              r["failures"][:2])

        b2 = json.loads(json.dumps(ok))
        b2["mining_phase_attempts"]["h1"] += 7
        check("12b. an altered per-miner count is caught",
              not SAMPV.verify_file(w(td, "altered.json", b2))["passed"])

        b3 = json.loads(json.dumps(ok))
        b3["mine_seconds"] = 450
        r3 = SAMPV.verify_file(w(td, "dur.json", b3))
        # a falsified duration now contradicts the SEALED schedule as well as the rates, and the
        # schedule check fires first because every timing claim depends on it
        check("12c. a wrong mining duration contradicts the sealed schedule",
              (not r3["passed"])
              and any("disagrees with mine_seconds" in f or "rate" in f
                      for f in r3["failures"]),
              r3["failures"][:2])

        b4 = json.loads(json.dumps(ok))
        b4["mining_phase_third_share"] = 0.5
        check("12d. a wrong third share is caught",
              not SAMPV.verify_file(w(td, "share.json", b4))["passed"])

        b5 = json.loads(json.dumps(ok))
        ev = b5["miner_evidence"]["h1"]["events"]
        ev[1]["seq"] = ev[0]["seq"]
        check("12e. duplicate event sequence numbers are caught",
              not SAMPV.verify_file(w(td, "dupseq.json", b5))["passed"])

        b6 = json.loads(json.dumps(ok))
        b6["miner_evidence"]["h1"]["events"][0]["series_id"] = "SERIES_OTHER"
        r6 = SAMPV.verify_file(w(td, "xseries.json", b6))
        check("12f. cross-series event identity is caught",
              (not r6["passed"]) and any("series_id" in f for f in r6["failures"]),
              r6["failures"][:2])

        b7 = json.loads(json.dumps(ok))
        b7["phase_boundaries"] = {"boundary_mono": 100.0}
        for e in b7["miner_evidence"]["atk"]["events"]:
            e["dispatch_mono"] = 150.0
        r7 = SAMPV.verify_file(w(td, "late.json", b7))
        check("12g. an attacker dispatch at/after the mining boundary is caught",
              (not r7["passed"]) and any("boundary" in f for f in r7["failures"]),
              r7["failures"][:2])

        b8 = json.loads(json.dumps(ok))
        b8["miner_evidence"]["atk"]["events"] = []
        b8["mining_phase_attempts"]["atk"] = 0
        b8["mining_attempts_from_events"]["atk"] = 0
        b8["mining_phase_total_attempts"] = real["h1"] + real["h2"]
        b8["mining_phase_rate_by_miner"]["atk"] = 0.0
        b8["mining_phase_third_share"] = 0.0
        r8 = SAMPV.verify_file(w(td, "dead.json", b8))
        check("12h. a dead/absent miner is caught, never treated as rate-matched",
              (not r8["passed"]) and any("zero mining-phase" in f for f in r8["failures"]),
              r8["failures"][:2])

        b9 = json.loads(json.dumps(ok))
        from tests_round4 import one_sample, resync_coverage as _rs
        _b = b9["phase_boundaries"]["post_start_mono"]
        b9["samples"] = [one_sample("post_stop", _b + 0.0),
                         one_sample("post_stop", _b + 15.0, readable=False),
                         one_sample("post_stop", _b + 30.0),
                         one_sample("post_stop", _b + 45.0)]
        _rs(b9)
        b9["verdicts"] = dict(b9["verdicts"], RECOVERY=True)
        r9 = SAMPV.verify_file(w(td, "recov.json", b9))
        check("12i. an error sample breaks a recovery run instead of bridging it",
              (not r9["passed"]) and any("RECOVERY" in f for f in r9["failures"]),
              f"recomputed={r9.get('recovery_recomputed')} {r9['failures'][:1]}")


def test_12_orchestration():
    src = io.open(os.path.join(REPO, "node/symmetric_series.py"), encoding="utf-8").read()
    check("12j. the post-start outcome is assigned to r before failed_attempts is attached",
          src.index('r = {"series_id": series_id, "condition": cond') <
          src.index('r["failed_attempts"] = attempts'))
    check("12k. the driver wires the offline verifiers into validation before sealing",
          "finalize_series(raw_paths, results, evid, prov)" in src and
          "SV.validate(results, verifier_results=merged)" in src)
    check("12l. any non-OK condition status aborts the series",
          'if r.get("status") != "OK" and not aborted:' in src)
    check("12m. the driver no longer calls SV.validate without verifier results",
          "SV.validate(results)\n" not in src)
    import symmetric_series as SS
    check("12n. finalize_series is importable and testable in isolation",
          callable(getattr(SS, "finalize_series", None)))


def test_13_bundle_seal():
    with tempfile.TemporaryDirectory() as td:
        b = os.path.join(td, "bundle")
        os.makedirs(os.path.join(b, "raw"))
        prov = Provenance(b, harness=["node/topology.py"], binary=BIN,
                          driver_argv=["python3", "node/symmetric_series.py", "--smoke=1"])
        prov.m["SMOKE_RUN"] = "unit test"
        prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
        rawp = w(os.path.join(b, "raw"), "c.json", {"condition": "control", "replicate": 1})
        prov.add_output(rawp, kind="raw")
        vr = w(b, "verifier_results.json",
               {"producer_verifier": {"control#1": {"passed": True}},
                "sample_verifier": {"control#1": {"passed": True}}})
        prov.add_output(vr, kind="verifier_results")
        prov.add_run("control#1#a1", {"h1": ["d"], "h2": ["d"], "atk": ["d"]})
        prov.finish()
        r = BV.verify(b)
        check("13. a properly sealed bundle verifies", r["passed"], r["failures"][:3])
        seal = json.load(open(os.path.join(b, "FINAL_SEAL.json")))
        check("13a. the detached seal binds manifest and SHA256SUMS",
              bool(seal.get("manifest_sha256")) and bool(seal.get("sha256sums_sha256")))
        m = json.load(open(os.path.join(b, "manifest.json")))
        m["tampered"] = True
        json.dump(m, open(os.path.join(b, "manifest.json"), "w"), indent=1)
        r2 = BV.verify(b)
        check("13b. a changed manifest fails the seal",
              (not r2["passed"]) and any("seal manifest" in f for f in r2["failures"]),
              r2["failures"][:2])
        json.dump(json.loads(json.dumps({k: v for k, v in m.items() if k != "tampered"})),
                  open(os.path.join(b, "manifest.json"), "w"), indent=1)
        with open(rawp, "w") as f:
            f.write("{}")
        r3 = BV.verify(b)
        check("13c. a changed raw record fails the checksum inventory",
              (not r3["passed"]) and any("modified" in f for f in r3["failures"]),
              r3["failures"][:2])
        os.remove(os.path.join(b, "FINAL_SEAL.json"))
        check("13d. a missing final seal fails", not BV.verify(b)["passed"])
        open(os.path.join(b, "stray.bin"), "w").write("x")
        r5 = BV.verify(b)
        check("13e. an unlisted extra file fails",
              any("unlisted" in f for f in r5["failures"]), r5["failures"][:2])


def main():
    print("NON-EVIDENCE round-3 harness tests\n")
    test_12_rates()
    test_12_orchestration()
    test_13_bundle_seal()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    import subprocess, time
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                            text=True).stdout.strip()
    harness = {}
    for f in ("node/symmetric_series.py", "node/sample_verify.py", "node/bundle_verify.py",
              "node/evidence_verify.py", "node/series_validate.py", "node/sym_miner.py",
              "node/provenance.py", "node/tests_round3.py"):
        q = os.path.join(REPO, f)
        if os.path.exists(q):
            harness[f] = hashlib.sha256(open(q, "rb").read()).hexdigest()
    out = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "label": "NON-EVIDENCE harness tests -- validate the harness, never the protocol",
           "repo_commit_at_run": commit, "harness_sha256": harness,
           "daemon_binary": BIN,
           "daemon_binary_sha256": (hashlib.sha256(open(BIN, "rb").read()).hexdigest()
                                    if os.path.exists(BIN) else None),
           "command": " ".join(sys.argv), "live": False,
           "passed": passed, "total": len(RESULTS), "results": RESULTS}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(out, **report_metadata("round3", sys.argv, False,
                                             CORE_SOURCES
                                             + ("node/tests_round3.py",))),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
