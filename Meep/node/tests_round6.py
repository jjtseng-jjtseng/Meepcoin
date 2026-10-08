#!/usr/bin/env python3
"""Round-6 harness tests: the evidence checker must not be able to accept a false result.

NON-EVIDENCE. These validate the harness, never the protocol.

Three ways a bad long record could previously have been called valid, all reproduced on
disposable copies of the real Gate E record before the fix:

  1  topology/sample coverage was TRUSTED, never recomputed. A record with 10 of 12 usable
     samples per phase and a forged {"adequate": true} passed with zero failures.
  2  a readable sample with differing H1/H2 tips and EMPTY branch evidence recorded fork=false
     and vanished; and RECOVERY trusted a stored all_same_tip that contradicted the saved tips.
  3  samples taken between nominal mining end and proven attacker quiescence were labelled
     `mining`, inflating mining coverage with observations of a network whose attacker had
     already stopped.

Plus the provenance closure gap: the bundle advertised an offline checker it did not carry.

Usage: python3 node/tests_round6.py [--out=docs/round2/tests_round6.json]
"""
import copy, hashlib, json, os, shutil, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bundle_verify as BV
import coverage as COV
import sample_verify as SAMPV
import series_validate as SV
import symmetric_series as SS
from provenance import Provenance
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import build_samples, build_series, full_record, one_sample, resync_coverage

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round6.json")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")


def verify_rec(rec):
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        return SAMPV.verify_file(p)


def caught(rec, substr):
    r = verify_rec(rec)
    return (not r["passed"]) and any(substr in f for f in r["failures"]), r


# ------------------------------------------------------------------ 1. coverage is recomputed
def test_1_coverage_recomputed():
    ok = full_record("control", 1)
    r = verify_rec(ok)
    check("R1. an honest complete record still passes", r["passed"], r["failures"][:2])

    bad = full_record("control", 1)
    bad["samples"] = ([s for s in bad["samples"] if s["phase"] == "mining"][:10]
                      + [s for s in bad["samples"] if s["phase"] == "post_stop"][:10])
    resync_coverage(bad)
    honest = bad["sample_coverage"]["adequate"]
    bad["sample_coverage"]["adequate"] = True
    bad["sample_coverage"]["failures"] = []
    bad["verdicts"]["sample_coverage_adequate"] = True
    hit, r = caught(bad, "sample_coverage.adequate")
    check("R1b. a starved record with forged sample_coverage.adequate FAILS",
          hit and honest is False, r["failures"][:2])
    out = SV.validate([bad], verifier_results={"control#1": {"passed": False,
                                                             "failures": ["sample verifier"]}})
    check("R1c. and it cannot enter a valid series", not out["series_valid"],
          out["invalid_reasons"][:2])


def test_2_positive_nine_record():
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        n_mine = sum(1 for s in recs[0]["samples"] if s["phase"] == "mining")
        n_post = sum(1 for s in recs[0]["samples"] if s["phase"] == "post_stop")
        check("R2. the positive fixture carries a COMPLETE 60/28 schedule, not a stub",
              (n_mine, n_post) == (60, 28), [n_mine, n_post])
        check("R2b. its coverage is honestly adequate, not hard-coded",
              recs[0]["sample_coverage"]["adequate"] is True
              and recs[0]["sample_coverage"]["phases"]["mining"]["usable"] == 60
              and recs[0]["sample_coverage"]["expected"]["mining"] == 60,
              recs[0]["sample_coverage"]["phases"]["mining"])
        validity, vres, sres = SS.finalize_series(paths, recs, td, prov=None)
        check("R2c. the complete nine-record pipeline reaches series_valid=TRUE",
              validity["series_valid"] is True, validity["invalid_reasons"][:3])
        check("R2d. every producer and sample verifier passed",
              all(v.get("passed") for v in vres.values())
              and all(v.get("passed") for v in sres.values()),
              [k for k, v in sres.items() if not v.get("passed")])
    # and it stops being valid the moment coverage is genuinely inadequate
    with tempfile.TemporaryDirectory() as td:
        paths, recs = build_series(td)
        r0 = recs[0]
        r0["samples"] = [s for s in r0["samples"] if s["phase"] != "post_stop"][:20]
        resync_coverage(r0)
        r0["status"] = SS.record_status(True, r0["sample_coverage"]["adequate"],
                                        r0["branch_coverage"]["adequate"])
        with open(paths[0], "w", encoding="utf-8") as f:
            json.dump(r0, f)
        validity, _, _ = SS.finalize_series(paths, recs, td, prov=None)
        check("R2e. genuinely inadequate coverage makes the same series invalid",
              validity["series_valid"] is False
              and any("coverage" in x for x in validity["invalid_reasons"]),
              [x for x in validity["invalid_reasons"] if "coverage" in x][:2])


def test_3_thresholds_are_policy():
    for path, key, bad in (("sample_coverage", "min_usable_fraction", 0.5),
                           ("sample_coverage", "min_usable_samples", 1),
                           ("sample_coverage", "max_non_conformant_samples", 5),
                           ("branch_coverage", "max_unreadable_samples", 99),
                           ("branch_coverage", "min_readable_fraction", 0.0),
                           ("branch_coverage", "min_readable_samples", 0)):
        rec = full_record("control", 1)
        rec[path]["thresholds"][key] = bad
        hit, r = caught(rec, f"{path}.thresholds.{key}")
        check(f"R3. a record cannot choose its own {path}.{key}", hit, r["failures"][:1])


def test_4_explicit_flags_required():
    for field in ("topology_observed", "branch_readable"):
        for how in ("remove", "null"):
            rec = full_record("control", 1)
            for sm in rec["samples"]:
                if how == "remove":
                    sm.pop(field, None)
                else:
                    sm[field] = None
            hit, r = caught(rec, "current schema")
            check(f"R4. {how} {field} -> the current-schema record is refused", hit,
                  r["failures"][:1])
    rec = full_record("control", 1)
    r = verify_rec(rec)
    check("R4c. an honest record reports the current schema",
          r.get("schema") == "current", r.get("schema"))


def test_5_readable_needs_evidence():
    for node in COV.REQUIRED_NODES:
        rec = full_record("control", 1)
        for sm in rec["samples"]:
            if sm.get("branch_readable"):
                sm["branch_evidence"].pop(node, None)
        hit, r = caught(rec, "node set")
        check(f"R5. a readable sample missing {node} evidence FAILS", hit, r["failures"][:1])
    rec = full_record("control", 1)
    for sm in rec["samples"]:
        if sm.get("branch_readable"):
            sm["branch_evidence"] = {}
    hit, r = caught(rec, "node set")
    check("R5d. wholly empty branch evidence on a readable sample FAILS", hit,
          r["failures"][:1])


def test_6_sequence_integrity():
    def forked_record():
        rec = full_record("control", 1)
        for sm in rec["samples"]:
            if sm["phase"] == "mining":
                sm["branch_evidence"]["h2"]["tip"] = "b" * 64
                sm["branch_evidence"]["h2"]["anchored_hashes"] = ["c" * 64, "b" * 64]
                sm["branch_evidence"]["h2"]["chain_digest"] = hashlib.sha256(
                    ("c" * 64 + "b" * 64).encode()).hexdigest()
                sm["tips"]["h2"]["tip"] = "b" * 64
                sm["tips_differ"], sm["all_same_tip"] = True, False
                sm["h1_h2_genuinely_forked"] = True
        rec["verdicts"]["longest_h1_h2_fork_run_samples"] = 60
        rec["verdicts"]["PARTITION"] = True
        return resync_coverage(rec)

    base = forked_record()
    r = verify_rec(base)
    check("R6. a genuine fork with intact sequences is derivable",
          r.get("longest_fork_run_recomputed") == 60, r["failures"][:2])

    cases = {
        "missing sequences": lambda sm: [sm["branch_evidence"][n].pop("anchored_hashes", None)
                                         for n in ("h1", "h2")],
        "tampered chain_len": lambda sm: sm["branch_evidence"]["h1"].update(chain_len=99),
        "tampered chain_digest": lambda sm: sm["branch_evidence"]["h1"].update(
            chain_digest="0" * 64),
        "tampered anchor_hash": lambda sm: sm["branch_evidence"]["h1"].update(
            anchor_hash="9" * 64),
        "sequence not ending at the tip": lambda sm: sm["branch_evidence"]["h1"].update(
            anchored_hashes=["c" * 64, "9" * 64]),
        "tips/branch_evidence disagreement": lambda sm: sm["tips"]["h1"].update(tip="9" * 64),
    }
    wants = {"missing sequences": "sequence is required",
             "tampered chain_len": "chain_len",
             "tampered chain_digest": "chain_digest",
             "tampered anchor_hash": "common anchor",
             "sequence not ending at the tip": "does not end at its own tip",
             "tips/branch_evidence disagreement": "tip disagrees"}
    for label, mutate in cases.items():
        rec = forked_record()
        for sm in rec["samples"]:
            if sm["phase"] == "mining":
                mutate(sm)
        hit, r = caught(rec, wants[label])
        check(f"R6. {label} FAILS", hit, r["failures"][:1])


def test_7_all_same_tip_derived():
    rec = full_record("control", 1)
    for sm in rec["samples"]:
        if sm["phase"] == "post_stop":
            sm["branch_evidence"]["atk"]["tip"] = "b" * 64
            sm["branch_evidence"]["atk"]["anchored_hashes"] = ["c" * 64, "b" * 64]
            sm["branch_evidence"]["atk"]["chain_digest"] = hashlib.sha256(
                ("c" * 64 + "b" * 64).encode()).hexdigest()
            sm["tips"]["atk"]["tip"] = "b" * 64
            sm["all_same_tip"] = True                       # the lie
            sm["tips_differ"] = True
    resync_coverage(rec)
    hit, r = caught(rec, "all_same_tip")
    check("R7. a diverged attacker cannot be hidden behind a stored all_same_tip", hit,
          r["failures"][:1])
    check("R7b. and RECOVERY is not granted on that evidence",
          r.get("recovery_recomputed") is False, r.get("recovery_recomputed"))


def test_8_recovery_fields():
    for field, bad in (("RECOVERY", False), ("recovery_first_qualifying_index", 7),
                       ("recovery_first_sample_t", 999.9)):
        rec = full_record("control", 1)
        rec["verdicts"][field] = bad
        hit, r = caught(rec, field)
        check(f"R8. a tampered {field} FAILS", hit, r["failures"][:1])


def test_9_10_transition():
    rec = full_record("control", 1)
    pb = rec["phase_boundaries"]
    mid = (pb["boundary_mono"] + pb["post_start_mono"]) / 2.0
    # inserted in TIME ORDER, so the only defect is the label itself
    sm = one_sample("mining", mid)                          # labelled mining, timed in transition
    n_mine = sum(1 for x in rec["samples"] if x["phase"] == "mining")
    rec["samples"].insert(n_mine, sm)
    resync_coverage(rec)
    hit, r = caught(rec, "do not all agree")
    check("R9. a transition observation labelled mining FAILS verification", hit,
          r["failures"][:1])

    rec2 = full_record("control", 1)
    before = copy.deepcopy(rec2["sample_coverage"])
    n_mine2 = sum(1 for x in rec2["samples"] if x["phase"] == "mining")
    rec2["samples"].insert(n_mine2, one_sample("transition", mid))
    resync_coverage(rec2)
    check("R10. a transition sample counts toward NEITHER phase's coverage",
          rec2["sample_coverage"]["phases"]["mining"]["observed"]
          == before["phases"]["mining"]["observed"]
          and rec2["sample_coverage"]["phases"]["post_stop"]["observed"]
          == before["phases"]["post_stop"]["observed"],
          [rec2["sample_coverage"]["phases"]["mining"]["observed"],
           before["phases"]["mining"]["observed"]])
    r2 = verify_rec(rec2)
    check("R10b. and a correctly labelled transition sample is accepted", r2["passed"],
          r2["failures"][:2])
    streak = ([one_sample("mining", i * 15.0, forked=True) for i in range(5)]
              + [one_sample("transition", 5 * 15.0, forked=True)]
              + [one_sample("mining", i * 15.0, forked=True) for i in range(6, 11)])
    check("R10c. a transition sample BREAKS a fork streak instead of bridging it",
          SS.longest_true_run_readable(streak, "h1_h2_genuinely_forked") == 5,
          SS.longest_true_run_readable(streak, "h1_h2_genuinely_forked"))


# ------------------------------------------------------------------ bundle closure
def make_bundle(td, series_valid=True, nine=True):
    b = os.path.join(td, "bundle")
    os.makedirs(os.path.join(b, "raw"), exist_ok=True)
    prov = Provenance(b, harness=SS.HARNESS, binary=BIN, driver_argv=["python3", "x"])
    prov.m["resolved_config"] = {f"k{i}": i for i in range(12)}
    prov.copy_inputs(["docs/round2/PREREGISTRATION.md",
                      "docs/round2/OPERATIONAL_PREREGISTRATION.md"], kind="prereg")
    prov.copy_inputs(SS.HARNESS, dest_subdir="inputs/harness", kind="harness_copy")
    paths, recs = build_series(os.path.join(b))
    validity, vres, sres = SS.finalize_series(paths, recs, b, prov=prov)
    for p in paths:
        prov.add_output(p, kind="raw")
    prov.m["series_valid"] = validity["series_valid"]
    prov.m["replay_gate"] = validity.get("replay_gate")
    prov.m["aborted"] = None
    prov.m["status"] = "COMPLETED"
    prov.finish()
    return b, prov, validity


def test_11_harness_closure():
    check("R11. sample_verify.py is in HARNESS", "node/sample_verify.py" in SS.HARNESS)
    check("R11b. bundle_verify.py is in HARNESS", "node/bundle_verify.py" in SS.HARNESS)
    with tempfile.TemporaryDirectory() as td:
        b, prov, _ = make_bundle(td)
        for name in ("sample_verify.py", "bundle_verify.py"):
            dst = os.path.join(b, "inputs", "harness", name)
            src = os.path.join(REPO, "node", name)
            same = (os.path.exists(dst)
                    and hashlib.sha256(open(dst, "rb").read()).hexdigest()
                    == hashlib.sha256(open(src, "rb").read()).hexdigest())
            check(f"R11c. {name} is copied into the bundle byte-identically", same, dst)
            listed = any(name in ln for ln in
                         open(os.path.join(b, "SHA256SUMS"), encoding="utf-8"))
            check(f"R11d. {name} is covered by SHA256SUMS", listed)
        r = BV.verify(b)
        check("R11e. the bundle with both checkers verifies", r["passed"], r["failures"][:3])


def raw_files(bundle):
    d = os.path.join(bundle, "raw")
    return [os.path.join(d, f) for f in sorted(os.listdir(d))]


def run_bundled(bundle, script, *args):
    """Run a checker CARRIED IN the bundle, from a cwd with no access to the live repo."""
    exe = os.path.join(bundle, "inputs", "harness", script)
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run([sys.executable, exe] + list(args), capture_output=True, text=True,
                       cwd=os.path.dirname(bundle), env=env)
    return p.returncode, (p.stdout + p.stderr)


def test_12_relocated_bundled_checker():
    with tempfile.TemporaryDirectory() as td:
        b, _, _ = make_bundle(td)
        moved = os.path.join(td, "elsewhere", "relocated")
        os.makedirs(os.path.dirname(moved), exist_ok=True)
        shutil.copytree(b, moved)
        rc, out = run_bundled(moved, "bundle_verify.py", moved, "--isolated")
        check("R12. the BUNDLED checker verifies the relocated bundle with no live repo",
              rc == 0 and "[PASS]" in out, out.strip().splitlines()[:3])
        # corrupting the bundled checker must be caught by the seal
        with open(os.path.join(moved, "inputs", "harness", "bundle_verify.py"), "a",
                  encoding="utf-8") as f:
            f.write("\n# tampered\n")
        rc2, out2 = run_bundled(moved, "bundle_verify.py", moved, "--isolated")
        check("R12b. a corrupted bundled checker fails its own checksum",
              rc2 != 0 and "modified checksum" in out2,
              out2.strip().splitlines()[:3])


def test_13_bundled_sample_verifier():
    with tempfile.TemporaryDirectory() as td:
        b, _, _ = make_bundle(td)
        moved = os.path.join(td, "moved2")
        shutil.copytree(b, moved)
        raw = sorted(os.listdir(os.path.join(moved, "raw")))[0]
        rp = os.path.join(moved, "raw", raw)
        rec = json.load(open(rp, encoding="utf-8"))
        rec["mining_phase_total_attempts"] = 999999
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        rc, out = run_bundled(moved, "sample_verify.py", rp)
        check("R13. the BUNDLED sample verifier rejects a corrupted attempt claim",
              rc != 0 and ("counter" in out or "!=" in out), out.strip().splitlines()[:3])


def test_14_bundled_series_validator():
    with tempfile.TemporaryDirectory() as td:
        b, _, validity = make_bundle(td)
        check("R14. the bundle's own nine-record series is valid before tampering",
              validity["series_valid"] is True, validity["invalid_reasons"][:2])
        moved = os.path.join(td, "moved3")
        shutil.copytree(b, moved)
        rc, out = run_bundled(moved, "series_validate.py", *raw_files(moved))
        check("R14b. the bundled validator runs BOTH verifiers",
              "producer verifier" in out and "sample verifier" in out,
              out.strip().splitlines()[:2])
        check("R14c. and passes the genuinely valid nine-record series",
              rc == 0 and "SERIES_VALID = True" in out, out.strip().splitlines()[-3:])

        # producer-verifier corruption
        m2 = os.path.join(td, "moved4")
        shutil.copytree(b, m2)
        rp = os.path.join(m2, "raw", sorted(os.listdir(os.path.join(m2, "raw")))[0])
        rec = json.load(open(rp, encoding="utf-8"))
        rec["producer_of"] = {}
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        rc2, out2 = run_bundled(m2, "series_validate.py", *raw_files(m2))
        check("R14d. producer-verifier corruption fails the bundled validator",
              rc2 != 0 and "SERIES_VALID = False" in out2, out2.strip().splitlines()[-2:])

        # sample-verifier corruption
        m3 = os.path.join(td, "moved5")
        shutil.copytree(b, m3)
        rp3 = os.path.join(m3, "raw", sorted(os.listdir(os.path.join(m3, "raw")))[0])
        rec3 = json.load(open(rp3, encoding="utf-8"))
        rec3["sample_coverage"]["adequate"] = True
        rec3["samples"] = rec3["samples"][:5]
        with open(rp3, "w", encoding="utf-8") as f:
            json.dump(rec3, f)
        rc3, out3 = run_bundled(m3, "series_validate.py", *raw_files(m3))
        check("R14e. sample-verifier corruption fails the bundled validator",
              rc3 != 0 and "SERIES_VALID = False" in out3, out3.strip().splitlines()[-2:])

        # replay gate survives in the bundled validator
        m4 = os.path.join(td, "moved6")
        shutil.copytree(b, m4)
        rp4 = os.path.join(m4, "raw", sorted(os.listdir(os.path.join(m4, "raw")))[-1])
        rec4 = json.load(open(rp4, encoding="utf-8"))
        rec4["verdicts"]["PARTITION"] = True
        with open(rp4, "w", encoding="utf-8") as f:
            json.dump(rec4, f)
        rc4, out4 = run_bundled(m4, "series_validate.py", *raw_files(m4))
        check("R14f. the replay gate is retained by the bundled validator",
              "PARTITION_PENDING_REPLAY" in out4 or "REPLAY_REQUIRED" in out4,
              out4.strip().splitlines()[-3:])


def test_15_verify_live_inputs():
    with tempfile.TemporaryDirectory() as td:
        b, prov, _ = make_bundle(td)
        lr = BV.verify_live_inputs(b)
        check("R15. matching external identities pass on the originating machine",
              lr["passed"] and lr["checked"] > 0, [lr["checked"], lr["failures"][:2]])

        ei = prov.m["external_identities"]
        first_kind = sorted(ei)[0]
        first_path = sorted(ei[first_kind])[0]

        m = json.load(open(os.path.join(b, "manifest.json"), encoding="utf-8"))
        m["external_identities"][first_kind][first_path]["sha256"] = "0" * 64
        json.dump(m, open(os.path.join(b, "manifest.json"), "w"))
        lr2 = BV.verify_live_inputs(b)
        check("R15b. a wrong recorded hash FAILS",
              (not lr2["passed"]) and any("hashes" in f for f in lr2["failures"]),
              lr2["failures"][:1])

        good_sha = prov.m["external_identities"][first_kind][first_path]["sha256"]
        m["external_identities"][first_kind][first_path]["sha256"] = good_sha
        m["external_identities"][first_kind][first_path]["bytes"] = 1
        json.dump(m, open(os.path.join(b, "manifest.json"), "w"))
        lr3 = BV.verify_live_inputs(b)
        check("R15c. a wrong recorded byte count FAILS",
              (not lr3["passed"]) and any("bytes" in f for f in lr3["failures"]),
              lr3["failures"][:1])

        m["external_identities"][first_kind]["/nonexistent/path/xyz.bin"] = {
            "sha256": "0" * 64, "bytes": 10}
        json.dump(m, open(os.path.join(b, "manifest.json"), "w"))
        lr4 = BV.verify_live_inputs(b)
        check("R15d. a missing external path FAILS",
              any("does not exist" in f for f in lr4["failures"]), lr4["failures"][:2])

        moved = os.path.join(td, "iso15")
        shutil.copytree(b, moved)
        r_iso = BV.verify(moved, isolated=True)
        check("R15e. isolated mode ignores external paths entirely",
              r_iso.get("out_of_bundle_checksum_entries") == 0, r_iso["failures"][:2])


def test_16_preregistered():
    doc = open(os.path.join(REPO, "docs/round2/OPERATIONAL_PREREGISTRATION.md"),
               encoding="utf-8").read()
    check("R16. section 10 is preregistered and dated before any measured series",
          "Fail-closed verification (preregistered 2026-08-15" in doc)
    check("R16b. the document states the policy is external to the evidence",
          "never** the thresholds" in doc and "declare exactly these values" in doc)
    def documented(v):
        """The document may write 0.90 where Python renders 0.9; both mean the same threshold."""
        forms = {f"**{v}**"}
        if isinstance(v, float):
            forms.add(f"**{v:.2f}**")
        return any(f in doc for f in forms)
    missing = [v for v in (COV.TOPO_MIN_FRACTION, COV.TOPO_MIN_SAMPLES,
                           COV.TOPO_MAX_NONCONFORMANT, COV.BRANCH_MAX_UNREADABLE,
                           COV.BRANCH_MIN_FRACTION, COV.BRANCH_MIN_SAMPLES)
               if not documented(v)]
    check("R16c. every enforced constant appears verbatim in the preregistration",
          not missing, missing)
    check("R16d. the transition phase and its exclusion are documented",
          "belong to **neither** phase" in doc and "break** PARTITION and RECOVERY runs" in doc)
    check("R16e. the bundled-checker requirement is documented",
          "inputs/harness/bundle_verify.py" in doc and "--verify-live-inputs" in doc)


def main():
    print("NON-EVIDENCE round-6 harness tests: the checker cannot accept a false result\n")
    for fn in (test_1_coverage_recomputed, test_2_positive_nine_record,
               test_3_thresholds_are_policy, test_4_explicit_flags_required,
               test_5_readable_needs_evidence, test_6_sequence_integrity,
               test_7_all_same_tip_derived, test_8_recovery_fields, test_9_10_transition,
               test_11_harness_closure, test_12_relocated_bundled_checker,
               test_13_bundled_sample_verifier, test_14_bundled_series_validator,
               test_15_verify_live_inputs, test_16_preregistered):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round6", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round6.py",)),
                       policy={"topo": [COV.TOPO_MIN_FRACTION, COV.TOPO_MIN_SAMPLES,
                                        COV.TOPO_MAX_NONCONFORMANT],
                               "branch": [COV.BRANCH_MAX_UNREADABLE,
                                          COV.BRANCH_MIN_FRACTION,
                                          COV.BRANCH_MIN_SAMPLES]},
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
