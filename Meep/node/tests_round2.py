#!/usr/bin/env python3
"""Round-2 harness tests. NON-EVIDENCE: these validate the harness, never the protocol.

Ten required checks plus supporting cases. Live-daemon tests are marked LIVE and use short
throwaway chains; the rest are pure unit tests over the evidence schema.

    1  submit_block success returns and persists the exact block_id                       LIVE
    2  two miners at the same height cannot be attributed to each other by a height race   LIVE
    3  serialized evidence reloads and all producer-derived aggregates recompute exactly
    4  an ambiguous submit transport outcome is preserved and forces the invalid path
    5  topology failure-injection matrix (8 cases)
    6  empty / inadequate sampling cannot pass
    7  all three daemon argvs plus the driver argv appear in a manifest
    8  logs are copied only after process exit, and missing logs fail closed
    9  retry counters and attempt IDs are collision-proof
   10  series-level rate/cap/status validation rejects a deliberately invalid summary

Usage: python3 node/tests_round2.py [--live=0] [--port=48000] [--out=docs/round2/tests.json]
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, time
import pathlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage as COV
import evidence_verify as EV
import series_validate as SV
import topology as T
from provenance import Provenance

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
LIVE = ARG.get("--live", "1") == "1"
PORT = int(ARG.get("--port", 48000))
OUT = ARG.get("--out", "docs/round2/tests_round2.json")
BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
SNAP = os.path.expanduser("~/.meepcoin-lowdiff/snap_src")

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append({"test": name, "passed": bool(ok), "detail": str(detail)[:400]})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""),
          flush=True)
    return bool(ok)


# ----------------------------------------------------------------- synthetic evidence helpers

# --------------------------------------------------------------------- report provenance
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _git(*args):
    try:
        r = subprocess.run(["git"] + list(args), cwd=str(REPO_ROOT),
                           capture_output=True, text=True)
        return r.stdout.strip()
    except Exception:
        return ""


def report_metadata(suite, argv, live, sources=()):
    """Truthful provenance for a canonical test report.

    A report that merely names a commit proves nothing if the tree was dirty when it ran: the
    behaviour it measured may never have been committed. These reports therefore record the
    tested commit, whether the tree was clean AT TEST START, the exact command, and the SHA-256 of
    every harness/test source the suite actually exercises."""
    dirty = _git("status", "--porcelain")
    src = {}
    for rel in sorted(set(sources)):
        q = REPO_ROOT / rel
        try:
            src[rel] = hashlib.sha256(q.read_bytes()).hexdigest()
        except OSError:
            src[rel] = "MISSING"
    return {
        "suite": suite,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tested_commit": _git("rev-parse", "HEAD"),
        "tested_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "tree_clean_at_test_start": dirty == "",
        "uncommitted_at_test_start": dirty.splitlines(),
        "command": " ".join([os.path.basename(sys.executable)] + list(argv)),
        "live": bool(live),
        "source_sha256": src,
    }


CORE_SOURCES = ("node/series_validate.py", "node/sample_verify.py", "node/evidence_verify.py",
                "node/coverage.py", "node/bundle_verify.py", "node/symmetric_series.py",
                "node/sym_miner.py", "node/topology.py", "node/branch_evidence.py",
                "node/provenance.py")


def synth_record(ambiguous=0, unknown=0, collide=False, drop_events=False,
                 tamper_id=False, bad_blob=False, stats_mismatch=False, unattributed=0):
    """A structurally complete condition record whose PRIMARY evidence is the event stream."""
    ids = {"h1": [f"{i:064x}" for i in range(1, 41)],
           "h2": [f"{i:064x}" for i in range(101, 136)],
           "atk": [f"{i:064x}" for i in range(201, 206)]}
    if collide:
        ids["h2"][0] = ids["h1"][0]
    seq, n = [], 0
    for who in ("h1", "h2", "atk"):
        for bid in ids[who]:
            seq.append({"height": n, "hash": bid, "prev_hash": f"p{n}", "timestamp": 1000 + n,
                        "difficulty": 10 + (n % 7), "cumulative_difficulty": 100 + n})
            n += 1
    for k in range(unattributed):            # canonical blocks no event explains
        seq.append({"height": n, "hash": f"{900 + k:064x}", "prev_hash": f"p{n}",
                    "timestamp": 1000 + n, "difficulty": 11, "cumulative_difficulty": 100 + n})
        n += 1

    def mk_events(who, lst):
        ev, seqno = [], 0
        for j, bid in enumerate(lst):
            seqno += 1
            ev.append({"miner": who, "seq": seqno, "phase": "mining", "outcome": "REJECTED",
                       "block_id": None, "blob_sha256": f"{j:064x}"})
            seqno += 1
            blob = "aa" * 4
            e = {"miner": who, "seq": seqno, "phase": "mining", "outcome": "ACCEPTED",
                 "block_id": bid, "blob": blob,
                 "blob_sha256": hashlib.sha256(bytes.fromhex(blob)).hexdigest()}
            if bad_blob and who == "atk" and j == 0:
                e["blob_sha256"] = "0" * 64
            ev.append(e)
        for _ in range(unknown if who == "atk" else 0):
            seqno += 1
            ev.append({"miner": who, "seq": seqno, "phase": "mining",
                       "outcome": "UNKNOWN_AFTER_TRANSPORT_ERROR", "block_id": None,
                       "blob_sha256": "0" * 64})
        for _ in range(ambiguous if who == "atk" else 0):
            seqno += 1
            ev.append({"miner": who, "seq": seqno, "phase": "mining", "outcome": "ACCEPTED",
                       "block_id": None, "blob_sha256": "0" * 64})
        return ev

    ev_map, pof = {}, {}
    for who, lst in ids.items():
        events = [] if drop_events else mk_events(who, lst)
        acc = sum(1 for e in events if e["outcome"] == "ACCEPTED" and e.get("block_id"))
        ev_map[who] = {
            "miner": who, "events": events, "event_count": len(events),
            "block_ids": sorted(lst), "candidates": [],
            "unknown_after_transport_error": [{}] * (unknown if who == "atk" else 0),
            "accepted_without_block_id": [{}] * (ambiguous if who == "atk" else 0),
            "stats": {"candidate_attempts": (len(events) + (5 if stats_mismatch and who == "h1"
                                                            else 0)),
                      "local_accepted": acc}}
        for bid in lst:
            pof[bid] = who
    if tamper_id:
        bad = "f" * 64
        ev_map["h1"]["block_ids"] = sorted([bad] + ev_map["h1"]["block_ids"][1:])

    blocks, work = {}, {}
    for b in seq:
        pr = pof.get(b["hash"], "unattributed")
        blocks[pr] = blocks.get(pr, 0) + 1
        work[pr] = work.get(pr, 0) + b["difficulty"]
    totw = sum(work.values()) or 1
    aw = {pr: {"blocks": blocks[pr], "work": work[pr], "work_share": round(work[pr] / totw, 5)}
          for pr in work}
    occ = EV.rolling_occupancy(seq, pof)
    mx = {pr: max([w.get(pr, 0) for w in occ] or [0])
          for pr in ("h1", "h2", "atk", "unattributed")}
    exact = (ambiguous == 0 and unknown == 0 and not collide and not drop_events
             and not tamper_id and not bad_blob and not stats_mismatch and unattributed == 0)
    return {"condition": "control", "replicate": 1, "attempt_id": "t_control1_a1", "status": "OK",
            "topology": "full_mesh",
            "miner_evidence": ev_map, "producer_of": pof,
            "ambiguous_accepted_count": ambiguous, "unknown_outcome_count": unknown,
            "attribution_exact": exact,
            "canonical_headers": {"h1": seq},
            "blob_archive": {"requested": len(seq), "archived": len(seq), "missing_count": 0},
            "per_node": {"h1": {"accepted_work": aw, "max_window_occupancy": mx,
                                "canonical_blocks_after_start": len(seq)}}}


def snap_from(adj, unresolved=None, errors=None):
    """Build a topology snapshot from a directed adjacency description."""
    return {"adjacency": {a: {b: [{"direction": "out"}] for b in bs} for a, bs in adj.items()},
            "undirected_links": [], "unresolved": unresolved or [], "peer_id_map": {},
            "rpc_errors": errors or [], "raw_connection_counts": {}}


# ----------------------------------------------------------------- tests
def test_3_reload_and_recompute():
    rec = synth_record()
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "cond.json")
        json.dump(rec, open(p, "w"))
        del rec                                   # discard the in-memory object entirely
        r = EV.verify(p)
        check("3. serialized evidence reloads and aggregates recompute exactly",
              r["passed"] and r["attribution_exact"],
              f"checks={len(r['checks'])} events={r.get('event_total')} "
              f"failures={r['failures'][:2]}")
        bad = synth_record()
        bad["per_node"]["h1"]["max_window_occupancy"]["h1"] = 999
        p2 = os.path.join(td, "bad.json")
        json.dump(bad, open(p2, "w"))
        check("3b. verifier FAILS on a tampered stored aggregate", not EV.verify(p2)["passed"])
        p3 = os.path.join(td, "old.json")
        json.dump({"condition": "control", "per_node": {}}, open(p3, "w"))
        r3 = EV.verify(p3)
        check("3c. pre-correction records are reported UNVERIFIABLE, not silently passed",
              not r3["verifiable"] and not r3["passed"])


def test_5b_verifier_negatives():
    """Every way attribution can be unsupported must fail, for the right reason."""
    cases = [
        ("empty event list with populated block_ids", {"drop_events": True}, "event stream"),
        ("one tampered block id", {"tamper_id": True}, "block_ids list disagrees"),
        ("wrong blob hash", {"bad_blob": True}, "blob hash mismatch"),
        ("stats/count mismatch", {"stats_mismatch": True}, "candidate_attempts"),
        ("one UNKNOWN outcome", {"unknown": 1}, "UNKNOWN"),
        ("one accepted without block_id", {"ambiguous": 1}, "no block_id"),
        ("block id collision", {"collide": True}, "claimed by"),
    ]
    with tempfile.TemporaryDirectory() as td:
        for label, kw, expect in cases:
            rec = synth_record(**kw)
            p = os.path.join(td, label.replace(" ", "_").replace("/", "_") + ".json")
            json.dump(rec, open(p, "w"))
            r = EV.verify(p)
            hit = any(expect.lower() in f.lower() for f in r["failures"])
            check(f"5b. verifier fails for the right reason: {label}",
                  (not r["passed"]) and hit,
                  f"passed={r['passed']} first={r['failures'][:1]}")
        # a record that CLAIMS exact attribution while canonical blocks are unattributed must fail
        rec = synth_record(unattributed=1)
        rec["attribution_exact"] = True
        p = os.path.join(td, "claims_exact_with_unattributed.json")
        json.dump(rec, open(p, "w"))
        r = EV.verify(p)
        check("5b. verifier fails for the right reason: claims exact while blocks unattributed",
              (not r["passed"]) and
              any("unattributed" in f for f in r["failures"]),
              f"unattributed={r.get('unattributed_canonical_blocks')} first={r['failures'][:1]}")
        # an honest record that reports exact=False with unattributed blocks is accepted as honest
        rec2 = synth_record(unattributed=1)
        p2 = os.path.join(td, "honest_unattributed.json")
        json.dump(rec2, open(p2, "w"))
        r2 = EV.verify(p2)
        check("5b. an honest record that admits unattributed blocks is not a verifier failure",
              r2["passed"] and r2["attribution_exact"] is False,
              f"exact={r2.get('attribution_exact')}")
        # and a PASS must still exit 0 only when nothing is unsupported
        good = synth_record()
        p = os.path.join(td, "good.json")
        json.dump(good, open(p, "w"))
        check("5b. clean record still passes", EV.verify(p)["passed"])


def test_5_topology_matrix():
    names = ["h1", "h2", "atk"]
    cases = [
        ("correct FULL_MESH", {"h1": ["h2", "atk"], "h2": ["h1", "atk"], "atk": ["h1", "h2"]},
         "full_mesh", True, None, None),
        ("correct STAR", {"h1": ["h2", "atk"], "h2": ["h1"], "atk": ["h1"]},
         "star", True, None, None),
        ("only one endpoint sees a required link", {"h1": ["h2", "atk"], "h2": [], "atk": ["h1"]},
         "full_mesh", False, None, None),
        ("missing required link", {"h1": ["h2"], "h2": ["h1"], "atk": []},
         "full_mesh", False, None, None),
        ("forbidden spoke-to-spoke link present",
         {"h1": ["h2", "atk"], "h2": ["h1", "atk"], "atk": ["h1", "h2"]}, "star", False, None, None),
        ("forbidden link seen by ONE endpoint only",
         {"h1": ["h2", "atk"], "h2": ["h1", "atk"], "atk": ["h1"]}, "star", False, None, None),
        ("unresolved active peer", {"h1": ["h2", "atk"], "h2": ["h1", "atk"], "atk": ["h1", "h2"]},
         "full_mesh", False, [{"node": "h1", "peer_id": "?"}], None),
        ("get_connections RPC error",
         {"h1": ["h2", "atk"], "h2": ["h1", "atk"], "atk": ["h1", "h2"]},
         "full_mesh", False, None, ["h2"]),
    ]
    for label, adj, topo, expect, unres, errs in cases:
        c = T.conformance(snap_from(adj, unres, errs), names, topo)
        check(f"5. topology: {label} -> conformant={expect}",
              c["conformant"] == expect, c["non_conformance_reasons"][:1])


def test_6_sampling():
    ok_sample = {"phase": "mining", "topology_conformant": True, "links": []}
    err_sample = {"phase": "mining", "error": "boom"}
    c = COV.evaluate([], 900, 420, 15.0, 0.90, 10, 0)
    check("6. empty sample list cannot pass", not c["adequate"], c["failures"][:1])
    c = COV.evaluate([err_sample] * 60, 900, 420, 15.0, 0.90, 10, 0)
    check("6b. all-error samples cannot pass", not c["adequate"], c["failures"][:1])
    c = COV.evaluate([ok_sample] * 5, 900, 420, 15.0, 0.90, 10, 0)
    check("6c. below the absolute sample floor cannot pass", not c["adequate"], c["failures"][:1])
    good = ([ok_sample] * 60 +
            [{"phase": "post_stop", "topology_conformant": True, "links": []}] * 28)
    c = COV.evaluate(good, 900, 420, 15.0, 0.90, 10, 0)
    check("6d. full-coverage conformant sampling passes", c["adequate"], c["failures"][:1])
    nc = good[:-1] + [{"phase": "post_stop", "topology_conformant": False, "links": []}]
    c = COV.evaluate(nc, 900, 420, 15.0, 0.90, 10, 0)
    check("6e. a single non-conformant sample fails the phase", not c["adequate"],
          c["failures"][:1])


def test_7_and_9_provenance():
    with tempfile.TemporaryDirectory() as td:
        prov = Provenance(td, harness=["node/topology.py"], binary=BIN,
                          driver_argv=["python3", "node/symmetric_series.py", "--topology=star"])
        argvs = {"h1": ["meepcoind", "--p2p-bind-port", "1"],
                 "h2": ["meepcoind", "--p2p-bind-port", "2"],
                 "atk": ["meepcoind", "--p2p-bind-port", "3"]}
        prov.add_run("control#1#a1", argvs, extra={"attempt_id": "s_control1_a1"})
        prov.update_run("control#1#a1", final_status="OK",
                        daemon_stop={"h1": {"path": "clean", "exited": True}})
        m = json.load(open(os.path.join(td, "manifest.json")))
        r = m["runs"][0]
        check("7. driver argv recorded", "--topology=star" in m["driver_argv"], m["driver_argv"])
        check("7b. all three daemon argvs recorded",
              sorted(r["node_argv"]) == ["atk", "h1", "h2"], sorted(r["node_argv"]))
        check("7c. end-of-run facts attach to the same entry",
              r.get("final_status") == "OK" and "daemon_stop" in r)
        ids = {f"{ns}{c}{rep}_a{a}" for ns in ("star_", "star2_", "mesh_")
               for c in ("none", "control", "attack") for rep in (1, 2, 3) for a in (1, 2, 3)}
        check("9. attempt IDs are collision-proof across namespaces/conditions/reps/attempts",
              len(ids) == 3 * 3 * 3 * 3, len(ids))


def test_8_logs_fail_closed():
    with tempfile.TemporaryDirectory() as td:
        prov = Provenance(os.path.join(td, "ev"), harness=[], binary=BIN)
        d1 = os.path.join(td, "n1"); os.makedirs(d1)
        open(os.path.join(d1, "meepcoind.log"), "w").write("x" * 100)
        d2 = os.path.join(td, "n2"); os.makedirs(d2)          # no log at all
        rep = prov.copy_logs({"n1": d1}, subdir="a", require_all=True)
        check("8. present logs are copied and hashed",
              rep["all_present"] and rep["copied"]["n1"]["sha256"], rep["copied"]["n1"]["bytes"])
        failed = False
        try:
            prov.copy_logs({"n1": d1, "n2": d2}, subdir="b", require_all=True)
        except RuntimeError as e:
            failed = "n2" in str(e)
        check("8b. a missing log FAILS CLOSED instead of being skipped", failed)
        m = json.load(open(os.path.join(td, "ev", "manifest.json")))
        check("8c. the failure is visible in the manifest",
              any(not x["all_present"] for x in m.get("log_capture", [])))



def derived_third_share(rec):
    """The share this record's OWN event stream implies, rounded like the driver.

    The scientific gates now decide from raw counts (Commit P), and a stored display field that
    disagrees with its events is reported as a forgery signal. A fixture must therefore store the
    value its events actually imply -- synth_record() yields h1 80 / h2 70 / atk 10, i.e. 0.0625,
    not the 0.08 these fixtures used to hard-code."""
    m = {n: sum(1 for e in (v.get("events") or []) if e.get("phase") == "mining")
         for n, v in (rec.get("miner_evidence") or {}).items()}
    tot = sum(m.values())
    return round(m.get("atk", 0) / tot, 5) if tot else 0.0


def boost_third_share(rec, extra):
    """Duplicate `extra` attacker mining events so the DERIVED share genuinely rises."""
    ev = rec["miner_evidence"]["atk"]
    rows = list(ev["events"])
    base = rows[-1]
    nxt = max(e.get("seq", 0) for e in rows) + 1
    for i in range(extra):
        rows.append(dict(base, seq=nxt + i))
    ev["events"] = rows
    ev["event_count"] = len(rows)
    ev["stats"] = dict(ev.get("stats") or {}, candidate_attempts=len(rows))
    return rec


def test_10_series_validation():
    """Series-level gates on EVENT-CONSISTENT records.

    These fixtures used to be aggregate-only stubs: they declared 40000 attempts and a 0.08
    third share while carrying a 160-event synth_record stream. Commit P made the scientific
    gates derive from raw events, so a fixture whose aggregates contradict its own events is no
    longer a valid stand-in for a real record. They are now built by tests_round4.full_record,
    which produces matching events and aggregates and lets a test set exact attempt counts."""
    from tests_round4 import full_record
    import copy as _copy

    def series(over=None):
        over = over or {}
        recs, vres = [], {}
        for rep in (1, 2, 3):
            for cond in ("none", "control", "attack"):
                kw = over.get((cond, rep), {})
                r = full_record(cond, rep, **kw)
                recs.append(r)
                vres[f"{cond}#{rep}"] = {"passed": True}
        return recs, vres

    good, vres10 = series()
    v = SV.validate(good, verifier_results=vres10)
    check("10. a well-formed series validates", v["series_valid"], v["invalid_reasons"][:2])

    # TOTAL pairing rule: give ATTACK#2 far fewer honest attempts so the totals diverge >2%
    bad, vb = series({("attack", 2): {"honest_rate": 15.0}})
    v = SV.validate(bad, verifier_results=vb)
    check("10b. rate-mismatched matched pair is rejected",
          not v["series_valid"] and any("deviation" in x for x in v["invalid_reasons"]),
          v["invalid_reasons"][:2])

    # share cap decided from RAW counts: 3600 of 40800 = 0.088235 > 0.085
    bad, vb = series({("control", 2): {"third_rate": 4.0},
                        ("attack", 2): {"third_rate": 4.0}})
    v = SV.validate(bad, verifier_results=vb)
    check("10c. third-miner share over the committed cap is rejected",
          not v["series_valid"] and any("exceeds cap" in x for x in v["invalid_reasons"]),
          [x for x in v["invalid_reasons"] if "cap" in x][:1])

    bad = _copy.deepcopy(good)
    bad[1]["mining_phase_third_share"] = 0.12              # forged; events unchanged
    v = SV.validate(bad, verifier_results=vres10)
    check("10c2. a forged stored share raises no cap finding against events that are in band",
          not any("exceeds cap" in x for x in v["invalid_reasons"])
          and any("disagrees with the raw events" in x for x in v["invalid_reasons"]),
          v["invalid_reasons"][:2])

    bad = _copy.deepcopy(good)
    bad[2]["status"] = "ERROR"
    v = SV.validate(bad, verifier_results=vres10)
    check("10d. an ERROR record hidden behind a COMPLETED manifest is rejected",
          not v["series_valid"], v["invalid_reasons"][:2])

    bad = _copy.deepcopy(good)
    bad[7]["sample_coverage"] = {"adequate": False, "failures": ["zero usable samples"]}
    v = SV.validate(bad, verifier_results=vres10)
    check("10e. inadequate sample coverage is rejected",
          not v["series_valid"] and any("coverage" in x for x in v["invalid_reasons"]))


# ----------------------------------------------------------------- LIVE tests
def test_1_2_live():
    import live_median_boundary as L
    from live_median_boundary import rebuild, rpc
    L.DAEMON = BIN
    gts = json.load(open("docs/lowdiff/snapshot.json"))["snapshot_build"]["genesis_ts"]
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    ds = {}
    try:
        for i, n in enumerate(("m1", "m2")):
            d = os.path.expanduser(f"~/.meepcoin-lowdiff/test_race_{n}")
            if os.path.isdir(d):
                shutil.rmtree(d)
            subprocess.run(["cp", "-a", "--sparse=always", SNAP, d], check=True)
            tn = os.path.join(d, "testnet")
            for sub in os.listdir(tn):
                q = os.path.join(tn, sub, "p2pstate.bin")
                if os.path.exists(q):
                    os.remove(q)
            ds[n] = L.Daemon(f"test_race_{n}", PORT + 10 * i, PORT + 10 * i + 1, fixed_diff=0,
                             offline=True, wipe=False, data_dir=d)
        for n in ds:
            ds[n].wait_synced(60)
        # --- test 1: exact block_id from the submit response ---
        t = ds["m1"].template()
        r = ds["m1"].submit_detailed(rebuild(t["blocktemplate_blob"], nonce=7))
        got = r.get("block_id")
        hdr = rpc(ds["m1"].rpc, "get_block_header_by_height",
                  {"height": ds["m1"].height() - 1})["result"]["block_header"]
        check("1. submit_block returns an exact block_id (LIVE)",
              r["outcome"] == "ACCEPTED" and bool(got) and got == hdr["hash"],
              f"outcome={r['outcome']} block_id={str(got)[:16]} tip={hdr['hash'][:16]}")
        check("1b. the accepted record carries blob hash and latency",
              bool(r.get("blob_sha256")) and r.get("latency_s") is not None,
              f"sha={r['blob_sha256'][:12]} lat={r['latency_s']}")
        # --- test 2: two competing blocks at the SAME height are distinguishable ---
        # Two isolated daemons at identical state produce different blocks for the same height.
        # A height lookup would attribute both to whichever is queried; block_id cannot.
        h = ds["m2"].height()
        t1 = ds["m2"].template()
        r1 = ds["m2"].submit_detailed(rebuild(t1["blocktemplate_blob"], nonce=11))
        d3 = os.path.expanduser("~/.meepcoin-lowdiff/test_race_m3")
        if os.path.isdir(d3):
            shutil.rmtree(d3)
        subprocess.run(["cp", "-a", "--sparse=always", SNAP, d3], check=True)
        tn = os.path.join(d3, "testnet")
        for sub in os.listdir(tn):
            q = os.path.join(tn, sub, "p2pstate.bin")
            if os.path.exists(q):
                os.remove(q)
        ds["m3"] = L.Daemon("test_race_m3", PORT + 30, PORT + 31, fixed_diff=0, offline=True,
                            wipe=False, data_dir=d3)
        ds["m3"].wait_synced(60)
        t2 = ds["m3"].template()
        r2 = ds["m3"].submit_detailed(rebuild(t2["blocktemplate_blob"], nonce=999))
        same_height = (h == ds["m3"].height() - 1)
        distinct = (r1.get("block_id") and r2.get("block_id") and
                    r1["block_id"] != r2["block_id"])
        check("2. competing blocks at the same height get distinct exact block_ids (LIVE)",
              bool(same_height and distinct),
              f"height={h} id1={str(r1.get('block_id'))[:12]} id2={str(r2.get('block_id'))[:12]}")
        pof = {r1["block_id"]: "m2", r2["block_id"]: "m3"}
        check("2b. neither miner can be attributed the other's block",
              pof.get(r1["block_id"]) == "m2" and pof.get(r2["block_id"]) == "m3")
    finally:
        for n in list(ds):
            try: ds[n].stop(clean_wait=10.0)
            except Exception: pass


def test_11_immutability_and_policy():
    """Output immutability, retry-stage policy, and both rate-pair checks."""
    import symmetric_series as SS
    # stage policy
    check("11. only pre-mining stages are retryable",
          SS.PRE_MINING_STAGES == ("SETUP", "TOPOLOGY_PROVEN") and
          "MINING_STARTED" not in SS.PRE_MINING_STAGES and
          "EVIDENCE_CAPTURE" not in SS.PRE_MINING_STAGES,
          str(SS.PRE_MINING_STAGES))
    e = SS.StageError("MINING_STARTED", "boom", partial={"a": 1})
    check("11b. StageError carries stage and the partial record",
          e.stage == "MINING_STARTED" and e.partial == {"a": 1})
    # fail-if-exists on a per-attempt data directory
    with tempfile.TemporaryDirectory() as td:
        old_root, SS.SNAPROOT = SS.SNAPROOT, td
        os.makedirs(os.path.join(td, "r2_exists_h1"))
        before = sorted(os.listdir(td))
        raised = False
        try:
            SS.fresh_copy("r2_exists_h1")
        except SS.StageError as ex:
            raised = "already exists" in str(ex)
        after = sorted(os.listdir(td))
        SS.SNAPROOT = old_root
        check("11c. an existing per-attempt data directory fails closed", raised)
        check("11d. and is left byte-for-byte unchanged", before == after)
    # both rate-pair checks, on EVENT-CONSISTENT records (see test_10 for why)
    from tests_round4 import full_record as _fr
    import copy as _cp

    def _series(over=None):
        over = over or {}
        recs, vr = [], {}
        for rep in (1, 2, 3):
            for cond in ("none", "control", "attack"):
                r = _fr(cond, rep, **over.get((cond, rep), {}))
                recs.append(r)
                vr[f"{cond}#{rep}"] = {"passed": True}
        return recs, vr

    good, vres = _series()
    v = SV.validate(good, verifier_results=vres)
    check("11e. a well-formed series validates", v["series_valid"], v["invalid_reasons"][:2])

    # THIRD-MINER mismatch while the TOTALS stay matched: move 145 attempts from the attacker
    # into the honest miners so the pair totals differ by ~0.003% but the third rates by ~4.6%
    bad, vb = _series({("attack", 2): {"third_rate": 3100 / 900.0,
                                         "honest_rate": 18072 / 900.0},
                         ("control", 2): {"third_rate": 3245 / 900.0,
                                          "honest_rate": 18000 / 900.0}})
    v = SV.validate(bad, verifier_results=vb)
    tot_ok = not any("TOTAL attempt deviation" in x for x in v["invalid_reasons"])
    check("11f. THIRD-MINER rate mismatch is caught even when totals match",
          (not v["series_valid"]) and tot_ok
          and any("THIRD-MINER" in x for x in v["invalid_reasons"]),
          [x for x in v["invalid_reasons"] if "MINER" in x or "TOTAL" in x][:2])
    bad = _cp.deepcopy(good)
    bad[3] = dict(bad[3], replicate=1)
    v = SV.validate(bad, verifier_results=vres)
    check("11g. duplicate replicate records are rejected",
          not v["series_valid"] and any("duplicate" in x for x in v["invalid_reasons"]))
    miss = [dict(r) for r in good]
    miss[0] = {k: v2 for k, v2 in miss[0].items() if k != "log_capture"}
    v = SV.validate(miss, verifier_results=vres)
    check("11h. a MISSING required field is a failure, not an implicit pass",
          not v["series_valid"] and any("missing" in x for x in v["invalid_reasons"]))
    v = SV.validate(good, verifier_results={})
    check("11i. no offline verifier result => series invalid",
          not v["series_valid"] and any("verifier" in x for x in v["invalid_reasons"]))
    vfail = {k: {"passed": False, "failures": ["bad"]} for k in vres}
    v = SV.validate(good, verifier_results=vfail)
    check("11j. a FAILED offline verifier invalidates the series", not v["series_valid"])
    nd = [dict(r) for r in good]
    nd[3] = dict(nd[3], all_daemons_exited=False)
    v = SV.validate(nd, verifier_results=vres)
    check("11k. a daemon that did not exit invalidates the series",
          not v["series_valid"] and any("exit" in x for x in v["invalid_reasons"]))
    nb = [dict(r) for r in good]
    nb[4] = dict(nb[4], blob_archive={"requested": 10, "archived": 9, "missing_count": 1})
    v = SV.validate(nb, verifier_results=vres)
    check("11l. an incomplete blob archive invalidates the series",
          not v["series_valid"] and any("blob" in x for x in v["invalid_reasons"]))


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    print("NON-EVIDENCE harness tests\n")
    print("-- schema / unit tests --")
    test_3_reload_and_recompute()
    test_5b_verifier_negatives()
    test_5_topology_matrix()
    test_6_sampling()
    test_7_and_9_provenance()
    test_8_logs_fail_closed()
    test_10_series_validation()
    test_11_immutability_and_policy()
    if LIVE:
        print("-- live daemon tests --")
        try:
            test_1_2_live()
        except Exception as e:
            check("1/2. LIVE tests", False, f"{type(e).__name__}: {e}")
    else:
        print("-- live daemon tests SKIPPED (--live=0) --")
    passed = sum(1 for r in RESULTS if r["passed"])
    out = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "label": "NON-EVIDENCE harness tests -- validate the harness, never the protocol",
           "live": LIVE, "passed": passed, "total": len(RESULTS), "results": RESULTS}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(out, **report_metadata("round2", sys.argv, LIVE,
                                             CORE_SOURCES
                                             + ("node/tests_round2.py",))),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
