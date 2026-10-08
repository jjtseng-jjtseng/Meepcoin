#!/usr/bin/env python3
"""Round-10 harness tests: the two third-miner arms must be the same program.

NON-EVIDENCE. These validate the harness, never the protocol. Nothing here launches a daemon:
every test drives the real SymMiner against a stub that records the exact ordered RPC path.

THE CONFOUND BEING REMOVED

Until now `SymMiner._timestamp` returned immediately for a non-adaptive miner. The third miner in
a CONTROL replicate therefore performed strictly LESS work per preparation cycle than the third
miner in an ATTACK replicate: no timestamp-window read, no candidate calculation, one fewer RPC
against its own daemon every time it re-templated. The two arms were not the same program, so a
difference in achieved attempts between them had a second candidate explanation that no
after-the-fact statistics could separate from the timestamp strategy itself.

Three modes now exist -- honest, control_sham, adaptive -- and the two third-miner modes walk the
identical ordered path:

    height -> block template -> timestamp-window read -> adaptive-candidate calculation

control_sham then DISCARDS the candidate and submits the honest template timestamp. This is a
PROSPECTIVE change. It explains nothing about any already-collected series, and it does not make
Gate N (results/FULLMESH_20260826_gateN) any less invalid: that series stays COLLECTION COMPLETE /
SERIES INVALID / NO CONFIRMED ATTACK RESULT / REPLAY NOT TRIGGERED.

WHAT IS DELIBERATELY UNCHANGED

Token-bucket rate and capacity, the 64-attempt bounded template reuse, the order of submissions,
the absence of concurrency, catch-up and compensating attempts, and every configured rate,
threshold and timing. Tests 8a-8e assert those directly so a later edit cannot drift them.

Usage: python3 node/tests_round10.py [--out=docs/round2/tests_round10.json]
"""
import copy, json, os, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sample_verify as SAMPV
import series_validate as SV
import sym_miner as SM
from live_median_boundary import read_varint, ts_off
from sym_miner import MODE_ADAPTIVE, MODE_CONTROL_SHAM, MODE_HONEST, SymMiner
from tests_round2 import check, RESULTS, report_metadata, CORE_SOURCES
from tests_round4 import full_record

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "docs/round2/tests_round10.json")

# "00"*96 is a genuine, parseable template blob: each 0x00 is a complete varint, so rebuild's
# major/minor/timestamp/prev/nonce offsets all land inside it. The real rebuild is used, not a
# stub, so the timestamp a miner ACTUALLY submits can be read back out of the bytes.
BLOB = "00" * 96
WINDOW = [1_700_000_000 + 10 * i for i in range(60)]


def blob_ts(blob_hex):
    """The timestamp actually encoded in a submitted blob."""
    raw = bytearray.fromhex(blob_hex)
    v, _ = read_varint(raw, ts_off(raw))
    return v


class FakeDaemon:
    """A daemon stub that records the ordered RPC path and can fail any preparation stage.

    It never sleeps and never forks; the miner thread it serves is bounded by max_submits.

    height() has to tell a NEW preparation cycle apart from the bounded loop's tip check, which
    also calls height(). The distinction is exact rather than heuristic: the loop's tip check is
    the only height() that ever immediately follows a submission, so the stub keys on the previous
    call. A heuristic based on "a template is in use" is wrong -- a preparation that fails AFTER
    the template call would leave the flag set and every later cycle would be misattributed to
    cycle 1, which is precisely the failure this stub has to be able to report."""

    def __init__(self, stop, max_submits=6, tip_every=2, start_height=100,
                 fail_stage=None, fail_cycles=(), window=None):
        self.stop = stop
        self.max_submits = max_submits
        self.tip_every = tip_every
        self.h = start_height
        self.fail_stage = fail_stage
        self.fail_cycles = set(fail_cycles)
        self.window = WINDOW if window is None else window
        self.calls = []              # every RPC, in order, tagged by cycle
        self.paths = []              # the ordered preparation path of each cycle
        self.submitted = []          # (cycle, blob_hex) in submission order
        self.submits = 0
        self.cycle = 0
        self.last_call = None
        self.lock = threading.RLock()

    # ---- the three preparation RPCs -------------------------------------------------
    def height(self):
        with self.lock:
            if self.last_call == "submit":             # the loop's tip check, not a new cycle
                self.calls.append((self.cycle, "height:tipcheck"))
                self.last_call = "tipcheck"
                return self.h
            self.cycle += 1
            self.paths.append([])
            self._note("height")
            self._maybe_fail("height")
            return self.h

    def template(self):
        with self.lock:
            self._note("template")
            self._maybe_fail("template")
            return {"blocktemplate_blob": BLOB, "difficulty": 7,
                    "prev_hash": "%064x" % self.h}

    def timestamps(self, lo, hi):
        with self.lock:
            self._note("timestamps")
            self._maybe_fail("timestamp_window")
            if self.fail_stage == "candidate" and self.cycle in self.fail_cycles:
                return [None, None]                    # unusable shape -> the median raises
            return list(self.window)

    # ---- submission ------------------------------------------------------------------
    def submit_detailed(self, blob):
        with self.lock:
            self.calls.append((self.cycle, "submit"))
            self.last_call = "submit"
            self.submits += 1
            self.submitted.append((self.cycle, blob))
            if self.submits % self.tip_every == 0:
                self.h += 1                            # tip moved: the loop must re-template
            if self.submits >= self.max_submits and self.stop is not None:
                self.stop.set()
        return {"outcome": "REJECTED", "block_id": None, "submitted_wall": time.time(),
                "latency_s": 0.001, "blob_sha256": "%064x" % (self.submits * 7919),
                "blob_bytes": len(blob) // 2, "status": "OK", "error": "low difficulty"}

    # ---- internals -------------------------------------------------------------------
    def _note(self, what):
        self.calls.append((self.cycle, what))
        self.paths[-1].append(what)
        self.last_call = what

    def _maybe_fail(self, stage):
        if self.fail_stage == stage and self.cycle in self.fail_cycles:
            raise RuntimeError("injected %s failure" % stage)


def drive(mode, **kw):
    """Run a REAL SymMiner against the stub until it stops. Returns (miner, daemon)."""
    stop = threading.Event()
    d = FakeDaemon(stop, **kw)
    m = SymMiner("h1" if mode == MODE_HONEST else "atk", d, 10_000.0, mode, stop,
                 nonce_salt=1, identity={"series_id": "T10"}, clock=None)
    m.start()
    m.join(timeout=20)
    if m.is_alive():
        raise RuntimeError("the stubbed miner did not terminate")
    return m, d


def record_for(atk_mode, condition, **kw):
    """A minimal record carrying only what check_preparation_cycles reads."""
    h1, _ = drive(MODE_HONEST, max_submits=4, tip_every=2)
    atk, d = drive(atk_mode, **kw)
    atk.name = "atk"
    for e in atk.events:
        e["miner"] = "atk"
    for c in atk.cycles:
        c["miner"] = "atk"
    ev = {"h1": h1.evidence(), "atk": atk.evidence()}
    ev["atk"]["miner"] = "atk"
    return {"condition": condition, "replicate": 1,
            "third_miner_mode": atk_mode, "miner_evidence": ev}, d


def verify(rec):
    res = {"failures": []}
    SAMPV.check_preparation_cycles(rec, res, res["failures"].append)
    return res


def caught(rec, needle):
    r = verify(rec)
    return any(needle in f for f in r["failures"]), r["failures"]


# ------------------------------------------------------------------ 1. one ordered path
def test_1_identical_ordered_path():
    _, d_sham = drive(MODE_CONTROL_SHAM, max_submits=8, tip_every=2)
    _, d_adapt = drive(MODE_ADAPTIVE, max_submits=8, tip_every=2)
    _, d_honest = drive(MODE_HONEST, max_submits=8, tip_every=2)
    want = ["height", "template", "timestamps"]
    check("T10-1. control_sham walks height -> template -> timestamp window on EVERY cycle",
          bool(d_sham.paths) and all(p == want for p in d_sham.paths), d_sham.paths[:3])
    check("T10-1b. adaptive walks the identical path",
          d_adapt.paths == d_sham.paths[:len(d_adapt.paths)] or
          all(p == want for p in d_adapt.paths), d_adapt.paths[:3])
    check("T10-1c. the two arms issue the SAME ordered RPC path per cycle",
          [p for p in d_sham.paths] == [p for p in d_adapt.paths],
          [d_sham.paths[:2], d_adapt.paths[:2]])
    check("T10-1d. an honest miner does NOT read the timestamp window",
          all(p == ["height", "template"] for p in d_honest.paths), d_honest.paths[:3])


# ------------------------------------------------------------------ 2. computed vs applied
def test_2_sham_computes_then_discards():
    m_s, d_s = drive(MODE_CONTROL_SHAM, max_submits=6, tip_every=2)
    m_a, d_a = drive(MODE_ADAPTIVE, max_submits=6, tip_every=2)
    check("T10-2. control_sham COMPUTES a candidate on every prepared cycle",
          bool(m_s.cycles) and all(c["candidate_computed"] and c["computed_strategy"]
                                   in ("max-legal-future", "lowest-legal")
                                   for c in m_s.cycles if c["status"] == "prepared"),
          [(c["computed_strategy"], c["computed_timestamp"]) for c in m_s.cycles[:2]])
    check("T10-2b. and DISCARDS it: applied is the honest template timestamp",
          all(c["candidate_discarded"] is True and c["applied_timestamp"] is None
              and c["applied_strategy"] == "honest-template"
              for c in m_s.cycles if c["status"] == "prepared"),
          [(c["candidate_discarded"], c["applied_strategy"]) for c in m_s.cycles[:2]])
    check("T10-2c. adaptive APPLIES the same computation it performed",
          all(c["candidate_discarded"] is False
              and c["applied_timestamp"] == c["computed_timestamp"]
              and c["applied_strategy"] == c["computed_strategy"]
              for c in m_a.cycles if c["status"] == "prepared"),
          [(c["computed_strategy"], c["applied_strategy"]) for c in m_a.cycles[:2]])

    # the BYTES prove it: the sham's blobs keep the template's timestamp, the attacker's do not
    sham_ts = {blob_ts(b) for _, b in d_s.submitted}
    atk_ts = {blob_ts(b) for _, b in d_a.submitted}
    check("T10-2d. every control_sham submission carries the template timestamp (0), unmodified",
          sham_ts == {0}, sorted(sham_ts)[:4])
    check("T10-2e. every adaptive submission carries a rewritten timestamp",
          bool(atk_ts) and 0 not in atk_ts, sorted(atk_ts)[:4])
    lows = [c["computed_timestamp"] for c in m_s.cycles
            if c.get("computed_strategy") == "lowest-legal"]
    check("T10-2f. the sham's discarded candidate is the real median, not a placeholder",
          all(t == SM.epee_median(WINDOW) for t in lows) if lows else False,
          [lows[:2], SM.epee_median(WINDOW)])


# ------------------------------------------------------------------ 3. complete linkage
def test_3_linkage_is_complete():
    m, _ = drive(MODE_ADAPTIVE, max_submits=9, tip_every=3)
    ids = [c["cycle"] for c in m.cycles]
    check("T10-3. cycle ids are contiguous from 1 with no duplicates",
          ids == list(range(1, len(ids) + 1)), ids[:8])
    linked = {}
    for e in m.events:
        linked.setdefault(e["cycle"], []).append(e["seq"])
    check("T10-3b. every event names a cycle that exists",
          all(c in set(ids) for c in linked), sorted(set(linked) - set(ids))[:4])
    check("T10-3c. every cycle's declared attempt_count and seq range match its events",
          all(c["attempt_count"] == len(linked.get(c["cycle"], []))
              and (c["first_seq"] == min(linked[c["cycle"]]) if c["cycle"] in linked
                   else c["first_seq"] is None)
              and (c["last_seq"] == max(linked[c["cycle"]]) if c["cycle"] in linked
                   else c["last_seq"] is None)
              for c in m.cycles),
          [(c["cycle"], c["attempt_count"], c["first_seq"], c["last_seq"])
           for c in m.cycles[:4]])
    check("T10-3d. the attempts sum to the event count, so nothing is double-counted",
          sum(c["attempt_count"] for c in m.cycles) == len(m.events) == m.attempts,
          [sum(c["attempt_count"] for c in m.cycles), len(m.events), m.attempts])
    check("T10-3e. the per-candidate rows carry ONLY the integer cycle id, not the telemetry",
          all(set(e) & {"stage_s", "computed_timestamp", "window_len"} == set()
              for e in m.events) and all(isinstance(e["cycle"], int) for e in m.events),
          sorted(set(m.events[0]) & {"stage_s", "computed_timestamp", "window_len"}))
    rec, _ = record_for(MODE_ADAPTIVE, "attack", max_submits=6, tip_every=2)
    check("T10-3f. an honest complete record passes the offline cycle check",
          not verify(rec)["failures"], verify(rec)["failures"][:3])


# ------------------------------------------------------------------ 4. failure rows
def test_4_failed_cycles_are_recorded():
    for stage, before in (("height", []), ("template", ["height"]),
                          ("timestamp_window", ["height", "template"]),
                          ("candidate", ["height", "template", "timestamp_window"])):
        m, d = drive(MODE_ADAPTIVE, max_submits=4, tip_every=2, fail_stage=stage,
                     fail_cycles=(1,))
        bad = [c for c in m.cycles if c["status"] == "failed"]
        ok = (len(bad) == 1 and bad[0]["cycle"] == 1
              and bad[0]["error_stage"] == stage
              and bad[0]["attempt_count"] == 0
              and bad[0]["first_seq"] is None
              and sorted(bad[0]["stage_s"]) == sorted(before))
        check("T10-4. an injected %s failure yields one failed cycle timing exactly %s"
              % (stage, before or "nothing"), ok,
              [bad[0]["error_stage"], sorted(bad[0]["stage_s"]),
               bad[0]["attempt_count"]] if bad else "no failed cycle")
        check("T10-4b. the %s failure produced no submission from that cycle" % stage,
              all(c != 1 for c, _ in d.submitted), [c for c, _ in d.submitted][:4])
        check("T10-4c. and the miner survived it and kept mining (%s)" % stage,
              m.fatal_error is None and m.attempts > 0,
              [m.fatal_error, m.attempts])


# ------------------------------------------------------------------ 5. missing telemetry
def test_5_missing_telemetry_is_rejected():
    rec, _ = record_for(MODE_ADAPTIVE, "attack", max_submits=6, tip_every=2)
    bad = copy.deepcopy(rec)
    bad["miner_evidence"]["atk"]["preparation_cycles"] = []
    bad["miner_evidence"]["atk"]["preparation_cycle_count"] = 0
    hit, f = caught(bad, "has no telemetry row")
    check("T10-5. events whose cycle has no telemetry row are REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    cyc = bad["miner_evidence"]["atk"]["preparation_cycles"]
    del cyc[1]
    bad["miner_evidence"]["atk"]["preparation_cycle_count"] = len(cyc)
    hit, f = caught(bad, "missing, reordered or fabricated")
    check("T10-5b. a deleted middle row breaks the 1..n contiguity and is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    for e in bad["miner_evidence"]["atk"]["events"]:
        e.pop("cycle", None)
    hit, f = caught(bad, "no integer cycle id")
    check("T10-5c. an event with no cycle id at all is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    bad["miner_evidence"]["atk"].pop("preparation_cycles")
    hit, f = caught(bad, "carries no preparation_cycles list")
    check("T10-5d. a miner declaring a mode but carrying no telemetry is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    bad["miner_evidence"]["h1"].pop("mode")
    hit, f = caught(bad, "mixes schemas")
    check("T10-5e. a record where only some miners declare a mode is REJECTED", hit, f[:2])


# ------------------------------------------------------------------ 6. duplicate telemetry
def test_6_duplicate_telemetry_is_rejected():
    rec, _ = record_for(MODE_ADAPTIVE, "attack", max_submits=6, tip_every=2)
    bad = copy.deepcopy(rec)
    cyc = bad["miner_evidence"]["atk"]["preparation_cycles"]
    cyc.insert(1, copy.deepcopy(cyc[0]))
    bad["miner_evidence"]["atk"]["preparation_cycle_count"] = len(cyc)
    hit, f = caught(bad, "duplicate preparation-cycle ids")
    check("T10-6. two rows claiming the same cycle id are REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    cyc = bad["miner_evidence"]["atk"]["preparation_cycles"]
    cyc.append(copy.deepcopy(cyc[-1]))
    cyc[-1]["cycle"] = len(cyc)
    cyc[-1]["attempt_count"] = 0
    cyc[-1]["first_seq"] = cyc[-1]["last_seq"] = None
    bad["miner_evidence"]["atk"]["preparation_cycle_count"] = len(cyc) - 1
    hit, f = caught(bad, "preparation_cycle_count")
    check("T10-6b. a stated cycle count that disagrees with the rows is REJECTED", hit, f[:2])


# ------------------------------------------------------------------ 7. orphaned/contradictory
def test_7_orphaned_and_contradictory_are_rejected():
    rec, _ = record_for(MODE_ADAPTIVE, "attack", max_submits=6, tip_every=2)

    bad = copy.deepcopy(rec)
    bad["miner_evidence"]["atk"]["preparation_cycles"][0]["attempt_count"] += 5
    hit, f = caught(bad, "contradictory telemetry")
    check("T10-7. a row claiming more attempts than reference it is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    ev = bad["miner_evidence"]["atk"]
    orph = copy.deepcopy(ev["preparation_cycles"][-1])
    orph.update({"cycle": len(ev["preparation_cycles"]) + 1, "attempt_count": 3,
                 "first_seq": 9001, "last_seq": 9003})
    ev["preparation_cycles"].append(orph)
    ev["preparation_cycle_count"] = len(ev["preparation_cycles"])
    hit, f = caught(bad, "orphaned telemetry")
    check("T10-7b. a row claiming attempts that no event references is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec)
    bad["miner_evidence"]["atk"]["preparation_cycles"][0]["applied_timestamp"] += 1
    hit, f = caught(bad, "contradicts the cycle")
    check("T10-7c. a row whose applied timestamp contradicts its own events is REJECTED",
          hit, f[:2])

    bad = copy.deepcopy(rec)
    for c in bad["miner_evidence"]["atk"]["preparation_cycles"]:
        c["candidate_discarded"] = True
    hit, f = caught(bad, "must APPLY its candidate")
    check("T10-7d. an adaptive row claiming it discarded its candidate is REJECTED", hit, f[:2])

    # the parity claim itself: a sham that skipped the window read cannot pass
    rec2, _ = record_for(MODE_CONTROL_SHAM, "control", max_submits=6, tip_every=2)
    check("T10-7e. an honest control_sham record passes", not verify(rec2)["failures"],
          verify(rec2)["failures"][:3])
    bad = copy.deepcopy(rec2)
    for c in bad["miner_evidence"]["atk"]["preparation_cycles"]:
        c["window_read"] = False
        c["candidate_computed"] = False
        c["stage_s"].pop("timestamp_window", None)
        c["stage_s"].pop("candidate", None)
    hit, f = caught(bad, "must read the timestamp window")
    check("T10-7f. a control_sham that skipped the window read is REJECTED -- the parity claim "
          "is checkable, not assumed", hit, f[:2])

    bad = copy.deepcopy(rec2)
    bad["third_miner_mode"] = MODE_ADAPTIVE
    hit, f = caught(bad, "third_miner_mode")
    check("T10-7g. a CONTROL record claiming an adaptive third miner is REJECTED", hit, f[:2])

    bad = copy.deepcopy(rec2)
    bad["miner_evidence"]["atk"]["adaptive"] = True
    hit, f = caught(bad, "contradicts mode")
    check("T10-7h. adaptive=true alongside mode=control_sham is REJECTED", hit, f[:2])

    # ---- and the same binding at SERIES level, where a mismatched arm would be a swap ----
    def series(mode_of, mixed=False):
        recs = []
        for rep in (1, 2, 3):
            for cond in ("none", "control", "attack"):
                r = full_record(cond, rep)
                if cond in ("control", "attack") and not (mixed and rep == 3):
                    r["third_miner_mode"] = mode_of(cond)
                recs.append(r)
        return recs

    def sv(recs):
        vres = {"%s#%s" % (r["condition"], r["replicate"]): {"passed": True, "failures": []}
                for r in recs}
        return SV.validate(recs, verifier_results=vres)

    right = {"control": MODE_CONTROL_SHAM, "attack": MODE_ADAPTIVE}
    out = sv(series(right.get))
    check("T10-7i. a series whose arms declare the correct modes raises no mode reason",
          not [x for x in out["invalid_reasons"] if "third_miner_mode" in x],
          out["invalid_reasons"][:3])

    swapped = {"control": MODE_ADAPTIVE, "attack": MODE_CONTROL_SHAM}
    out = sv(series(swapped.get))
    check("T10-7j. swapping the arms' modes makes the series INVALID",
          out["series_valid"] is False
          and len([x for x in out["invalid_reasons"] if "third_miner_mode" in x]) == 6,
          [x for x in out["invalid_reasons"] if "third_miner_mode" in x][:2])

    recs = series(right.get)
    for r in recs:
        if r["condition"] == "none":
            r["third_miner_mode"] = MODE_ADAPTIVE
    out = sv(recs)
    check("T10-7k. a NONE record declaring a third-miner mode is REJECTED",
          bool([x for x in out["invalid_reasons"] if "must declare no third_miner_mode" in x]),
          [x for x in out["invalid_reasons"] if "third_miner_mode" in x][:2])

    out = sv(series(right.get, mixed=True))
    check("T10-7l. a series mixing harness generations is REJECTED",
          bool([x for x in out["invalid_reasons"] if "mixes harness generations" in x]),
          [x for x in out["invalid_reasons"] if "generations" in x][:1])


# ------------------------------------------------------------------ 8. nothing else moved
def test_8_invariants_unchanged():
    b = SM.TokenBucket(45.0)
    check("T10-8. the token bucket still holds exactly two seconds of tokens",
          b.rate == 45.0 and b.capacity == 90.0 and b.tokens == 90.0,
          [b.rate, b.capacity, b.tokens])
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sym_miner.py"),
               encoding="utf-8").read()
    check("T10-8b. the bounded template reuse is still exactly 64 attempts",
          src.count("for _ in range(64):") == 1, src.count("for _ in range(64):"))
    check("T10-8c. no concurrency, queue or catch-up was introduced into the miner",
          not any(w in src for w in ("ThreadPool", "concurrent.futures", "Queue(", "catch_up",
                                     "compensat")),
          [w for w in ("ThreadPool", "concurrent.futures", "Queue(", "catch_up", "compensat")
           if w in src])

    m, d = drive(MODE_ADAPTIVE, max_submits=7, tip_every=3)
    order = [e["seq"] for e in m.events]
    check("T10-8d. submissions are recorded in strict seq order, one event per submission",
          order == sorted(order) and order == list(range(1, len(order) + 1))
          and len(order) == len(d.submitted), [order[:6], len(d.submitted)])
    check("T10-8e. every attempt spent exactly one token: attempts == events == submissions",
          m.attempts == len(m.events) == len(d.submitted), [m.attempts, len(m.events),
                                                            len(d.submitted)])

    for bad_mode in (True, False, None, "control", "attack", "sham"):
        try:
            SymMiner("x", None, 1.0, bad_mode, threading.Event())
            ok = False
        except ValueError:
            ok = True
        check("T10-8f. mode %r is refused at construction, never coerced" % (bad_mode,), ok)


def main():
    print("NON-EVIDENCE round-10 harness tests: third-miner path parity and cycle telemetry\n")
    for fn in (test_1_identical_ordered_path, test_2_sham_computes_then_discards,
               test_3_linkage_is_complete, test_4_failed_cycles_are_recorded,
               test_5_missing_telemetry_is_rejected, test_6_duplicate_telemetry_is_rejected,
               test_7_orphaned_and_contradictory_are_rejected, test_8_invariants_unchanged):
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dict(report_metadata("round10", sys.argv, False,
                                       CORE_SOURCES + ("node/tests_round10.py",)),
                       passed=passed, total=len(RESULTS), results=RESULTS),
                  f, indent=1)
    print(f"\n{passed}/{len(RESULTS)} passed -> {OUT}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
