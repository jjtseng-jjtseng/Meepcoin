#!/usr/bin/env python3
"""One mining implementation for every participant, with a deterministic rate limit.

Last round's honest nodes used the daemon's internal miner while the third miner used an external
template->rebuild->submit loop. Those are different engines with different cadences, so any
percentage formed across them mixed units. Here all three miners are instances of this class.

THREE MODES, AND WHY THE SHAM EXISTS

  honest        h1 and h2. Mines the template timestamp; never reads the timestamp window.
  control_sham  the third miner in a CONTROL replicate.
  adaptive      the third miner in an ATTACK replicate.

control_sham and adaptive execute the SAME ordered preparation path -- height, block template,
timestamp-window read, adaptive-candidate calculation -- and differ only in what they do with the
candidate at the end: adaptive applies it, control_sham discards it and submits the honest template
timestamp. Before this, a CONTROL third miner skipped the window read and the calculation entirely,
so the two arms were not the same program: the ATTACK arm issued one extra RPC per preparation
cycle. Any per-arm difference in achieved attempts therefore had a second candidate explanation
that no amount of after-the-fact statistics could separate from the timestamp strategy itself.
That confound is what this removes; it is a PROSPECTIVE change and it explains nothing about any
already-collected series.

Each preparation cycle emits one compact telemetry row -- stage timings, the computed candidate,
the applied timestamp, and the sequence range of the attempts it produced. The per-candidate rows
carry only the integer cycle id, so the telemetry is not duplicated per attempt, and an offline
verifier can reject missing, duplicate, orphaned or self-contradictory telemetry.

The token bucket makes the candidate-attempt rate a controlled input rather than a property of how
fast a Python loop happens to run, so CONTROL and ATTACK can be matched to within a stated
tolerance and the match can be verified afterwards from the recorded attempt counts.
"""
import threading, time

from live_median_boundary import rebuild, epee_median, TS_WINDOW

FTL, FTL_MARGIN = 7200, 5

MODE_HONEST = "honest"
MODE_CONTROL_SHAM = "control_sham"
MODE_ADAPTIVE = "adaptive"
MODES = (MODE_HONEST, MODE_CONTROL_SHAM, MODE_ADAPTIVE)

# The two third-miner modes that MUST walk the identical preparation path.
THIRD_MODES = (MODE_CONTROL_SHAM, MODE_ADAPTIVE)


class TokenBucket:
    """Deterministic rate limit. Capacity is two seconds of tokens, so a miner may absorb a short
    stall without being able to convert a long one into a burst."""
    def __init__(self, rate_per_s):
        self.rate = float(rate_per_s)
        self.capacity = max(1.0, 2.0 * self.rate)
        self.tokens = self.capacity
        self.t = time.monotonic()
        self.lock = threading.Lock()
        self.waited_s = 0.0

    def take(self, stop=None):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.t) * self.rate)
                self.t = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                need = (1.0 - self.tokens) / self.rate
            if stop is not None and stop.is_set():
                return False
            self.waited_s += min(need, 0.25)
            time.sleep(min(need, 0.25))


class SymMiner(threading.Thread):
    """External miner against its OWN daemon. Never submits to another node."""

    def __init__(self, name, d, rate_per_s, mode, stop, nonce_salt=0, keep_blobs=True,
                 keep_rejects=True, identity=None, clock=None):
        super().__init__(daemon=True)
        # `mode` used to be a bool named `adaptive`. Accepting a bool here would silently turn the
        # CONTROL third miner back into an honest miner that skips the window read -- exactly the
        # asymmetry this class now exists to prevent -- so a bool is rejected outright rather than
        # coerced.
        if mode not in MODES:
            raise ValueError(f"SymMiner mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.adaptive = (mode == MODE_ADAPTIVE)   # retained: older evidence readers use this name
        self.name, self.d, self.stop = name, d, stop
        self.bucket = TokenBucket(rate_per_s)
        self.configured_rate = float(rate_per_s)
        self.nonce_salt = nonce_salt
        self.keep_blobs = keep_blobs        # store the exact submitted bytes for later replay
        # EVERY token-spent attempt is recorded. Without rejected attempts the mining-phase
        # totals, cadence, third share and the +/-2% rate checks cannot be recomputed from
        # saved evidence -- only the accepted subset could be, which is not what the rate
        # rules are about.
        self.keep_rejects = keep_rejects
        # NOTE: not `ident` -- threading.Thread.ident is a read-only property and
        # assigning to it raises AttributeError at construction time.
        self.identity = dict(identity or {})   # condition/triplet/attempt identity
        self.seq = 0
        # Phase is DERIVED from an immutable shared schedule, never from a mutable string another
        # thread rewrites. `clock` carries the fixed monotonic boundaries and the dispatch gate.
        self.clock = clock
        self.events = []                    # one compact event per attempt
        self.attempts = 0            # candidate attempts = tokens actually spent
        self.accepted = 0            # submissions the local daemon accepted
        # exact block ids returned BY THE DAEMON for this miner's own accepted submissions.
        # Never inferred from a height lookup.
        self.hashes = set()
        self.rows = []               # full per-candidate records, serialised by the driver
        self.unknown = []            # UNKNOWN_AFTER_TRANSPORT_ERROR candidates
        self.ambiguous = []          # accepted but no block_id returned
        self.rejects = {}
        self.errors = {}
        self.cycles = []             # one compact telemetry row per preparation cycle
        self.t_start = None
        self.t_end = None
        # A thread that died is 'not alive', which previously read as quiescent. These make the
        # difference between 'stopped as instructed' and 'crashed silently' visible.
        self.fatal_error = None
        self.end_reason = None
        self.stop_requested = False

    def _read_window(self, ch):
        """The timestamp window the adaptive calculation needs. Both third-miner modes read it."""
        ph = ch - 1
        return self.d.timestamps(max(0, ph - (TS_WINDOW - 1)), ph) if ch > 0 else []

    @staticmethod
    def _candidate(ch, win):
        """The adaptive timestamp candidate. Pure: identical inputs give identical outputs, so
        the sham arm computes exactly the value the attack arm would have applied."""
        med = epee_median(win) if win else 0
        hi = int(time.time()) + FTL - FTL_MARGIN
        return ((hi, "max-legal-future") if ch % 2 == 0 else (med, "lowest-legal"))

    def _prepare(self, cycle_id):
        """One preparation cycle, in ONE fixed order for both third-miner modes.

        height -> block template -> timestamp-window read -> adaptive-candidate calculation.

        Returns (telemetry_row, template). On failure the row carries status="failed" and the
        stage that raised, and the template is None. Nothing is submitted here, so the failure
        path cannot reorder submissions."""
        t0 = time.monotonic()
        tel = {"cycle": cycle_id, "miner": self.name, "mode": self.mode,
               "cycle_start_wall": time.time(), "cycle_start_mono": t0,
               "window_read": False, "candidate_computed": False,
               "height": None, "parent_hash_from_template": None, "template_difficulty": None,
               "window_len": None, "window_median": None,
               "computed_timestamp": None, "computed_strategy": None,
               "applied_timestamp": None, "applied_strategy": None,
               "candidate_discarded": None,
               "stage_s": {}, "prepared_mono": None,
               "attempt_count": 0, "first_seq": None, "last_seq": None,
               "status": "prepared", "error_stage": None, "error_type": None,
               "error_message": None}

        def fail(stage, exc):
            tel.update({"status": "failed", "error_stage": stage,
                        "error_type": type(exc).__name__, "error_message": str(exc)[:200],
                        "prepared_mono": time.monotonic()})
            k = f"{stage}: {type(exc).__name__}"
            self.errors[k] = self.errors.get(k, 0) + 1
            return tel, None

        mark = t0
        try:
            ch = self.d.height()
        except Exception as e:
            return fail("height", e)
        now = time.monotonic(); tel["stage_s"]["height"] = now - mark; mark = now
        tel["height"] = ch

        try:
            t = self.d.template()
            diff = int(t["difficulty"])
        except Exception as e:
            return fail("template", e)
        now = time.monotonic(); tel["stage_s"]["template"] = now - mark; mark = now
        tel["template_difficulty"] = diff
        tel["parent_hash_from_template"] = t.get("prev_hash")

        if self.mode == MODE_HONEST:
            tel["applied_timestamp"], tel["applied_strategy"] = None, "honest-template"
            tel["candidate_discarded"] = False
            tel["prepared_mono"] = mark
            return tel, t

        # ---- from here the two third-miner modes are the SAME program ----
        try:
            win = self._read_window(ch)
        except Exception as e:
            return fail("timestamp_window", e)
        now = time.monotonic(); tel["stage_s"]["timestamp_window"] = now - mark; mark = now
        tel["window_read"] = True
        tel["window_len"] = len(win)

        try:
            # the median belongs to the candidate calculation, not to the read, and must be
            # inside this try: a window the daemon returns in an unusable shape is a failed
            # preparation cycle, not an unhandled exception that kills the miner thread
            tel["window_median"] = epee_median(win) if win else None
            cand_ts, cand_choice = self._candidate(ch, win)
        except Exception as e:
            return fail("candidate", e)
        now = time.monotonic(); tel["stage_s"]["candidate"] = now - mark
        tel["candidate_computed"] = True
        tel["computed_timestamp"], tel["computed_strategy"] = cand_ts, cand_choice

        if self.mode == MODE_ADAPTIVE:
            tel["applied_timestamp"], tel["applied_strategy"] = cand_ts, cand_choice
            tel["candidate_discarded"] = False
        else:                                    # MODE_CONTROL_SHAM
            # the candidate was computed on the same path and is now thrown away; the honest
            # template timestamp is what actually gets submitted
            tel["applied_timestamp"], tel["applied_strategy"] = None, "honest-template"
            tel["candidate_discarded"] = True
        tel["prepared_mono"] = time.monotonic()
        return tel, t

    def run(self):
        self.t_start = time.time()
        i = 0
        try:
            self._run_inner()
            self.end_reason = self.end_reason or "stop_requested"
        except BaseException as e:
            import traceback
            self.fatal_error = {"type": type(e).__name__, "message": str(e)[:400],
                                "traceback": traceback.format_exc()[-2000:]}
            self.end_reason = "fatal_exception"
        finally:
            self.t_end = time.time()

    # Terminal reasons that mean the miner stopped BECAUSE IT WAS SUPPOSED TO. Anything else --
    # a fatal exception, or a thread that ended for no recorded reason -- is not clean.
    CLEAN_END_REASONS = ("stop_requested", "dispatch_closed")

    def healthy(self):
        """Ran, terminated for a scheduled reason, and recorded one event per attempt.

        `dispatch_closed` is a CLEAN termination, not a fault: the third miner's dispatch window
        ends at the fixed mining boundary, so being refused dispatch there is exactly what is
        supposed to happen to it. This mattered only once the close became SCHEDULED -- while the
        driver closed dispatch late and backdated it, the third miner almost always exited via its
        stop event instead, so this path was effectively unreachable and the health model appeared
        correct. With the scheduled close it is the normal exit, and treating it as unhealthy
        aborted the run at EVIDENCE_CAPTURE (results/SMOKE_20260815_gateC2)."""
        return (self.fatal_error is None and self.end_reason in self.CLEAN_END_REASONS
                and self.attempts > 0 and len(self.events) == self.attempts)

    def _run_inner(self):
        i = 0
        cycle_id = 0
        try:
            while not self.stop.is_set():
                cycle_id += 1
                tel, t = self._prepare(cycle_id)
                self.cycles.append(tel)
                if tel["status"] == "failed":
                    time.sleep(0.05)
                    continue
                ch = tel["height"]
                diff = tel["template_difficulty"]
                parent = tel["parent_hash_from_template"]
                ts, choice = tel["applied_timestamp"], tel["applied_strategy"]
                seq_before = self.seq
                # one template is reused for a bounded number of rate-limited attempts; the loop
                # re-templates whenever the tip moves, which is what a real miner does
                try:
                    for _ in range(64):
                        if self.stop.is_set():
                            return
                        if not self.bucket.take(self.stop):
                            return
                        i += 1
                        nonce = (self.nonce_salt + ch * 100003 + i) & 0xFFFFFFFF
                        blob = rebuild(t["blocktemplate_blob"], ts=ts, nonce=nonce)
                        # Phase is fixed at DISPATCH against immutable boundaries, so an RPC that
                        # completes after a boundary cannot be reassigned to the wrong phase, and a
                        # dispatch during the transition cannot be mislabelled by a racing writer.
                        dispatch_wall, dispatch_mono = time.time(), time.monotonic()
                        if self.clock is not None:
                            if not self.clock.may_dispatch(self.name, dispatch_mono):
                                # dispatch closed for this miner: return the token and stop cleanly
                                self.end_reason = self.end_reason or "dispatch_closed"
                                return
                            phase_at_dispatch = self.clock.phase_of(dispatch_mono)
                        else:
                            phase_at_dispatch = "mining"
                        r = self.d.submit_detailed(blob)
                        self.attempts += 1
                        # everything needed to reproduce attribution from the saved file alone
                        self.seq += 1
                        row = {"miner": self.name, "seq": self.seq, "cycle": cycle_id,
                               "phase": phase_at_dispatch,
                               "outcome": r["outcome"], "block_id": r.get("block_id"),
                               "intended_height": ch, "parent_hash_from_template": parent,
                               "nonce": nonce, "timestamp": ts, "timestamp_strategy": choice,
                               "template_difficulty": diff,
                               "dispatch_wall": dispatch_wall, "dispatch_mono": dispatch_mono,
                               "completed_wall": r["submitted_wall"] + r["latency_s"],
                               "completed_mono": time.monotonic(),
                               "submitted_wall": r["submitted_wall"], "latency_s": r["latency_s"],
                               "blob_sha256": r["blob_sha256"], "blob_bytes": r["blob_bytes"],
                               "response_status": r.get("status"), "error": r.get("error"),
                               **self.identity}
                        # the full blob is kept for ACCEPTED and UNKNOWN (replay and
                        # reconciliation need the exact bytes); a rejected candidate keeps its
                        # hash but not its body
                        if self.keep_blobs and r["outcome"] in ("ACCEPTED",
                                                                "UNKNOWN_AFTER_TRANSPORT_ERROR"):
                            row["blob"] = blob
                        self.events.append(row)
                        if r["outcome"] == "ACCEPTED":
                            self.accepted += 1
                            if r.get("block_id"):
                                self.hashes.add(r["block_id"])
                            else:
                                # accepted but no identifier returned: ambiguous, never guessed
                                self.ambiguous.append(row)
                            self.rows.append(row)
                            break
                        if r["outcome"] == "UNKNOWN_AFTER_TRANSPORT_ERROR":
                            # the candidate may or may not be on a chain. It is NOT a
                            # rejection, it is NOT resubmitted, and it is preserved for
                            # deterministic reconciliation.
                            self.unknown.append(row)
                            self.rows.append(row)
                            break
                        if r.get("error"):
                            self.rejects[r["error"]] = self.rejects.get(r["error"], 0) + 1
                        try:
                            if self.d.height() != ch:
                                break
                        except Exception:
                            break
                finally:
                    # every exit from the bounded loop -- normal, break, stop, dispatch close --
                    # finalises the cycle, so a telemetry row can never be left unlinked
                    n = self.seq - seq_before
                    tel["attempt_count"] = n
                    tel["first_seq"] = seq_before + 1 if n else None
                    tel["last_seq"] = self.seq if n else None
                    tel["cycle_end_mono"] = time.monotonic()
        finally:
            pass

    def stats(self):
        dur = (self.t_end or time.time()) - (self.t_start or time.time())
        dur = dur if dur > 0 else 1e-9
        return {"name": self.name, "mode": self.mode, "adaptive": self.adaptive,
                "preparation_cycles": len(self.cycles),
                "failed_preparation_cycles": sum(1 for c in self.cycles
                                                 if c.get("status") == "failed"),
                "configured_rate_per_s": self.configured_rate,
                "candidate_attempts": self.attempts,
                "achieved_attempts_per_s": round(self.attempts / dur, 4),
                "local_accepted": self.accepted, "recorded_block_ids": len(self.hashes),
                "unknown_after_transport_error": len(self.unknown),
                "accepted_without_block_id": len(self.ambiguous),
                "seconds": round(dur, 2),
                "rate_limiter_wait_s": round(self.bucket.waited_s, 2),
                "fatal_error": self.fatal_error, "end_reason": self.end_reason,
                "healthy": self.healthy(),
                "distinct_reject_reasons": self.rejects, "errors": self.errors}

    def evidence(self):
        """Everything an offline verifier needs, with the per-attempt event stream as the PRIMARY
        source. `block_ids` is a redundant convenience list that the verifier cross-checks against
        the events rather than trusting."""
        by_phase = {}
        for e in self.events:
            by_phase[e["phase"]] = by_phase.get(e["phase"], 0) + 1
        return {"miner": self.name, "mode": self.mode, "adaptive": self.adaptive,
                "events": self.events,
                "preparation_cycles": self.cycles,
                "preparation_cycle_count": len(self.cycles),
                "event_count": len(self.events),
                "attempts_by_phase": by_phase,
                "block_ids": sorted(self.hashes),
                "candidates": self.rows,
                "unknown_after_transport_error": self.unknown,
                "accepted_without_block_id": self.ambiguous,
                "stats": self.stats()}


def calibrate_capacity(d, seconds, nonce_salt=0):
    """Hash-bound capacity for THIS engine and code path: attempts/s when every attempt fails
    proof-of-work, i.e. when the miner is not template-bound. Must be run against a chain whose
    difficulty is far above one attempt per block, otherwise it measures cadence instead."""
    t = d.template()
    diff = int(t["difficulty"])
    n = 0
    t0 = time.time()
    accepted = 0
    while time.time() - t0 < seconds:
        ok, _, _ = d.submit(rebuild(t["blocktemplate_blob"],
                                    nonce=(nonce_salt + n) & 0xFFFFFFFF))
        n += 1
        if ok:
            accepted += 1
            t = d.template()
    dur = time.time() - t0
    return {"template_difficulty": diff, "attempts": n, "seconds": round(dur, 2),
            "attempts_per_s": round(n / dur, 3), "accepted_during_calibration": accepted,
            "hash_bound": diff > 1000 and accepted <= 1,
            "note": "attempts/s with the same external engine used in the experiment; each attempt "
                    "is one MeepHash computed by the daemon during submit_block validation"}
