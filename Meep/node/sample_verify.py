#!/usr/bin/env python3
"""Offline verification of SAMPLE-derived claims: rates, phases, fork/lag, PARTITION, RECOVERY.

`evidence_verify.py` proves producer attribution. It does not check the rate rules the experiment
depends on, and an audit fixture with 160 real events but a claimed 40,000 mining attempts passed
every producer check and still returned SERIES_VALID=True. That gap is closed here: every rate and
phase number is recomputed from the serialized event stream and compared with the stored record.

Recovery is evaluated over the FULL ordered post-stop sample sequence. Error, missing and
non-conformant samples break consecutiveness -- the driver previously filtered error samples out
before looking for a run, so `same-tip, error, same-tip, same-tip` could masquerade as three
consecutive same-tip observations.

Usage: python3 node/sample_verify.py <raw condition json> [...]
"""
import hashlib, json, math, os, re, sys

# F: a bundled verifier must NEVER add a file to the sealed bundle it is checking. Running the
# copied series validator used to emit inputs/harness/__pycache__/*.pyc, after which the very
# next isolated bundle verification failed on unlisted files. Suppressing bytecode BEFORE the
# sibling imports below keeps post-seal verification side-effect-free and repeatable in any
# order. `python3 -B` / PYTHONDONTWRITEBYTECODE stay useful as defence in depth, but the code
# must not depend on the caller remembering them.
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage as COV

RECOVERY_SAMPLES = 3
PARTITION_SAMPLES = 20
# P0-6: an absent or nearly-absent miner must not pass by matching another absent miner.
# 80 % of each configured per-miner rate and of the configured total. Fixed here and in
# docs/round2/OPERATIONAL_PREREGISTRATION.md before any measured run.
RATE_FLOOR_FRACTION = 0.80
RATE_FLOOR_UNSET = object()   # "threshold absent from the record"
REQUIRED_IDENTITY = ("series_id", "triplet_id", "matched_replicate_id", "attempt_id",
                     "condition", "replicate", "topology")
EXPECTED_MINERS = {"none": {"h1", "h2"}, "control": {"h1", "h2", "atk"},
                   "attack": {"h1", "h2", "atk"}}


def digest(res):
    return hashlib.sha256(json.dumps(res, sort_keys=True, default=str).encode()).hexdigest()


def _events(rec):
    out = []
    for name, ev in (rec.get("miner_evidence") or {}).items():
        for e in ev.get("events") or []:
            out.append(e)
    return out


# ------------------------------------------------------------------ preparation-cycle telemetry
MINER_MODES = ("honest", "control_sham", "adaptive")
THIRD_MINER_MODES = ("control_sham", "adaptive")
ADAPTIVE_STRATEGIES = ("max-legal-future", "lowest-legal")
HONEST_STRATEGY = "honest-template"

# stages every prepared cycle must have timed, by mode
REQUIRED_STAGES = {"honest": ("height", "template"),
                   "control_sham": ("height", "template", "timestamp_window", "candidate"),
                   "adaptive": ("height", "template", "timestamp_window", "candidate")}
# the ordered path both third-miner modes walk; a failure names the stage that raised
STAGE_ORDER = ("height", "template", "timestamp_window", "candidate")


def check_preparation_cycles(rec, res, fail):
    """Every attempt must be explained by exactly one preparation cycle, and the two third-miner
    modes must have walked the same path.

    The point of the telemetry is that a CONTROL third miner and an ATTACK third miner do the same
    work per cycle and differ only in whether the computed candidate is applied. That claim is only
    worth anything if the record cannot lie about it, so this rejects telemetry that is missing,
    duplicated, orphaned, or contradicted by the events it claims to have produced."""
    ev = rec.get("miner_evidence") or {}
    modes = {n: b.get("mode") for n, b in ev.items()}
    present = [n for n, m in modes.items() if m is not None]
    if not present:
        # a record produced before the mode split. It is verifiable in every other respect, but
        # its path-parity claim cannot be checked and is NOT assumed.
        res["miner_schema"] = "pre-mode-split"
        res["preparation_cycles_checked"] = False
        return
    if len(present) != len(ev):
        fail("miner evidence mixes schemas: %s declare a mode and %s do not -- a partial record "
             "cannot be checked for path parity"
             % (sorted(present), sorted(set(ev) - set(present))))
        res["miner_schema"] = "mixed"
        res["preparation_cycles_checked"] = False
        return
    res["miner_schema"] = "current"
    res["preparation_cycles_checked"] = True

    stated = rec.get("third_miner_mode")
    third_modes = {n: m for n, m in modes.items() if m in THIRD_MINER_MODES}
    if rec.get("condition") in ("control", "attack"):
        want = "adaptive" if rec.get("condition") == "attack" else "control_sham"
        if list(third_modes.values()) != [want]:
            fail("condition %s must run exactly one third miner in mode %s, found %s"
                 % (rec.get("condition"), want, third_modes or "none"))
        if stated != want:
            fail("record third_miner_mode %r != %r required by condition %s"
                 % (stated, want, rec.get("condition")))
    elif third_modes:
        fail("condition %s must run no third miner, found %s" % (rec.get("condition"),
                                                                 third_modes))

    counts = {}
    for name, block in sorted(ev.items()):
        mode = block.get("mode")
        if mode not in MINER_MODES:
            fail("%s: unknown miner mode %r" % (name, mode))
            continue
        if bool(block.get("adaptive")) != (mode == "adaptive"):
            fail("%s: adaptive=%r contradicts mode=%r" % (name, block.get("adaptive"), mode))
        cycles = block.get("preparation_cycles")
        if not isinstance(cycles, list):
            fail("%s: declares mode %s but carries no preparation_cycles list" % (name, mode))
            continue
        stated_n = block.get("preparation_cycle_count")
        if stated_n != len(cycles):
            fail("%s: preparation_cycle_count %r != %d rows" % (name, stated_n, len(cycles)))

        events = block.get("events") or []
        # ---- one row per cycle id, contiguous from 1: a deleted row cannot hide ----
        ids = [c.get("cycle") for c in cycles]
        if any(not isinstance(i, int) or isinstance(i, bool) for i in ids):
            fail("%s: every preparation cycle needs an integer id" % name)
            continue
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            fail("%s: duplicate preparation-cycle ids %s" % (name, dup[:5]))
        if ids != list(range(1, len(ids) + 1)):
            fail("%s: preparation-cycle ids are not 1..%d in order (got %s...) -- a row is "
                 "missing, reordered or fabricated" % (name, len(ids), ids[:6]))
        by_id = {}
        for c in cycles:
            by_id.setdefault(c.get("cycle"), c)

        # ---- every event names a cycle that exists ----
        ev_by_cycle = {}
        for e in events:
            cid = e.get("cycle")
            if not isinstance(cid, int) or isinstance(cid, bool):
                fail("%s: event seq %r carries no integer cycle id" % (name, e.get("seq")))
                continue
            if cid not in by_id:
                fail("%s: event seq %r references preparation cycle %r, which has no telemetry "
                     "row" % (name, e.get("seq"), cid))
                continue
            ev_by_cycle.setdefault(cid, []).append(e)

        prev_start = None
        for c in cycles:
            cid = c.get("cycle")
            tag = "%s cycle %s" % (name, cid)
            if c.get("miner") != name:
                fail("%s: row claims miner %r" % (tag, c.get("miner")))
            if c.get("mode") != mode:
                fail("%s: row mode %r != miner mode %r" % (tag, c.get("mode"), mode))
            status = c.get("status")
            if status not in ("prepared", "failed"):
                fail("%s: status %r is neither prepared nor failed" % (tag, status))
                continue

            mine = ev_by_cycle.get(cid, [])
            n = c.get("attempt_count")
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                fail("%s: attempt_count %r is not a non-negative integer" % (tag, n))
            elif n != len(mine):
                fail("%s: declares %d attempts but %d events reference it -- %s telemetry"
                     % (tag, n, len(mine),
                        "orphaned" if not mine else "contradictory"))
            seqs = sorted(e.get("seq") for e in mine)
            if mine:
                if c.get("first_seq") != seqs[0] or c.get("last_seq") != seqs[-1]:
                    fail("%s: declares seq range %r..%r but its events span %r..%r"
                         % (tag, c.get("first_seq"), c.get("last_seq"), seqs[0], seqs[-1]))
                if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
                    fail("%s: its events are not a contiguous seq run (%s)" % (tag, seqs[:6]))
            elif c.get("first_seq") is not None or c.get("last_seq") is not None:
                fail("%s: produced no attempts but declares a seq range %r..%r"
                     % (tag, c.get("first_seq"), c.get("last_seq")))

            # ---- timings ----
            st = c.get("stage_s")
            if not isinstance(st, dict):
                fail("%s: stage_s is not a mapping" % tag)
                st = {}
            for k, v in st.items():
                if k not in STAGE_ORDER:
                    fail("%s: unknown stage %r" % (tag, k))
                elif not _finite(v) or v < 0:
                    fail("%s: stage %s took %r" % (tag, k, v))
            t0, t1 = c.get("cycle_start_mono"), c.get("prepared_mono")
            if not _finite(t0) or not _finite(t1) or t1 < t0:
                fail("%s: cycle_start_mono %r / prepared_mono %r are not an ordered pair"
                     % (tag, t0, t1))
            if prev_start is not None and _finite(t0) and t0 < prev_start:
                fail("%s: starts before the previous cycle" % tag)
            if _finite(t0):
                prev_start = t0

            if status == "failed":
                if not c.get("error_stage") or not c.get("error_type"):
                    fail("%s: failed without naming the stage and exception" % tag)
                if c.get("error_stage") not in STAGE_ORDER:
                    fail("%s: error_stage %r is not one of %s"
                         % (tag, c.get("error_stage"), list(STAGE_ORDER)))
                elif set(st) != set(STAGE_ORDER[:STAGE_ORDER.index(c["error_stage"])]):
                    fail("%s: failed at %s but timed stages %s -- the recorded path does not "
                         "match the recorded failure"
                         % (tag, c["error_stage"], sorted(st)))
                if mine:
                    fail("%s: failed preparation yet %d attempts reference it" % (tag, len(mine)))
                continue

            missing = [k for k in REQUIRED_STAGES[mode] if k not in st]
            if missing:
                fail("%s: mode %s must time %s; missing %s"
                     % (tag, mode, list(REQUIRED_STAGES[mode]), missing))
            extra = [k for k in st if k not in REQUIRED_STAGES[mode]]
            if extra:
                fail("%s: mode %s timed stages it must not walk: %s" % (tag, mode, extra))

            # ---- the path claim itself ----
            want_window = mode in THIRD_MINER_MODES
            if bool(c.get("window_read")) != want_window:
                fail("%s: window_read=%r, but mode %s must%s read the timestamp window"
                     % (tag, c.get("window_read"), mode, "" if want_window else " not"))
            if bool(c.get("candidate_computed")) != want_window:
                fail("%s: candidate_computed=%r contradicts mode %s"
                     % (tag, c.get("candidate_computed"), mode))
            if mode == "honest":
                if c.get("computed_timestamp") is not None or c.get("computed_strategy"):
                    fail("%s: an honest cycle must not carry an adaptive candidate" % tag)
            else:
                if c.get("computed_strategy") not in ADAPTIVE_STRATEGIES:
                    fail("%s: computed_strategy %r is not one of %s"
                         % (tag, c.get("computed_strategy"), list(ADAPTIVE_STRATEGIES)))
                if not isinstance(c.get("computed_timestamp"), int):
                    fail("%s: computed_timestamp %r is not an integer"
                         % (tag, c.get("computed_timestamp")))
                if not isinstance(c.get("window_len"), int) or c.get("window_len") < 0:
                    fail("%s: window_len %r is not a count" % (tag, c.get("window_len")))

            if mode == "adaptive":
                if c.get("candidate_discarded") is not False:
                    fail("%s: an adaptive cycle must APPLY its candidate" % tag)
                if (c.get("applied_timestamp") != c.get("computed_timestamp")
                        or c.get("applied_strategy") != c.get("computed_strategy")):
                    fail("%s: applied %r/%r != computed %r/%r"
                         % (tag, c.get("applied_timestamp"), c.get("applied_strategy"),
                            c.get("computed_timestamp"), c.get("computed_strategy")))
            else:
                if mode == "control_sham" and c.get("candidate_discarded") is not True:
                    fail("%s: a control_sham cycle must DISCARD its candidate" % tag)
                if c.get("applied_timestamp") is not None:
                    fail("%s: mode %s must submit the honest template timestamp, not %r"
                         % (tag, mode, c.get("applied_timestamp")))
                if c.get("applied_strategy") != HONEST_STRATEGY:
                    fail("%s: mode %s must record applied_strategy %r, not %r"
                         % (tag, mode, HONEST_STRATEGY, c.get("applied_strategy")))

            # ---- the events must agree with what the cycle says it applied ----
            for e in mine:
                for field, want in (("timestamp", c.get("applied_timestamp")),
                                    ("timestamp_strategy", c.get("applied_strategy")),
                                    ("intended_height", c.get("height")),
                                    ("template_difficulty", c.get("template_difficulty")),
                                    ("parent_hash_from_template",
                                     c.get("parent_hash_from_template"))):
                    if e.get(field) != want:
                        fail("%s: event seq %r %s=%r contradicts the cycle's %r"
                             % (tag, e.get("seq"), field, e.get(field), want))
                        break
                dm = e.get("dispatch_mono")
                end = c.get("cycle_end_mono")
                if _finite(dm) and _finite(t1) and dm < t1:
                    fail("%s: event seq %r dispatched at %r, before the cycle was prepared (%r)"
                         % (tag, e.get("seq"), dm, t1))
                elif _finite(dm) and _finite(end) and dm > end:
                    fail("%s: event seq %r dispatched at %r, after the cycle ended (%r)"
                         % (tag, e.get("seq"), dm, end))
        counts[name] = {"cycles": len(cycles), "attempts": len(events),
                        "failed_cycles": sum(1 for c in cycles if c.get("status") == "failed")}
    res["preparation_cycles"] = counts


def check_identity(rec, res, fail):
    """P0-1: identity must be present on the RECORD and echoed by every event. A missing field on
    either side is a failure, never a skipped comparison."""
    ident = {}
    for k in REQUIRED_IDENTITY:
        v = rec.get(k)
        if v in (None, ""):
            fail(f"record identity field {k} is missing or empty")
        ident[k] = v
    res["identity"] = ident
    cond = rec.get("condition")
    ev = rec.get("miner_evidence") or {}
    active = {n for n, m in ev.items() if (m.get("events") or [])}
    exp = EXPECTED_MINERS.get(cond)
    if exp is None:
        fail(f"unknown condition {cond!r}")
    else:
        if active - exp:
            fail(f"unexpected active miner(s) {sorted(active - exp)} for condition {cond}")
        if exp - active:
            fail(f"missing active miner(s) {sorted(exp - active)} for condition {cond}")
    res["active_miners"] = sorted(active)
    # F: EVERY event must echo EVERY required identity field. The previous version checked
    # attempt_id/triplet_id on one representative event per miner and then only series_id on the
    # rest, so a wrong attempt_id or triplet_id on any later event passed silently -- which is
    # precisely the substitution the record<->event cross-check exists to catch. Only the first
    # offending event per (miner, field) is reported so one bad run cannot emit 40,000 lines.
    for name, m in ev.items():
        seen = set()
        for e in (m.get("events") or []):
            for k in REQUIRED_IDENTITY:
                if k in seen:
                    continue
                want = rec.get(k)
                if want in (None, ""):
                    continue
                have = e.get(k)
                if have in (None, ""):
                    fail(f"{name}: event seq {e.get('seq')} has no {k}")
                    seen.add(k)
                elif have != want:
                    fail(f"{name}: event seq {e.get('seq')} {k}={have!r} != record {want!r}")
                    seen.add(k)


def check_rate_floors(rec, res, fail, mining, mine_s):
    """P0-6: every miner must actually have participated at its configured rate."""
    cfg = rec.get("configured_rates") or {}
    total_cfg = cfg.get("total")
    per_cfg = {"h1": cfg.get("honest"), "h2": cfg.get("honest"), "atk": cfg.get("third")}
    if not mine_s or not total_cfg:
        fail("cannot evaluate rate floors: configured rates or mining duration missing")
        return
    floors = {}
    expected = EXPECTED_MINERS.get(rec.get("condition"), set(mining))
    for n, cnt in mining.items():
        want = per_cfg.get(n)
        if want in (None, 0) or n not in expected:
            continue
        achieved = cnt / float(mine_s)
        floor = want * RATE_FLOOR_FRACTION
        floors[n] = {"configured": want, "achieved": round(achieved, 4),
                     "floor": round(floor, 4), "ok": achieved >= floor}
        if achieved < floor:
            fail(f"{n}: achieved {achieved:.4f}/s is below {RATE_FLOOR_FRACTION:.0%} of the "
                 f"configured {want}/s (floor {floor:.4f})")
    tot_achieved = sum(mining.values()) / float(mine_s)
    tot_floor = total_cfg * RATE_FLOOR_FRACTION
    floors["_total"] = {"configured": total_cfg, "achieved": round(tot_achieved, 4),
                        "floor": round(tot_floor, 4), "ok": tot_achieved >= tot_floor}
    if tot_achieved < tot_floor:
        fail(f"total achieved {tot_achieved:.4f}/s is below {RATE_FLOOR_FRACTION:.0%} of the "
             f"configured {total_cfg}/s (floor {tot_floor:.4f})")
    res["rate_floors"] = floors


def recompute_rates(rec, res, fail):
    """Per-miner attempts by phase, totals, rates, third share -- all from events."""
    ev = rec.get("miner_evidence") or {}
    pb = rec.get("phase_boundaries") or {}
    # the actual closed-dispatch interval is authoritative for rates; nominal is a fallback
    mine_s = (rec.get("mine_seconds_actual") or rec.get("mine_seconds") or
              (rec.get("resolved") or {}).get("mine_seconds"))
    res["mine_seconds_used"] = mine_s
    by_miner = {}
    seqs = {}
    for name, m in ev.items():
        events = m.get("events") or []
        counts = {}
        seen = set()
        for e in events:
            counts[e.get("phase")] = counts.get(e.get("phase"), 0) + 1
            sq = e.get("seq")
            if sq in seen:
                fail(f"{name}: duplicate event seq {sq}")
            seen.add(sq)
            for idkey in ("series_id", "attempt_id"):
                if idkey in e and rec.get(idkey) and e[idkey] != rec[idkey]:
                    fail(f"{name}: event {idkey}={e[idkey]!r} != record {rec[idkey]!r}")
            dw, cw = e.get("dispatch_wall"), e.get("completed_wall")
            if dw is not None and cw is not None and cw < dw:
                fail(f"{name}: event seq {sq} completed before dispatch")
        seqs[name] = sorted(x for x in seen if isinstance(x, int))
        if seqs[name] and seqs[name] != list(range(1, len(seqs[name]) + 1)):
            fail(f"{name}: event seq numbers are not contiguous from 1")
        by_miner[name] = counts
    res["attempts_by_phase"] = by_miner
    mining = {n: c.get("mining", 0) for n, c in by_miner.items()}
    res["mining_attempts_recomputed"] = mining
    stored_ev = rec.get("mining_attempts_from_events")
    if stored_ev is not None and stored_ev != mining:
        fail(f"mining_attempts_from_events {stored_ev} != recomputed {mining}")
    stored_counters = rec.get("mining_phase_attempts")
    if stored_counters is not None and stored_counters != mining:
        fail(f"mining_phase_attempts counters {stored_counters} != recomputed from events {mining}")
    if rec.get("mining_attempts_counter_agrees") is not True and stored_counters is not None:
        fail("mining_attempts_counter_agrees is not True")
    total = sum(mining.values())
    res["mining_total_recomputed"] = total
    stored_total = rec.get("mining_phase_total_attempts")
    if stored_total is not None and stored_total != total:
        fail(f"mining_phase_total_attempts {stored_total} != recomputed {total}")
    if mine_s:
        rates = {n: v / float(mine_s) for n, v in mining.items()}
        res["mining_rates_recomputed"] = {n: round(v, 4) for n, v in rates.items()}
        stored_rates = rec.get("mining_phase_rate_by_miner") or {}
        for n, v in rates.items():
            sv = stored_rates.get(n)
            if sv is None:
                fail(f"stored mining rate missing for {n}")
            elif abs(sv - v) > 0.01:
                fail(f"{n}: stored rate {sv} != recomputed {v:.4f}")
        res["mining_total_rate_recomputed"] = round(total / float(mine_s), 4)
    if "atk" in mining and total:
        share = mining["atk"] / total
        res["third_share_recomputed"] = round(share, 6)
        st = rec.get("mining_phase_third_share")
        if st is not None and abs(st - share) > 1e-4:
            fail(f"mining_phase_third_share {st} != recomputed {share:.6f}")
    # no attacker dispatch at or after the mining boundary
    b = pb.get("boundary_mono")
    if b is not None and "atk" in ev:
        late = [e.get("seq") for e in (ev["atk"].get("events") or [])
                if e.get("dispatch_mono") is not None and e["dispatch_mono"] >= b]
        res["third_dispatches_at_or_after_boundary"] = len(late)
        if late:
            fail(f"third miner dispatched {len(late)} attempts at/after the mining boundary")
    # A miner the condition EXPECTS must have produced attempts. NONE legitimately has no third
    # miner, so the rule is scoped by condition rather than applied to every key present.
    expected = EXPECTED_MINERS.get(rec.get("condition"), set(mining))
    for n in expected:
        if mining.get(n, 0) == 0:
            fail(f"{n}: zero mining-phase attempts -- miner absent or dead, not a valid condition")
    check_rate_floors(rec, res, fail, mining, mine_s)


# --------------------------------------------------------------------------- schedule binding
TIME_TOL = 1e-6          # fixed floating-point tolerance for monotonic comparisons
ROUND_DP = 4             # the documented rounding the collector uses for late_by_s


def _finite(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def check_schedule(rec, res, fail):
    """Bind the COMPLETE sealed schedule and cross-check every duplicate representation.

    The verifier previously read mining_start/boundary/post_start and never post_end, so a sample
    timestamped arbitrarily far after the run still classified as post_stop. It also never
    compared phase_clock against phase_boundaries, so the two copies of one schedule could
    disagree with no consequence."""
    pb = rec.get("phase_boundaries") or {}
    pc = rec.get("phase_clock") or {}
    need = {"mining_start_mono": pb.get("mining_start_mono"),
            "boundary_mono": pb.get("boundary_mono"),
            "nominal_mining_end_mono": pb.get("nominal_mining_end_mono"),
            "post_start_mono": pb.get("post_start_mono"),
            "post_end_mono": pb.get("post_end_mono")}
    for k, v in need.items():
        if not _finite(v):
            fail("phase_boundaries.%s is missing or not a finite number (%r)" % (k, v))
    if any(not _finite(v) for v in need.values()):
        return None
    start = need["mining_start_mono"]
    end = need["boundary_mono"]
    post = need["post_start_mono"]
    pend = need["post_end_mono"]
    if need["nominal_mining_end_mono"] != end:
        fail("nominal_mining_end_mono %s != boundary_mono %s"
             % (need["nominal_mining_end_mono"], end))
    if not (start <= end <= post <= pend):
        fail("sealed boundaries are not ordered: start=%s end=%s post=%s post_end=%s"
             % (start, end, post, pend))
    for ck, want, label in (("mining_start_mono", start, "mining_start_mono"),
                            ("mining_end_mono", end, "boundary_mono"),
                            ("post_start_mono", post, "post_start_mono"),
                            # P0: the clock must seal the RIGHT edge too, or the window is open
                            ("post_end_mono", pend, "post_end_mono")):
        got = pc.get(ck)
        if not _finite(got):
            fail("phase_clock.%s is missing or not finite (%r)" % (ck, got))
        elif got != want:
            fail("phase_clock.%s %s != phase_boundaries.%s %s" % (ck, got, label, want))
    mine_s = rec.get("mine_seconds")
    post_s = rec.get("post_seconds")
    sample_s = rec.get("sample_seconds")
    for k, v in (("mine_seconds", mine_s), ("post_seconds", post_s),
                 ("sample_seconds", sample_s)):
        if not _finite(v) or v <= 0:
            fail("%s is missing or not a positive finite number (%r)" % (k, v))
    if not all(_finite(v) and v > 0 for v in (mine_s, post_s, sample_s)):
        return None
    if abs(pend - (post + float(post_s))) > TIME_TOL:
        fail("post_end_mono %s != post_start_mono + post_seconds %s"
             % (pend, post + float(post_s)))
    if abs((end - start) - float(mine_s)) > 0.5:
        fail("nominal mining interval %.4fs disagrees with mine_seconds %s"
             % (end - start, mine_s))
    act = rec.get("mine_seconds_actual", pb.get("actual_mining_interval_s"))
    if act is not None:
        if not _finite(act):
            fail("actual mining interval is not finite (%r)" % (act,))
        elif abs(act - round(end - start, ROUND_DP)) > 1e-3:
            fail("actual mining interval %s != sealed %s"
                 % (act, round(end - start, ROUND_DP)))
    # P0: the scheduled-close map is the runtime's proof that each miner's dispatch window was
    # bounded. The attacker closes at mining end; the honest miners close at post end. Anything
    # else means some miner could dispatch outside its own window.
    want_close = {"h1": pend, "h2": pend}
    if rec.get("condition") in ("control", "attack"):
        want_close["atk"] = end
    got_close = (pc.get("dispatch_scheduled_close_mono") or {})
    if set(got_close) != set(want_close):
        fail("dispatch_scheduled_close_mono covers %s, expected exactly %s for condition %s"
             % (sorted(got_close), sorted(want_close), rec.get("condition")))
    else:
        for n, w in want_close.items():
            g = got_close.get(n)
            if not _finite(g):
                fail("dispatch_scheduled_close_mono[%s] is not finite (%r)" % (n, g))
            elif abs(g - w) > TIME_TOL:
                fail("dispatch_scheduled_close_mono[%s] is %s, expected the sealed %s"
                     % (n, g, w))
    sch = {"mining_start": start, "nominal_end": end, "post_start": post, "post_end": pend,
           "sample_seconds": float(sample_s), "mine_seconds": float(mine_s),
           "post_seconds": float(post_s)}
    res["schedule"] = sch
    return sch


def phase_for(t, sch):
    """The one phase rule, bounded at BOTH ends."""
    if t < sch["mining_start"]:
        return "before_start"
    if t < sch["nominal_end"]:
        return "mining"
    if t < sch["post_start"]:
        return "transition"
    if t < sch["post_end"]:
        return "post_stop"
    return "after_end"


def check_cadence(rec, res, fail, samples, sch):
    """Prove the samples are a real SCHEDULE **and** a real set of OBSERVATIONS.

    Commit I validated the distribution of `scheduled_mono` only. Actual `t_mono` had to be
    increasing, inside the window and no earlier than its slot -- with no maximum lateness and no
    actual-slot rule. Preserving Gate G's honest schedules while moving all 12 mining observations
    into the final 0.11 s of mining (max lateness 179.8795 s) and all 12 post observations into the
    final 0.11 s of post-stop (165.1095 s) therefore PASSED with zero failures. The plan covered
    the phase; the measurements did not.
    """
    iv = sch["sample_seconds"]
    prev_t = prev_s = None
    seen_s, seen_t = set(), set()
    bad_phase, slots = [], {"mining": {}, "post_stop": {}}
    for i, sm in enumerate(samples):
        t = sm.get("t_mono")
        sc = sm.get("scheduled_mono")
        lb = sm.get("late_by_s")
        for k, v in (("t_mono", t), ("scheduled_mono", sc), ("late_by_s", lb)):
            if not _finite(v):
                fail("sample %d: %s is missing or not a finite number (%r)" % (i, k, v))
        if not (_finite(t) and _finite(sc) and _finite(lb)):
            continue
        if prev_t is not None and not (t > prev_t):
            fail("sample %d: t_mono %s is not strictly after the previous %s" % (i, t, prev_t))
        if prev_s is not None and not (sc > prev_s):
            fail("sample %d: scheduled_mono %s is not strictly after the previous %s"
                 % (i, sc, prev_s))
        if t in seen_t:
            fail("sample %d: duplicate t_mono %s" % (i, t))
        if sc in seen_s:
            fail("sample %d: duplicate scheduled_mono %s" % (i, sc))
        seen_t.add(t)
        seen_s.add(sc)
        prev_t, prev_s = t, sc

        # BOTH times must lie inside the sealed window
        for k, v in (("scheduled_mono", sc), ("t_mono", t)):
            if not (sch["mining_start"] <= v < sch["post_end"]):
                fail("sample %d: %s %s lies OUTSIDE the sealed run window [%s, %s)"
                     % (i, k, v, sch["mining_start"], sch["post_end"]))

        # lateness: nonnegative, correctly reported, and strictly under one interval. A sample a
        # full interval late did not observe its own slot -- it observed the next one.
        if t < sc - TIME_TOL:
            fail("sample %d: observed at %s BEFORE its scheduled slot %s" % (i, t, sc))
        want_late = round(t - sc, ROUND_DP)
        if abs(lb - want_late) > 10 ** -ROUND_DP:
            fail("sample %d: late_by_s %s != %s derived from t_mono - scheduled_mono"
                 % (i, lb, want_late))
        if lb >= iv - TIME_TOL:
            fail("sample %d: observed %.4fs after its scheduled slot, a full %ss cadence "
                 "interval or more -- it missed its own opportunity and cannot count as "
                 "temporal coverage" % (i, lb, iv))

        # the phase must follow from BOTH times, and match what was stored
        d_sched = phase_for(sc, sch)
        d_actual = phase_for(t, sch)
        stored = sm.get("phase")
        if d_sched != d_actual or stored != d_actual:
            bad_phase.append({"index": i, "stored": stored, "from_scheduled": d_sched,
                              "from_t_mono": d_actual})
        elif d_actual in COV.COVERAGE_PHASES:
            lo = sch["mining_start"] if d_actual == "mining" else sch["post_start"]
            slots[d_actual].setdefault(int((t - lo) // iv), []).append(i)
    if bad_phase:
        fail("%d sample(s) whose stored phase, scheduled phase and observed phase do not all "
             "agree, e.g. %s" % (len(bad_phase), bad_phase[:3]))
    counts = {}
    for sm in samples:
        counts[sm.get("phase")] = counts.get(sm.get("phase"), 0) + 1
    res["phase_counts"] = counts
    res["transition_samples"] = counts.get("transition", 0)
    res["transition_seconds"] = round(sch["post_start"] - sch["nominal_end"], ROUND_DP)

    # ---- distribution, checked on the PLAN and on the MEASUREMENTS ----
    spans = {"mining": (sch["mining_start"], sch["nominal_end"]),
             "post_stop": (sch["post_start"], sch["post_end"])}
    dist = {}
    for ph, (lo, hi) in spans.items():
        rows = [sm for sm in samples if sm.get("phase") == ph
                and _finite(sm.get("scheduled_mono")) and _finite(sm.get("t_mono"))]
        d = {"n": len(rows)}
        if not rows:
            fail("%s: no scheduled observation retained" % ph)
            dist[ph] = d
            continue
        for kind, key in (("scheduled", "scheduled_mono"), ("actual", "t_mono")):
            times = sorted(sm[key] for sm in rows)
            gaps = [b - a for a, b in zip(times, times[1:])]
            d["%s_first_offset" % kind] = round(times[0] - lo, ROUND_DP)
            d["%s_last_gap_to_end" % kind] = round(hi - times[-1], ROUND_DP)
            d["%s_min_gap" % kind] = round(min(gaps), ROUND_DP) if gaps else None
            d["%s_span" % kind] = round(times[-1] - times[0], ROUND_DP)
            if times[0] - lo > iv + TIME_TOL:
                fail("%s: first %s observation is %ss after the phase began, more than one %ss "
                     "interval -- the start of the phase is unobserved"
                     % (ph, kind, d["%s_first_offset" % kind], iv))
            if hi - times[-1] > iv + TIME_TOL:
                fail("%s: last %s observation is %ss before the phase ended, more than one %ss "
                     "interval -- the end of the phase is unobserved"
                     % (ph, kind, d["%s_last_gap_to_end" % kind], iv))
            # Spacing is an invariant of the PLAN only. Honest observations jitter around their
            # slots -- a sample 0.4 ms late followed by one on time leaves a 14.9996 s actual gap
            # in the real Gate G data -- so an actual-gap floor would reject honest runs. What
            # actually matters for measurement is that each observation occupies its own slot,
            # which the distinct-actual-slot rule below enforces directly.
            if kind == "scheduled" and gaps and min(gaps) < iv - TIME_TOL:
                fail("%s: two %s observations are %ss apart, closer than the %ss cadence"
                     % (ph, kind, d["%s_min_gap" % kind], iv))
        # one counted observation per distinct ACTUAL opportunity
        dup = {k: v for k, v in slots[ph].items() if len(v) > 1}
        d["actual_slots"] = len(slots[ph])
        if dup:
            fail("%s: %d observation(s) share an actual %ss slot with another -- two rows in one "
                 "real slot are not two observations (slots %s)"
                 % (ph, sum(len(v) for v in dup.values()), iv,
                    {k: v for k, v in list(dup.items())[:3]}))
        if len(slots[ph]) != len(rows):
            fail("%s: %d rows occupy only %d distinct actual slots"
                 % (ph, len(rows), len(slots[ph])))
        dist[ph] = d
    res["cadence"] = dist


def check_event_phases(rec, res, fail, sch):
    """Derive every miner event phase from dispatch_mono, never from its own label.

    A real post-stop H1 event relabelled `mining`, with every stored counter, rate and share
    updated to match, previously passed: the event phase was read rather than derived."""
    ev = rec.get("miner_evidence") or {}
    by_phase, mismatched = {}, []
    for name, m in sorted(ev.items()):
        rows = m.get("events") or []
        counts = {"mining": 0, "transition": 0, "post_stop": 0}
        prev_d, prev_seq = None, None
        for e in rows:
            d = e.get("dispatch_mono")
            if not _finite(d):
                fail("%s: event seq %s has no finite dispatch_mono" % (name, e.get("seq")))
                continue
            if prev_d is not None and d < prev_d - TIME_TOL:
                fail("%s: event seq %s dispatch_mono %s goes backwards from %s"
                     % (name, e.get("seq"), d, prev_d))
            prev_d = d
            sq = e.get("seq")
            if not isinstance(sq, int):
                fail("%s: event has a non-integer seq %r" % (name, sq))
            elif prev_seq is not None and sq != prev_seq + 1:
                fail("%s: event seq jumps %s -> %s; the stream is not contiguous"
                     % (name, prev_seq, sq))
            if isinstance(sq, int):
                prev_seq = sq
            # P0: the window is closed at BOTH ends. The previous version coerced `after_end`
            # back to `post_stop`, so a dispatch at post_end + 100 s passed. A request first
            # dispatched at or after post end is outside the sealed experiment; only a request
            # dispatched BEFORE post end may legitimately COMPLETE after it.
            derived = phase_for(d, sch)
            if derived == "before_start":
                fail("%s: event seq %s dispatched at %s, BEFORE mining started at %s"
                     % (name, sq, d, sch["mining_start"]))
                continue
            if derived == "after_end":
                fail("%s: event seq %s dispatched at %s, at or after the sealed post end %s -- "
                     "this dispatch is outside the experiment"
                     % (name, sq, d, sch["post_end"]))
                continue
            c_mono = e.get("completed_mono")
            if not _finite(c_mono):
                fail("%s: event seq %s has no finite completed_mono" % (name, sq))
            elif c_mono < d - TIME_TOL:
                fail("%s: event seq %s completed at %s, BEFORE it was dispatched at %s"
                     % (name, sq, c_mono, d))
            counts[derived] = counts.get(derived, 0) + 1
            if e.get("phase") != derived:
                mismatched.append({"miner": name, "seq": sq, "dispatch_mono": d,
                                   "stored": e.get("phase"), "derived": derived})
        by_phase[name] = counts
    if mismatched:
        fail("%d miner event(s) carry a phase that does not follow from their dispatch_mono and "
             "the sealed boundaries, e.g. %s" % (len(mismatched), mismatched[:3]))
    res["attempts_by_phase_recomputed"] = by_phase
    stored = rec.get("attempts_by_phase")
    if not isinstance(stored, dict):
        fail("attempts_by_phase is missing from the record")
    else:
        if set(stored) != set(by_phase):
            fail("attempts_by_phase miners %s != %s" % (sorted(stored), sorted(by_phase)))
        for n, want in by_phase.items():
            got = stored.get(n) or {}
            for ph, c in want.items():
                if got.get(ph, 0) != c:
                    fail("attempts_by_phase[%s][%s] stored %s != derived %s"
                         % (n, ph, got.get(ph), c))
    return by_phase


def _cmp(fail, what, stored, derived):
    """Compare a stored field with the independently derived one."""
    if stored is None:
        fail(f"{what}: absent from the record, so it cannot be checked")
    elif stored != derived:
        fail(f"{what}: stored {stored!r} != derived {derived!r}")


def check_thresholds(rec, res, fail):
    """The record must declare EXACTLY the preregistered policy.

    Reading thresholds out of the record under test let a forged report nominate a permissive
    policy and then satisfy it. The literal constants below are the only acceptable values."""
    want_t = {"min_usable_fraction": COV.TOPO_MIN_FRACTION,
              "min_usable_samples": COV.TOPO_MIN_SAMPLES,
              "max_non_conformant_samples": COV.TOPO_MAX_NONCONFORMANT}
    want_b = {"max_unreadable_samples": COV.BRANCH_MAX_UNREADABLE,
              "min_readable_fraction": COV.BRANCH_MIN_FRACTION,
              "min_readable_samples": COV.BRANCH_MIN_SAMPLES}
    got_t = ((rec.get("sample_coverage") or {}).get("thresholds") or {})
    got_b = ((rec.get("branch_coverage") or {}).get("thresholds") or {})
    for name, want, got in (("sample_coverage", want_t, got_t),
                            ("branch_coverage", want_b, got_b)):
        for k, v in want.items():
            if got.get(k) != v:
                fail(f"{name}.thresholds.{k} is {got.get(k)!r}, not the preregistered {v!r}")
    res["thresholds_match_policy"] = not any(
        got_t.get(k) != v for k, v in want_t.items()) and not any(
        got_b.get(k) != v for k, v in want_b.items())


def check_phase_labels(rec, res, fail, samples):
    """Every sample's phase must follow from its own t_mono and the SEALED boundaries.

    The sampler used to hold a separate mutable boundary, so samples taken after nominal mining end
    but before the attacker's last in-flight submit returned were still labelled `mining`. That
    inflates mining coverage with observations of a network whose attacker had already stopped."""
    pb = rec.get("phase_boundaries") or {}
    start = pb.get("mining_start_mono")
    nominal_end = pb.get("boundary_mono", pb.get("nominal_mining_end_mono"))
    post_start = pb.get("post_start_mono")
    if start is None or nominal_end is None or post_start is None:
        fail("phase_boundaries lack mining_start_mono/boundary_mono/post_start_mono, so sample "
             "phase labels cannot be independently checked")
        return
    if not (start <= nominal_end <= post_start):
        fail(f"sealed boundaries are not ordered: start={start} end={nominal_end} "
             f"post={post_start}")
    counts, bad, prev = {}, [], None
    for i, sm in enumerate(samples):
        t = sm.get("t_mono")
        if t is None:
            fail(f"sample {i} has no t_mono, so its phase cannot be checked")
            continue
        if prev is not None and t < prev:
            fail(f"sample {i} t_mono {t} goes backwards from {prev}")
        prev = t
        want = "mining" if t < nominal_end else ("transition" if t < post_start else "post_stop")
        got = sm.get("phase")
        counts[got] = counts.get(got, 0) + 1
        if got != want:
            bad.append({"index": i, "t_mono": t, "stored": got, "derived": want})
    res["phase_counts"] = counts
    res["transition_samples"] = counts.get("transition", 0)
    res["transition_seconds"] = round(post_start - nominal_end, 4)
    if bad:
        fail(f"{len(bad)} sample(s) carry a phase that does not follow from their t_mono and the "
             f"sealed boundaries, e.g. {bad[:3]}")


def _node_tip(sm, n):
    """The tip this sample recorded for node n, cross-checked between its two locations."""
    tips = (sm.get("tips") or {}).get(n) or {}
    be = (sm.get("branch_evidence") or {}).get(n) or {}
    return tips.get("tip"), be.get("tip"), tips.get("height"), be.get("height")


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _hex64(x):
    return isinstance(x, str) and bool(HEX64.match(x))


def check_branch_completeness(sm, i, fail):
    """A readable sample must CONTAIN complete, well-typed, self-consistent geometry.

    Absent evidence used to be a neutral "cannot decide" that was skipped, and metadata was
    optional in practice: removing chain_digest, corrupting anchor_height or dropping heights all
    passed. Everything the fork/lag decision rests on is now mandatory and typed."""
    ok = True
    tips, be = sm.get("tips"), sm.get("branch_evidence")
    if not isinstance(tips, dict) or not isinstance(be, dict):
        fail("sample %d: branch_readable but tips/branch_evidence are missing" % i)
        return False
    want = set(COV.REQUIRED_NODES)
    for label, d in (("tips", tips), ("branch_evidence", be)):
        if set(d) != want:
            fail("sample %d: %s node set %s != required %s"
                 % (i, label, sorted(d), sorted(want)))
            ok = False
    if not ok:
        return False
    anchors = set()
    for n in COV.REQUIRED_NODES:
        t, e = tips[n], be[n]
        if not isinstance(t.get("height"), int) or not isinstance(e.get("height"), int):
            fail("sample %d: node %s height is missing or not an integer" % (i, n))
            ok = False
        elif t["height"] != e["height"]:
            fail("sample %d: node %s height disagrees %s != %s"
                 % (i, n, t["height"], e["height"]))
            ok = False
        if not _hex64(t.get("tip")) or not _hex64(e.get("tip")):
            fail("sample %d: node %s tip is missing or not a 64-hex hash" % (i, n))
            ok = False
        elif t["tip"] != e["tip"]:
            fail("sample %d: node %s tip disagrees between tips (%s) and branch_evidence (%s)"
                 % (i, n, t["tip"][:12], e["tip"][:12]))
            ok = False
        if not isinstance(e.get("anchor_height"), int) or e["anchor_height"] < 0:
            fail("sample %d: node %s anchor_height is missing or not a non-negative integer" % (i, n))
            ok = False
        if not _hex64(e.get("anchor_hash")):
            fail("sample %d: node %s anchor_hash is missing or not a 64-hex hash" % (i, n))
            ok = False
        if not isinstance(e.get("chain_len"), int):
            fail("sample %d: node %s chain_len is missing or not an integer" % (i, n))
            ok = False
        if not _hex64(e.get("chain_digest")):
            fail("sample %d: node %s chain_digest is missing or not a 64-hex hash" % (i, n))
            ok = False
        anchors.add((e.get("anchor_height"), e.get("anchor_hash")))
    if len(anchors) != 1:
        fail("sample %d: the three nodes do not share ONE common anchor: %s"
             % (i, sorted(anchors)))
        ok = False
    return ok


def check_sequences(sm, i, fail, required):
    """Validate each node's anchored sequence as a chain, not as a bag of hashes."""
    ok = True
    be = sm["branch_evidence"]
    for n in COV.REQUIRED_NODES:
        e = be[n]
        seq = e.get("anchored_hashes")
        if seq is None:
            if required:
                fail("sample %d: node %s has no anchored_hashes, but the tips differ so the "
                     "sequence is required to tell lag from a genuine fork" % (i, n))
                ok = False
            continue
        if not isinstance(seq, list) or not seq:
            fail("sample %d: node %s anchored_hashes is not a non-empty list" % (i, n))
            ok = False
            continue
        if not all(_hex64(h) for h in seq):
            fail("sample %d: node %s anchored_hashes contains a non-64-hex entry" % (i, n))
            ok = False
            continue
        if len(set(seq)) != len(seq):
            fail("sample %d: node %s anchored_hashes contains duplicate hashes" % (i, n))
            ok = False
        if e.get("chain_len") != len(seq):
            fail("sample %d: node %s chain_len %s != %d hashes"
                 % (i, n, e.get("chain_len"), len(seq)))
            ok = False
        # node_view stores `height` as the NEXT daemon height; the sequence spans
        # [anchor_height, height-1], so its length is height - anchor_height
        want_len = e.get("height", 0) - e.get("anchor_height", 0)
        if isinstance(e.get("height"), int) and isinstance(e.get("anchor_height"), int) \
                and len(seq) != want_len:
            fail("sample %d: node %s sequence length %d != height - anchor_height (%d)"
                 % (i, n, len(seq), want_len))
            ok = False
        if hashlib.sha256("".join(seq).encode()).hexdigest() != e.get("chain_digest"):
            fail("sample %d: node %s chain_digest does not match its own hash sequence" % (i, n))
            ok = False
        if seq[0] != e.get("anchor_hash"):
            fail("sample %d: node %s sequence does not start at the recorded anchor" % (i, n))
            ok = False
        if seq[-1] != e.get("tip"):
            fail("sample %d: node %s sequence does not end at its own tip" % (i, n))
            ok = False
    return ok


def lag_or_fork(seq_a, seq_b):
    """Lag ONLY when one complete anchored sequence is an exact PREFIX of the other.

    Deciding lag by hash membership was unsound: inserting the other node's tip anywhere in a
    sequence made a genuine fork read as lag while every length, digest, anchor and endpoint
    still checked out. A prefix relation cannot be forged that way -- the shorter chain must be
    reproduced element for element from the shared anchor.

    Returns (forked, common_ancestor_index) where the index is into the shared prefix."""
    n = 0
    for x, y in zip(seq_a, seq_b):
        if x != y:
            break
        n += 1
    prefix = (n == len(seq_a)) or (n == len(seq_b))
    return (not prefix), n



def check_start_state(rec, res, fail):
    """Derive start identity from start_state; never trust the flag.

    A record could claim start_identical=true while its three nodes recorded different genesis
    hashes, heights and tips, and a nine-record series built that way still validated."""
    si = rec.get("start_identical")
    if not isinstance(si, bool):
        fail("start_identical is missing or not a literal boolean (%r)" % (si,))
    st = rec.get("start_state")
    if not isinstance(st, dict) or not st:
        fail("start_state is missing")
        return None
    if set(st) != set(COV.REQUIRED_NODES):
        fail("start_state node set %s != required %s" % (sorted(st), sorted(COV.REQUIRED_NODES)))
        return None
    fields = ("genesis_hash", "height", "tip_hash", "tip_difficulty", "cumulative_difficulty")
    tuples, ok = {}, True
    for n in COV.REQUIRED_NODES:
        d = st[n] or {}
        if not d:
            # an empty start_state carries no claim; it cannot support start_identical=true
            fail("start_state[%s] is empty, so start identity cannot be derived" % n)
            ok = False
            continue
        for f in fields:
            v = d.get(f)
            if f.endswith("_hash"):
                if not _hex64(v):
                    fail("start_state[%s].%s is missing or not a 64-hex hash" % (n, f))
                    ok = False
            elif not isinstance(v, int) or isinstance(v, bool):
                fail("start_state[%s].%s is missing or not an integer" % (n, f))
                ok = False
        tuples[n] = tuple(d.get(f) for f in fields)
    if not ok:
        return None
    derived = len(set(tuples.values())) == 1
    res["start_identical_recomputed"] = derived
    res["start_tuple"] = list(tuples[COV.REQUIRED_NODES[0]]) if derived else None
    if isinstance(si, bool):
        _cmp(fail, "start_identical", si, derived)
    if not derived:
        fail("the three nodes did not start from the same state: %s"
             % ({n: t[:3] for n, t in tuples.items()}))
    return tuples[COV.REQUIRED_NODES[0]] if derived else None


def recompute_topology(rec, res, fail, samples):
    """Rerun STRICT conformance from each sample's own retained adjacency evidence.

    Topology is the controlled experimental variable, so the stored boolean is never the source
    of truth: a sample whose raw adjacency showed a missing FULL_MESH edge previously passed
    because another field said conformant=true."""
    import topology as T
    topo = rec.get("topology")
    if not topo:
        fail("record does not state its topology, so conformance cannot be rerun")
        return None
    names = list(COV.REQUIRED_NODES)
    derived_all, bad = [], 0
    for i, sm in enumerate(samples):
        if not sm.get("topology_observed"):
            derived_all.append(None)
            continue
        adj = sm.get("adjacency")
        if not isinstance(adj, dict) or not adj:
            fail("sample %d: topology_observed but no adjacency evidence is retained" % i)
            derived_all.append(None)
            bad += 1
            continue
        for k in ("rpc_errors", "unresolved"):
            if not isinstance(sm.get(k), list):
                fail("sample %d: topology_observed but %s is missing" % (i, k))
                bad += 1
        snap = {"adjacency": adj, "rpc_errors": sm.get("rpc_errors") or [],
                "unresolved": sm.get("unresolved") or []}
        d = T.conformance(snap, names, topo)
        derived_all.append(d)
        stored = sm.get("conformance")
        if not isinstance(stored, dict):
            fail("sample %d: no retained conformance result to compare" % i)
            bad += 1
        else:
            for k in ("topology", "required", "forbidden", "mutually_confirmed", "one_sided_only",
                      "missing", "forbidden_present", "rpc_errors", "unresolved_count",
                      "conformant"):
                a, b = stored.get(k), d.get(k)
                if isinstance(a, list) and isinstance(b, list):
                    a = [list(x) if isinstance(x, (list, tuple)) else x for x in a]
                    b = [list(x) if isinstance(x, (list, tuple)) else x for x in b]
                if a != b:
                    fail("sample %d: conformance.%s stored %r != recomputed %r" % (i, k, a, b))
                    bad += 1
        if sm.get("topology_conformant") != d["conformant"]:
            fail("sample %d: topology_conformant stored %r != recomputed %r from its own "
                 "adjacency" % (i, sm.get("topology_conformant"), d["conformant"]))
            bad += 1
        # the flattened copies must agree with the recomputed verdict too
        lm = [list(x) for x in (sm.get("links_missing") or [])]
        if lm != [list(x) for x in d["missing"]]:
            fail("sample %d: links_missing stored %r != recomputed %r" % (i, lm, d["missing"]))
            bad += 1
        lf = [list(x) for x in (sm.get("links_forbidden_present") or [])]
        if lf != [list(x) for x in d["forbidden_present"]]:
            fail("sample %d: links_forbidden_present stored %r != recomputed %r"
                 % (i, lf, d["forbidden_present"]))
            bad += 1
        links = sorted({tuple(sorted((a, b))) for a, peers in adj.items() for b in peers})
        stored_links = sorted(tuple(x) for x in (sm.get("links") or []))
        if stored_links != links:
            fail("sample %d: links stored %r != derived from adjacency %r"
                 % (i, stored_links, links))
            bad += 1
    res["topology_recomputed_samples"] = sum(1 for d in derived_all if d is not None)
    res["topology_recompute_failures"] = bad
    return derived_all


def compare_structure(fail, label, stored, derived):
    """Exact, schema-aware comparison of a whole coverage structure.

    A partial allowlist let fabricated top-level `expected` values and invented per-phase error
    categories through. Comparing the complete structure means a new scientific field cannot be
    silently omitted from checking."""
    if not isinstance(stored, dict):
        fail("%s report is missing from the record" % label)
        return
    def norm(x):
        if isinstance(x, dict):
            return {k: norm(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [norm(v) for v in x]
        return x
    a, b = norm(stored), norm(derived)
    if a == b:
        return
    keys = sorted(set(a) | set(b))
    for k in keys:
        if a.get(k) != b.get(k):
            if isinstance(a.get(k), dict) and isinstance(b.get(k), dict):
                for kk in sorted(set(a[k]) | set(b[k])):
                    if a[k].get(kk) != b[k].get(kk):
                        fail("%s.%s.%s stored %r != derived %r"
                             % (label, k, kk, a[k].get(kk), b[k].get(kk)))
            else:
                fail("%s.%s stored %r != derived %r" % (label, k, a.get(k), b.get(k)))


def recompute_samples(rec, res, fail):
    samples = rec.get("samples") or []
    res["sample_count"] = len(samples)
    if not samples:
        fail("no samples retained")
        return

    missing = COV.missing_explicit_flags(samples)
    if missing:
        fail("%d sample(s) do not state topology_observed and branch_readable as booleans, e.g. "
             "indices %s -- this record cannot be verified under the current schema and must not "
             "be counted" % (len(missing), missing[:5]))
        res["schema"] = "legacy-or-incomplete"
        return
    res["schema"] = "current"

    check_thresholds(rec, res, fail)
    check_start_state(rec, res, fail)

    # ---- the sealed schedule binds everything that follows ----
    sch = check_schedule(rec, res, fail)
    if sch is None:
        fail("the sealed schedule is unusable, so no timing-dependent claim in this record can "
             "be verified")
        return
    check_cadence(rec, res, fail, samples, sch)
    check_event_phases(rec, res, fail, sch)

    # ---- topology rerun from each sample's own adjacency ----
    derived_topo = recompute_topology(rec, res, fail, samples)

    topo_obs = [s_ for s_ in samples if COV.topology_observed(s_)]
    conf_ok = (bool(topo_obs) and all(bool(s_.get("topology_conformant")) for s_ in topo_obs)
               and len(topo_obs) == len(samples))
    if derived_topo is not None:
        seen = [d for d in derived_topo if d is not None]
        conf_ok = (bool(seen) and all(d["conformant"] for d in seen)
                   and len(seen) == len(samples))
    res["topology_observed_samples"] = len(topo_obs)
    res["topology_conformant_throughout_recomputed"] = conf_ok
    _cmp(fail, "topology_conformant_throughout",
         (rec.get("verdicts") or {}).get("topology_conformant_throughout"), conf_ok)

    # ---- BOTH coverages recomputed under the FIXED policy and compared in full ----
    rt = COV.evaluate(samples, sch["mine_seconds"], sch["post_seconds"], sch["sample_seconds"],
                      COV.TOPO_MIN_FRACTION, COV.TOPO_MIN_SAMPLES, COV.TOPO_MAX_NONCONFORMANT)
    rb = COV.branch_evaluate(samples, sch["mine_seconds"], sch["post_seconds"],
                             sch["sample_seconds"], COV.BRANCH_MAX_UNREADABLE,
                             COV.BRANCH_MIN_FRACTION, COV.BRANCH_MIN_SAMPLES)
    res["sample_coverage_recomputed"] = rt
    res["branch_coverage_recomputed"] = rb
    compare_structure(fail, "sample_coverage", rec.get("sample_coverage"), rt)
    compare_structure(fail, "branch_coverage", rec.get("branch_coverage"), rb)
    _cmp(fail, "verdicts.sample_coverage_adequate",
         (rec.get("verdicts") or {}).get("sample_coverage_adequate"), rt["adequate"])
    _cmp(fail, "verdicts.branch_coverage_adequate",
         (rec.get("verdicts") or {}).get("branch_coverage_adequate"), rb["adequate"])

    # ---- per-sample branch derivation ----
    rederived, undecidable = [], 0
    ancestors = []
    for i, sm in enumerate(samples):
        if not COV.branch_readable(sm):
            rederived.append(None)
            ancestors.append(None)
            continue
        if not check_branch_completeness(sm, i, fail):
            rederived.append(None)
            ancestors.append(None)
            undecidable += 1
            continue
        be = sm["branch_evidence"]
        tips_differ = len({be[n]["tip"] for n in COV.REQUIRED_NODES}) > 1
        _cmp(fail, "sample %d: tips_differ" % i, sm.get("tips_differ"), tips_differ)
        _cmp(fail, "sample %d: all_same_tip" % i, sm.get("all_same_tip"), not tips_differ)
        if not check_sequences(sm, i, fail, required=tips_differ):
            rederived.append(None)
            ancestors.append(None)
            undecidable += 1
            continue
        a, b = be["h1"], be["h2"]
        if a["tip"] == b["tip"]:
            rederived.append(False)
            ancestors.append(a.get("anchor_height", 0) + len(a.get("anchored_hashes") or []) - 1
                             if a.get("anchored_hashes") else None)
            continue
        ha, hb = a.get("anchored_hashes"), b.get("anchored_hashes")
        if not ha or not hb:
            fail("sample %d: h1 and h2 tips differ but the anchored sequences needed to tell lag "
                 "from a genuine fork are absent -- this is undecidable evidence, not absence of "
                 "a fork" % i)
            rederived.append(None)
            ancestors.append(None)
            undecidable += 1
            continue
        forked, n_common = lag_or_fork(ha, hb)
        rederived.append(forked)
        ancestors.append(a["anchor_height"] + n_common - 1 if n_common else None)
    res["fork_rederived"] = rederived
    res["undecidable_fork_samples"] = undecidable
    for i, sm in enumerate(samples):
        if rederived[i] is None:
            continue
        _cmp(fail, "sample %d: h1_h2_genuinely_forked" % i,
             bool(sm.get("h1_h2_genuinely_forked")), bool(rederived[i]))
        if "h1_h2_common_ancestor" in sm and ancestors[i] is not None:
            _cmp(fail, "sample %d: h1_h2_common_ancestor" % i,
                 sm.get("h1_h2_common_ancestor"), ancestors[i])

    best = cur = 0
    for i, sm in enumerate(samples):
        if sm.get("phase") not in COV.COVERAGE_PHASES or rederived[i] is None:
            cur = 0
            continue
        cur = cur + 1 if rederived[i] else 0
        best = max(best, cur)
    res["longest_fork_run_recomputed"] = best
    _cmp(fail, "longest_h1_h2_fork_run_samples",
         (rec.get("verdicts") or {}).get("longest_h1_h2_fork_run_samples"), best)
    part = bool(conf_ok and rt["adequate"] and rb["adequate"] and best >= PARTITION_SAMPLES)
    res["partition_recomputed"] = part
    _cmp(fail, "PARTITION", (rec.get("verdicts") or {}).get("PARTITION"), part)

    # ---- RECOVERY from derived same-tip values over post_stop samples only ----
    post = [s_ for s_ in samples if s_.get("phase") == "post_stop"]
    res["post_sample_count"] = len(post)
    run, start_i, first_idx = 0, None, None
    for i, sm in enumerate(post):
        same = None
        if COV.branch_readable(sm) and isinstance(sm.get("branch_evidence"), dict) and \
                all(n in sm["branch_evidence"] for n in COV.REQUIRED_NODES):
            same = len({sm["branch_evidence"][n].get("tip")
                        for n in COV.REQUIRED_NODES}) == 1
        ok = (COV.topology_observed(sm) and COV.branch_readable(sm)
              and sm.get("topology_conformant") and same is True)
        if ok:
            if run == 0:
                start_i = i
            run += 1
            if run >= RECOVERY_SAMPLES and first_idx is None:
                first_idx = start_i
        else:
            run = 0
    res["recovery_recomputed"] = first_idx is not None
    res["recovery_first_index"] = first_idx
    v = rec.get("verdicts") or {}
    _cmp(fail, "RECOVERY", v.get("RECOVERY"), first_idx is not None)
    _cmp(fail, "recovery_first_qualifying_index", v.get("recovery_first_qualifying_index"),
         first_idx)
    want_t = None
    if first_idx is not None:
        if not _finite(post[first_idx].get("t_mono")):
            fail("recovery_first_sample_t cannot be rederived: the sample t_mono is missing")
        else:
            want_t = round(post[first_idx]["t_mono"] - sch["post_start"], 1)
    res["recovery_first_sample_t_recomputed"] = want_t
    if "recovery_first_sample_t" in v or want_t is not None:
        _cmp(fail, "recovery_first_sample_t", v.get("recovery_first_sample_t"), want_t)


def verify_file(path):
    rec = json.load(open(path, encoding="utf-8"))
    res = {"file": path, "condition": rec.get("condition"), "replicate": rec.get("replicate"),
           "failures": []}
    fail = res["failures"].append
    if "miner_evidence" not in rec:
        fail("miner_evidence absent -- rates cannot be recomputed")
        res["passed"] = False
        return res
    try:
        check_identity(rec, res, fail)
        check_preparation_cycles(rec, res, fail)
        recompute_rates(rec, res, fail)
        recompute_samples(rec, res, fail)
    except Exception as e:
        fail(f"{type(e).__name__}: {e}")
    res["passed"] = not res["failures"]
    return res


def main(argv):
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    bad = 0
    for p in paths:
        r = verify_file(p)
        print(f"[{'PASS' if r['passed'] else 'FAIL'}] {os.path.basename(p)}  "
              f"mining={r.get('mining_total_recomputed')} "
              f"third_share={r.get('third_share_recomputed')} "
              f"fork_run={r.get('longest_fork_run_recomputed')} "
              f"recovery={r.get('recovery_recomputed')} digest={digest(r)[:16]}")
        for f in r["failures"][:10]:
            print(f"    ! {f}")
        if not r["passed"]:
            bad += 1
    print(f"\n{len(paths) - bad}/{len(paths)} sample/rate records verified")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
