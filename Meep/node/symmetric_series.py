#!/usr/bin/env python3
"""Round 2: symmetric-miner series on a PROVEN topology, with branch-aware evidence.

Every participant runs the same external mining implementation (node/sym_miner.py) under a token
bucket, so capacity, cadence, occupancy and accepted work stay separate and CONTROL/ATTACK can be
rate-matched and verified. Topology is proven by directed adjacency before mining starts and
sampled throughout; a run whose required links are missing fails immediately and is discarded.

Conditions (see docs/round2/PREREGISTRATION.md, committed before the first measured run):
    SYMMETRIC_NONE      h1 + h2 honest timestamps, no third miner
    SYMMETRIC_CONTROL   h1 + h2 + third, all honest timestamps
    SYMMETRIC_ATTACK    as CONTROL, third miner uses the adaptive timestamp strategy

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
No consensus rule is added or modified by this script.
"""
import hashlib, json, os, shutil, statistics, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
import topology as T
import branch_evidence as BE
import coverage as COV
from provenance import Provenance
from sym_miner import SymMiner, MODE_HONEST, MODE_CONTROL_SHAM, MODE_ADAPTIVE
from live_median_boundary import rpc, rest

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
REPO = "/mnt/c/Users/tseng/meepcoin"
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT0 = int(ARG.get("--port", 39000))
MINE_S = int(ARG.get("--mine", 900))
POST_S = int(ARG.get("--post", 420))
REPS = int(ARG.get("--reps", 3))
TOPOLOGY = ARG.get("--topology", "full_mesh")
CONDS = ARG.get("--conditions", "none,control,attack").split(",")
SNAPROOT = os.path.expanduser(ARG.get("--snaproot", "~/.meepcoin-lowdiff"))
SRC = os.path.join(SNAPROOT, "snap_src")
OUTDIR = ARG.get("--outdir", "docs/round2")
EVID = ARG.get("--evidence", None)
SERIES = ARG.get("--series", None)
SMOKE = ARG.get("--smoke", "0") == "1"
STAGGER_S = float(ARG.get("--stagger", 6.0))   # start daemons one at a time so each dials those
                                               # already up; simultaneous start forms the third
                                               # link only sometimes (docs/round2/topology_probe.json)
MESH_RETRIES = int(ARG.get("--mesh-retries", 3))
# Per-run data-directory namespace. A new series must never reuse or resume another series'
# per-run directories, so each series gets its own prefix.
NS = ARG.get("--ns", "")

# ---- pre-registered rate quotas (docs/round2/PREREGISTRATION.md section 4) ----
TOTAL_RATE = float(ARG.get("--rate", 45.0))
THIRD_FRACTION = 0.08
RATE_THIRD = TOTAL_RATE * THIRD_FRACTION
RATE_HONEST = (TOTAL_RATE - RATE_THIRD) / 2.0
RATE_TOL = 0.02            # CONTROL vs ATTACK must match within +/-2%
THIRD_SHARE_MAX = 0.085    # measured third-miner share of total attempts
SAMPLE_S = 15.0
# ---- preregistered branch-readability policy (OPERATIONAL_PREREGISTRATION.md section 9) ----
# Topology conformance has ZERO tolerance and is measured independently of the branch view. A
# branch view that cannot be READ is an evidence-coverage fact, not a topology fact: conflating
# the two made results/SMOKE_20260815_gateC4 report INVALID_TOPOLOGY_DRIFT for a run whose
# topology never drifted. All three limits below apply and the strictest governs.
BRANCH_MAX_UNREADABLE = COV.BRANCH_MAX_UNREADABLE
BRANCH_MIN_FRACTION = COV.BRANCH_MIN_FRACTION
BRANCH_MIN_SAMPLES = COV.BRANCH_MIN_SAMPLES
PARTITION_SAMPLES = 20     # 20 x 15 s = 300 s
RECOVERY_SAMPLES = 3
CENSOR_FRAC, CENSOR_MIN_BLOCKS = 0.95, 50
EQ_SUSTAIN = 20            # consecutive blocks inside the band
# Sample-coverage thresholds -- see docs/round2/OPERATIONAL_PREREGISTRATION.md.
# Fixed before the next measured run; not tunable from the command line.
# Single source of truth: the driver enforces exactly the constants the offline verifier enforces,
# so the two can never drift apart.
COV_MIN_FRACTION = COV.TOPO_MIN_FRACTION
COV_MIN_SAMPLES = COV.TOPO_MIN_SAMPLES
COV_MAX_NONCONFORMANT = COV.TOPO_MAX_NONCONFORMANT

NAMES = ["h1", "h2", "atk"]
HARNESS = ["node/symmetric_series.py", "node/sym_miner.py", "node/branch_evidence.py",
           "node/topology.py", "node/provenance.py", "node/live_median_boundary.py",
           "node/lowdiff_snapshot.py", "node/coverage.py", "node/evidence_verify.py",
           "node/series_validate.py", "node/replay_branches.py",
           # D: both offline checkers participate in the verdict and must travel with the
           # evidence. The bundle previously advertised an offline bundle checker it did not
           # contain, and hashed no copy of the sample verifier that decides the science.
           "node/sample_verify.py", "node/bundle_verify.py"]


STAGES = ["SETUP", "TOPOLOGY_PROVEN", "MINING_STARTED", "POST_STOP", "EVIDENCE_CAPTURE",
          "SEALED"]
# Only failures strictly BEFORE mining begins may be retried as the same condition.
PRE_MINING_STAGES = ("SETUP", "TOPOLOGY_PROVEN")


class StageError(RuntimeError):
    """Carries the stage at which an attempt failed, so the retry policy is decided by evidence
    rather than by which exception type happened to escape."""
    def __init__(self, stage, msg, partial=None):
        super().__init__(msg)
        self.stage = stage
        self.partial = partial or {}


def _write_interrupted(evid, series_id, cond, rep, attempt, aid, port, exc, prov):
    """Preserve the COMPLETE partial record of an interrupted attempt, not a terse stub."""
    partial = getattr(exc, "partial", None) or {}
    stage = getattr(exc, "stage", "UNKNOWN")
    ipath = os.path.join(evid, f"INTERRUPTED_{series_id}__{cond}_{rep}_a{attempt}.json")
    body = {"series_id": series_id, "condition": cond, "replicate": rep, "attempt": attempt,
            "attempt_id": aid, "port": port, "stage": stage,
            "status": "INTERRUPTED",
            "retryable_as_same_condition": stage in PRE_MINING_STAGES,
            "error": f"{type(exc).__name__}: {exc}",
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "NOT evidence. Preserved so an interrupted attempt is never silently lost.",
            "partial_record": partial}
    with open(ipath, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=1, default=str)
    prov.add_output(ipath, kind="interrupted_attempt")
    return ipath


class PhaseClock:
    """One immutable schedule shared by every miner and the sampler.

    Previously the driver recorded a boundary, then mutated each miner's `phase` string while those
    threads were dispatching, then snapshotted counters, and only afterwards stopped the attacker.
    Three things could go wrong: an attempt dispatched before the boundary could complete after the
    counter snapshot; an attempt dispatched during the mutation window could get the wrong phase;
    and the sampler's post label started earlier than the POST_S timer, so the labelled and timed
    post windows were different intervals. All three are removed by deriving phase from fixed
    timestamps and closing dispatch atomically.
    """
    def __init__(self, mining_start_mono, mine_seconds):
        self.mining_start_mono = mining_start_mono
        self.mining_end_mono = mining_start_mono + float(mine_seconds)
        self._closed = {}                 # miner name -> monotonic time dispatch was closed
        self._scheduled = {}              # miner name -> monotonic time dispatch MUST be closed
        self._post_start_mono = None
        # P0: the sealed experiment has TWO ends. Without a post end the window was open on the
        # right: a dispatch or a sample arbitrarily far after the run still classified as
        # post_stop. It is fixed once, when the post window opens, and never moves.
        self._post_end_mono = None
        self._lock = threading.Lock()

    def schedule_close(self, name, when):
        """Register a close time IN ADVANCE, so the gate is the fixed schedule.

        The driver's boundary wait polls on a 0.25 s tick, so close_dispatch() is necessarily
        called SOME time after the boundary and then backdates the closure to the boundary. That
        left a real window -- measured at 46.6 ms in results/SMOKE_20260815_gateC -- in which the
        third miner still passed may_dispatch() while the record claimed dispatch had closed
        exactly at the boundary. A scheduled close is enforced from the first instant, so no
        dispatch can occur at or after it no matter when the driver thread wakes up."""
        with self._lock:
            self._scheduled[name] = float(when)

    def close_dispatch(self, name, when=None):
        with self._lock:
            self._closed.setdefault(name, when if when is not None else time.monotonic())

    def may_dispatch(self, name, mono):
        with self._lock:
            sched = self._scheduled.get(name)
            c = self._closed.get(name)
        if sched is not None and mono >= sched:
            return False
        return c is None or mono < c

    def set_post_start(self, mono, post_seconds=None):
        """Open the post window and, with it, seal the end of the whole experiment."""
        with self._lock:
            if self._post_start_mono is not None:
                return                      # write-once: the sealed schedule never moves
            self._post_start_mono = mono
            if post_seconds is not None:
                self._post_end_mono = mono + float(post_seconds)

    @property
    def post_start_mono(self):
        return self._post_start_mono

    @property
    def post_end_mono(self):
        return self._post_end_mono

    def within_window(self, mono):
        """True only inside the sealed experiment [mining_start, post_end)."""
        if mono < self.mining_start_mono:
            return False
        pe = self._post_end_mono
        return pe is None or mono < pe

    def phase_of(self, mono):
        """before_start -> mining -> transition -> post_stop -> after_end, fixed boundaries only.

        The two outer names exist so nothing outside the sealed window can be silently absorbed
        into an inner phase."""
        if mono < self.mining_start_mono:
            return "before_start"
        if mono < self.mining_end_mono:
            return "mining"
        ps = self._post_start_mono
        if ps is None or mono < ps:
            return "transition"
        pe = self._post_end_mono
        if pe is not None and mono >= pe:
            return "after_end"
        return "post_stop"

    def export(self):
        return {"mining_start_mono": self.mining_start_mono,
                "mining_end_mono": self.mining_end_mono,
                # scheduled = enforced from the start; closed = when the driver actually recorded
                # it. They are reported separately so the evidence never implies the closure took
                # effect earlier than it did.
                "dispatch_scheduled_close_mono": dict(self._scheduled),
                "dispatch_closed_mono": dict(self._closed),
                "post_start_mono": self._post_start_mono,
                "post_end_mono": self._post_end_mono}


def finalize_series(raw_paths, results, evid, prov=None):
    """Run the offline verifiers on the AUTHORITATIVE raw files, retain their results in the
    bundle, and derive series validity from them.

    This exists because the driver previously called SV.validate(results) with no verifier results
    at all, so `series_validate` -- which requires a passing verifier per record -- emitted
    "no offline verifier result supplied" for every condition. A nine-condition series was
    therefore guaranteed invalid after ~3.4 hours. The console verdict, summary, manifest and exit
    code must all come from this one object, never from a later standalone CLI invocation.
    """
    import series_validate as SV
    # ONE implementation, shared with the standalone CLI, so the two can never diverge.
    vres, sres, merged_pre = SV.run_verifiers(raw_paths)
    vpath = os.path.join(evid, "verifier_results.json")
    with open(vpath, "w", encoding="utf-8") as f:
        json.dump({"producer_verifier": vres, "sample_verifier": sres}, f, indent=1, default=str)
    if prov is not None:
        prov.add_output(vpath, kind="verifier_results")
    merged = merged_pre
    validity = SV.validate(results, verifier_results=merged)
    validity["verifier_results_path"] = vpath
    return validity, vres, sres


def fresh_copy(name, allow_existing=False):
    dst = os.path.join(SNAPROOT, name)
    if os.path.isdir(dst):
        # a measured attempt never reuses or destroys an existing per-attempt directory
        if not allow_existing:
            raise StageError("SETUP", f"per-attempt data directory already exists: {dst}")
        shutil.rmtree(dst)
    r = subprocess.run(["cp", "-a", "--sparse=always", SRC, dst], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"snapshot copy failed: {r.stderr[:200]}")
    return dst


class Sampler(threading.Thread):
    """Periodic branch + adjacency samples. This is what PARTITION and RECOVERY are judged on."""
    def __init__(self, ds, nodes, start_h, stop, clock):
        super().__init__(daemon=True)
        self.ds, self.nodes, self.start_h, self.stop = ds, nodes, start_h, stop
        # C: the sampler owns NO boundary of its own. It previously held a mutable boundary_mono
        # that the driver assigned only after the attacker's last in-flight submit returned, so
        # every sample taken in that window was labelled `mining` even though nominal mining had
        # already ended -- inflating mining coverage with observations of a network whose attacker
        # had stopped. Phase now comes from the one sealed schedule.
        self.clock = clock
        self.samples = []
        self.overruns = []

    def phase_at(self, t_mono):
        """mining -> transition -> post_stop, from the single sealed schedule."""
        return self.clock.phase_of(t_mono)

    def run(self):
        # Fixed-rate schedule: the next slot is due SAMPLE_S after the PREVIOUS due time, not
        # SAMPLE_S after an arbitrarily long sample finished. Overruns are recorded rather than
        # silently stretching the cadence and inflating apparent coverage.
        next_due = time.monotonic()
        while not self.stop.is_set():
            slot_due = next_due
            next_due += SAMPLE_S
            t = time.time()
            t_mono = time.monotonic()
            # P0: never BEGIN a sample outside the sealed window. The driver's post timer wakes
            # on a poll, so the sampler can reach a slot a fraction after post end; such an
            # observation is outside the experiment and is dropped rather than recorded as
            # post_stop.
            if not self.clock.within_window(t_mono):
                break
            sample = {"phase": self.phase_at(t_mono), "t": t, "t_mono": t_mono,
                      "scheduled_mono": slot_due,
                      "late_by_s": round(t_mono - slot_due, 4)}
            # ---------- 1. TOPOLOGY, observed independently and FIRST ----------
            # Taken first so an unreadable chain can never cost us the topology measurement. A
            # topology RPC failure is fail-closed nonconformance (policy 1); a BRANCH failure is
            # never allowed to imply anything about topology.
            try:
                adj = T.snapshot(self.nodes)
                conf = T.conformance(adj, list(self.ds), TOPOLOGY)
                sample.update({
                    "topology_observed": True, "topology_error": None,
                    "topology_conformant": bool(conf["conformant"]),
                    "conformance": conf,
                    "links": adj["undirected_links"], "links_missing": conf["missing"],
                    "links_forbidden_present": conf["forbidden_present"],
                    "adjacency": adj["adjacency"], "raw_connection_rows": adj.get("raw_rows"),
                    "rpc_errors": adj.get("rpc_errors"), "unresolved": adj.get("unresolved"),
                    "conn_counts": adj["raw_connection_counts"]})
            except Exception as e:
                sample.update({
                    "topology_observed": False,
                    "topology_error": f"{type(e).__name__}: {e}",
                    # fail closed: a topology observation that could not be made is NOT conformant
                    "topology_conformant": False})
            # ---------- 2. BRANCH VIEW, observed independently ----------
            try:
                views = {n: BE.node_view(self.ds[n], self.start_h) for n in self.ds}
                fs = BE.fork_state(views)
                # P0-5: store enough per-sample evidence for an OFFLINE verifier to rederive
                # lag / common ancestor / genuine fork. When every tip agrees that is trivial, so
                # the full hash chain is stored only when the tips actually differ -- which is
                # exactly the case a partition claim depends on.
                tips_differ = len({v["tip"] for v in views.values()}) > 1
                branch_ev = {}
                for n, v in views.items():
                    e = {"height": v["height"], "tip": v["tip"],
                         "anchor_height": v.get("anchor_height"),
                         "anchor_hash": v.get("anchor_hash"),
                         "cum": v.get("tip_cumulative_difficulty"),
                         "chain_digest": hashlib.sha256(
                             "".join(v.get("anchored_hashes") or []).encode()).hexdigest(),
                         "chain_len": len(v.get("anchored_hashes") or [])}
                    if tips_differ:
                        e["anchored_hashes"] = v.get("anchored_hashes")
                    branch_ev[n] = e
                sample.update({
                    "branch_readable": True, "branch_error": None,
                    # real attempt count from node_view, not an assumed 1
                    "branch_attempts": max(v.get("attempts", 1) for v in views.values()),
                    "tips": {n: {"height": v["height"], "tip": v["tip"],
                                 "cum": v["tip_cumulative_difficulty"]} for n, v in views.items()},
                    "all_same_tip": len({v["tip"] for v in views.values()}) == 1,
                    "h1_h2_genuinely_forked": fs.get("h1|h2", {}).get("genuinely_forked"),
                    "branch_evidence": branch_ev, "tips_differ": tips_differ,
                    "h1_h2_common_ancestor": fs.get("h1|h2", {}).get("common_ancestor_height")})
            except Exception as e:
                # An unreadable branch view says NOTHING about the topology and NOTHING about
                # same-tip / lag / fork. Every branch verdict is left None so no downstream step
                # can read a missing observation as agreement.
                sample.update({
                    "branch_readable": False,
                    "branch_error": f"{type(e).__name__}: {e}",
                    "branch_attempts": getattr(e, "attempts", None),
                    "branch_retries": getattr(e, "retries", None),
                    "tips": None, "all_same_tip": None, "h1_h2_genuinely_forked": None,
                    "branch_evidence": None, "tips_differ": None,
                    "h1_h2_common_ancestor": None})
            self.samples.append(sample)
            over = time.monotonic() - next_due
            if over > 0:
                self.overruns.append({"scheduled_mono": slot_due, "over_by_s": round(over, 3)})
                next_due = time.monotonic()          # resynchronise after a missed deadline
            while time.monotonic() < next_due and not self.stop.is_set():
                time.sleep(min(0.5, max(0.0, next_due - time.monotonic())))


def _equilibrium(diffs, rate_per_s):
    """Pre-registered band: D* = measured cadence x 60 s target; band [D*/4, D*x4]; entered when
    difficulty stays inside it for 20 consecutive blocks. The formula was fixed in advance; the
    rate is measured, because what difficulty is achievable depends on the rate limiter."""
    if not rate_per_s or not diffs:
        return {"expected": None, "band": None, "entered_at_index": None, "entered": False}
    star = rate_per_s * 60.0
    lo, hi = star / 4.0, star * 4.0
    run = 0
    idx = None
    for i, d in enumerate(diffs):
        run = run + 1 if lo <= d <= hi else 0
        if run >= EQ_SUSTAIN:
            idx = i - EQ_SUSTAIN + 1
            break
    return {"expected": round(star, 1), "band": [round(lo, 1), round(hi, 1)],
            "sustain_blocks": EQ_SUSTAIN, "entered_at_index": idx, "entered": idx is not None}


def longest_true_run(samples, key):
    best = cur = 0
    for s in samples:
        cur = cur + 1 if s.get(key) else 0
        best = max(best, cur)
    return best


def record_status(conformant_throughout, sample_coverage_adequate, branch_coverage_adequate):
    """The single place that decides why a record is invalid.

    Order matters and is preregistered: a real topology failure invalidates the record even when
    branch coverage is fine, and an unreadable-chain problem is reported as what it is rather than
    being mislabelled as topology drift (results/SMOKE_20260815_gateC4).
    """
    if not conformant_throughout:
        return "INVALID_TOPOLOGY_DRIFT"
    if not sample_coverage_adequate:
        return "INVALID_SAMPLE_COVERAGE"
    if not branch_coverage_adequate:
        return "INVALID_BRANCH_EVIDENCE_COVERAGE"
    return "OK"


def longest_true_run_readable(samples, key):
    """Longest consecutive run of `key` over BRANCH-READABLE samples only.

    Unreadable samples are not skipped -- they remain in the ordered sequence and reset the run.
    Skipping them would splice two separated intervals into one apparent streak and could
    manufacture a PARTITION that never happened.
    """
    import coverage as _COV
    best = cur = 0
    for s in samples:
        # A transition sample belongs to neither phase and is not evidence of a sustained
        # condition, so like an unread sample it RESETS the run rather than extending or
        # bridging it.
        if s.get("phase") not in _COV.COVERAGE_PHASES or not _COV.branch_readable(s):
            cur = 0
            continue
        cur = cur + 1 if s.get(key) else 0
        best = max(best, cur)
    return best


def run_condition(cond, rep, port, gts, prov, attempt=1, evid_dir=".", raw_dir=None,
                  blob_dir=None, series_id="series"):
    third = (cond != "none")
    adaptive = (cond == "attack")
    p2p = {n: port + 10 * i for i, n in enumerate(NAMES)}
    rpcp = {n: p2p[n] + 1 for n in NAMES}
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    # every attempt gets its own data directories and its own evidence sub-directory, so an
    # interrupted attempt is preserved instead of being overwritten by its own retry
    aid = f"{NS}{cond}{rep}_a{attempt}"
    dirs = {n: fresh_copy(f"r2_{aid}_{n}", allow_existing=SMOKE) for n in NAMES}
    # The snapshot carries a persisted p2p state directory from the port it was built on. It is
    # keyed by port so a new daemon would not load it, but it is removed anyway so no copied peer
    # state can influence adjacency, and the removal is recorded rather than assumed harmless.
    removed_p2p = []
    for n in NAMES:
        tn = os.path.join(dirs[n], "testnet")
        if os.path.isdir(tn):
            for sub in os.listdir(tn):
                q = os.path.join(tn, sub, "p2pstate.bin")
                if os.path.exists(q):
                    os.remove(q)
                    removed_p2p.append(q)
    # P0-3: everything cleanup touches is initialised BEFORE the try, so a failure inside the very
    # first daemon constructor cannot raise UnboundLocalError in `finally` and mask the real error.
    ds, stop_all = {}, threading.Event()
    stop_third = threading.Event()
    miners, samp, clock = {}, None, None
    run_label = f"{cond}#{rep}#a{attempt}"
    daemons_expected = len(NAMES)
    cleanup_errors = []
    stage = {"now": "SETUP", "history": []}

    def enter(name):
        stage["now"] = name
        stage["history"].append({"stage": name, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                     time.gmtime()),
                                 "mono": time.monotonic()})
        rec["stage"] = name
        rec["stage_history"] = stage["history"]
    # P0-1: identity lives on the RECORD, not only on the event rows. A successful record
    # previously carried no series_id/triplet_id at all, so "exactly one series identity" could
    # never actually be enforced.
    rec = {"series_id": series_id, "condition": cond, "replicate": rep, "attempt": attempt,
           "attempt_id": aid,
           "triplet_id": f"{series_id}#rep{rep}",
           "matched_replicate_id": f"{series_id}#rep{rep}",
           "topology": TOPOLOGY,
           "adaptive_third_miner": adaptive,
           "third_miner_mode": (MODE_ADAPTIVE if adaptive else MODE_CONTROL_SHAM) if third
                               else None,
           "configured_rates": {"total": TOTAL_RATE, "third": RATE_THIRD, "honest": RATE_HONEST},
           "mine_seconds": MINE_S, "post_seconds": POST_S,
           # the offline verifier needs the cadence to recompute coverage independently
           "sample_seconds": SAMPLE_S}
    try:
        # Peer configuration must MATCH the requested topology. Previously every node was given
        # both other nodes as exclusive peers regardless of --topology, so a "star" run would have
        # configured, formed and then reported a full mesh.
        cfg_peers = {n: [o for o in NAMES if o != n] for n in NAMES}
        if TOPOLOGY == "star":
            hub = NAMES[0]
            cfg_peers = {hub: [o for o in NAMES if o != hub]}
            for o in NAMES:
                if o != hub:
                    cfg_peers[o] = [hub]          # spokes know only the hub, never each other
        rec["configured_peers"] = cfg_peers
        for n in NAMES:
            extra = []
            for o in cfg_peers[n]:
                extra += ["--add-exclusive-node", f"127.0.0.1:{p2p[o]}"]
            ds[n] = L.Daemon(f"r2_{aid}_{n}", p2p[n], rpcp[n], fixed_diff=0, offline=False,
                             extra=extra, wipe=False, data_dir=dirs[n])
            if STAGGER_S:
                time.sleep(STAGGER_S)
        rec["removed_copied_p2pstate"] = removed_p2p
        rec["stagger_seconds"] = STAGGER_S
        rec["data_dir_namespace"] = NS
        rec["data_dirs"] = dirs
        prov.add_run(run_label, {n: ds[n].argv for n in NAMES},
                     extra={"attempt_id": aid, "attempt": attempt, "replicate": rep,
                            "condition": cond,
                            # must be the SAME value the record carries; it was TOPOLOGY#rep here
                            # and series_id#rep on the record, i.e. one field with two meanings
                            "matched_replicate_id": f"{series_id}#rep{rep}",
                            "triplet_id": f"{series_id}#rep{rep}", "series_id": series_id,
                            "ports": p2p, "rpc_ports": rpcp, "data_dirs": dirs,
                            "topology": TOPOLOGY, "namespace": NS,
                            "configured_peers": cfg_peers,
                            "removed_copied_p2pstate": removed_p2p,
                            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        for n in NAMES:
            if not ds[n].wait_synced(90):
                # a sync timeout is a pre-mining SETUP failure, not a silent pass
                raise StageError("SETUP", f"{n} did not report synchronized within 90 s",
                                 partial=dict(rec))

        # ---------- identical start state ----------
        start = {}
        for n in NAMES:
            i = ds[n].info()
            g = rpc(ds[n].rpc, "get_block_header_by_height",
                    {"height": 0})["result"]["block_header"]
            th = rpc(ds[n].rpc, "get_block_header_by_height",
                     {"height": i["height"] - 1})["result"]["block_header"]
            start[n] = {"genesis_hash": g["hash"], "height": int(i["height"]),
                        "tip_hash": i["top_block_hash"], "tip_difficulty": int(th["difficulty"]),
                        "cumulative_difficulty": int(th.get("cumulative_difficulty", 0))}
        rec["start_state"] = start
        keys = ("genesis_hash", "height", "tip_hash", "tip_difficulty", "cumulative_difficulty")
        rec["start_identical"] = all(len({start[n][k] for n in NAMES}) == 1 for k in keys)
        if not rec["start_identical"]:
            raise StageError("SETUP", "start states differ across nodes", partial=dict(rec))
        start_h = start["h1"]["height"]

        # ---------- PROVE topology before mining ----------
        nodes = {n: (rpcp[n], p2p[n]) for n in NAMES}
        ok, snap, hist = T.wait_for(nodes, TOPOLOGY, timeout=150, poll=3.0)
        rec["topology_before_mining"] = {
            "established": ok, "required": snap.get("required_links"),
            "forbidden": snap.get("forbidden_links"),
            "links": snap["undirected_links"], "missing": snap.get("missing_links"),
            "forbidden_present": snap.get("forbidden_present"),
            "conformance": snap.get("conformance"),
            "adjacency": snap["adjacency"],
            "peer_id_map": snap["peer_id_map"], "unresolved": snap["unresolved"],
            "history": hist}
        if not ok:
            rec["status"] = "FAILED_TOPOLOGY"
            raise StageError("SETUP", 
                f"{TOPOLOGY} not conformant: missing={snap.get('missing_links')} "
                f"forbidden_present={snap.get('forbidden_present')}", partial=dict(rec))
        enter("TOPOLOGY_PROVEN")

        for n in NAMES:
            ds[n].mark_log()

        # ---------- mining phase ----------
        # C: ONE phase schedule. It is constructed and its boundaries fixed BEFORE the sampler
        # starts, and the same object is handed to the sampler and to every miner, so a sample and
        # an attempt taken at the same instant can never disagree about which phase they were in.
        t0, t0_mono = time.time(), time.monotonic()
        clock = PhaseClock(t0_mono, MINE_S)
        samp = Sampler(ds, nodes, start_h, stop_all, clock)
        samp.start()
        # F: every event echoes the COMPLETE required identity set, so the record<->event
        # cross-check has something to compare for every field rather than only three of seven.
        identity = {"series_id": series_id, "condition": cond, "replicate": rep,
                    "attempt_id": aid, "triplet_id": f"{series_id}#rep{rep}",
                    "matched_replicate_id": f"{series_id}#rep{rep}", "topology": TOPOLOGY}
        # The third miner's mode differs between the arms, but its PATH does not: control_sham and
        # adaptive both read the timestamp window and compute the adaptive candidate, and only the
        # decision to apply or discard it differs. Passing a bare bool here is rejected by
        # SymMiner, so the CONTROL arm cannot silently revert to the shorter honest path.
        third_mode = MODE_ADAPTIVE if adaptive else MODE_CONTROL_SHAM
        miners = {"h1": SymMiner("h1", ds["h1"], RATE_HONEST, MODE_HONEST, stop_all,
                                 nonce_salt=1 << 20, identity=identity, clock=clock),
                  "h2": SymMiner("h2", ds["h2"], RATE_HONEST, MODE_HONEST, stop_all,
                                 nonce_salt=2 << 20, identity=identity, clock=clock)}
        if third:
            miners["atk"] = SymMiner("atk", ds["atk"], RATE_THIRD, third_mode, stop_third,
                                     nonce_salt=3 << 20, identity=identity, clock=clock)
        enter("MINING_STARTED")
        # the schedule was sealed above, before the sampler started; it is never re-stamped here
        # P0-4: the third miner's dispatch window is bounded by the SCHEDULE, registered before
        # any miner thread starts. Relying on the driver to call close_dispatch() at the boundary
        # cannot work: that thread wakes on a 0.25 s poll, so it always closes late and backdates.
        if third:
            clock.schedule_close("atk", clock.mining_end_mono)
        rec["phase_boundaries"] = {"mining_start_wall": t0, "mining_start_mono": t0_mono,
                                   "nominal_mining_end_mono": clock.mining_end_mono}
        for m in miners.values():
            m.start()
        while time.monotonic() < clock.mining_end_mono:
            time.sleep(0.25)
        # ---------- post-stop observation: third miner off, honest miners keep mining ----------
        # snapshot attempt counters at the instant the third miner stops. The honest miners keep
        # mining for POST_S afterwards, so a share computed over the whole run would understate the
        # third miner by roughly POST_S/(MINE_S+POST_S). Shares are reported for the mining phase.
        # P0-4: close attacker dispatch ATOMICALLY at the fixed boundary, let any pre-boundary
        # submission finish, join it, and only then declare post-stop. Counters are never
        # snapshotted here -- they are derived from the final serialized events after quiescence.
        boundary_mono, boundary_wall = clock.mining_end_mono, time.time()
        if third:
            clock.close_dispatch("atk", boundary_mono)
        rec["phase_boundaries"].update({"boundary_wall": boundary_wall,
                                        "boundary_mono": boundary_mono})
        enter("POST_STOP")
        for _m in miners.values():
            _m.stop_requested = True
        stop_third.set()
        if third:
            # bound must exceed the longest submit_block timeout (120 s) or a miner can still be
            # mutating its own evidence while capture begins
            miners["atk"].join(timeout=150)
            if miners["atk"].is_alive():
                raise StageError("POST_STOP", "third miner still alive after 150 s join",
                                 partial=dict(rec))
        # post window is timed from PROVEN attacker quiescence, and the sampler uses the same
        # instant, so the labelled and timed post intervals are one interval
        post_start_mono = time.monotonic()
        # P0: sealing the post window also seals the end of the experiment, and the honest miners
        # get an EXACT scheduled close there. Previously only the attacker had a scheduled close
        # (at mining end); h1/h2 ran until the driver's 0.5 s post-timer poll set stop_all, which
        # left a real race in which a dispatch could begin after the window had closed. Gate G
        # contains three such dispatches (h1 x2, latest +0.065486 s; h2 x1, +0.045987 s).
        clock.set_post_start(post_start_mono, POST_S)
        for _n in ("h1", "h2"):
            clock.schedule_close(_n, clock.post_end_mono)
        rec["phase_boundaries"].update({
            "attacker_quiesced_mono": post_start_mono,
            "post_start_mono": post_start_mono,
            "post_end_mono": clock.post_end_mono,
            "transition_latency_s": round(post_start_mono - boundary_mono, 4),
            "actual_mining_interval_s": round(boundary_mono - t0_mono, 4)})
        post_mark = time.time()
        _post_start_mono = post_start_mono
        for s in samp.samples:
            s.setdefault("phase", "mining")
        samp.phase = "post_stop"
        while time.monotonic() - _post_start_mono < POST_S:
            time.sleep(0.5)
        stop_all.set()
        alive = []
        for n, m in miners.items():
            m.join(timeout=150)
            if m.is_alive():
                alive.append(f"miner:{n}")
        samp.join(timeout=150)
        if samp.is_alive():
            alive.append("sampler")
        unhealthy = [n for n, m in miners.items() if not m.healthy()]
        rec["miner_health"] = {n: {"healthy": m.healthy(), "end_reason": m.end_reason,
                                   "fatal_error": m.fatal_error, "attempts": m.attempts,
                                   "events": len(m.events)} for n, m in miners.items()}
        # a joined-but-crashed miner is NOT quiescent in any useful sense
        rec["threads_quiescent"] = bool(not alive and not unhealthy)
        if unhealthy:
            alive += [f"unhealthy:{n}" for n in unhealthy]
        if alive:
            # never serialise evidence a live thread can still mutate
            raise StageError("EVIDENCE_CAPTURE", f"threads still alive after join: {alive}",
                             partial=dict(rec))
        enter("EVIDENCE_CAPTURE")

        rec["miner_stats"] = {n: m.stats() for n, m in miners.items()}
        tot = sum(m.attempts for m in miners.values())
        rec["achieved_total_attempts"] = tot
        rec["achieved_third_share_of_attempts"] = (round(miners["atk"].attempts / tot, 5)
                                                   if third and tot else 0.0)
        # P0-4: counters come ONLY from the final serialized events, after thread quiescence.
        ev_mining = {n: sum(1 for e in m.events if e["phase"] == "mining")
                     for n, m in miners.items()}
        mining_attempts = dict(ev_mining)
        rec["mining_attempts_from_events"] = ev_mining
        rec["mining_attempts_counter_agrees"] = True
        rec["phase_clock"] = clock.export()
        rec["attempts_by_phase"] = {n: {ph: sum(1 for e in m.events if e["phase"] == ph)
                                        for ph in ("mining", "transition", "post_stop")}
                                    for n, m in miners.items()}
        mtot = sum(mining_attempts.values())
        rec["mining_phase_attempts"] = mining_attempts
        rec["mining_phase_total_attempts"] = mtot
        _mine_actual = rec["phase_boundaries"].get("actual_mining_interval_s") or MINE_S
        rec["mine_seconds"] = MINE_S
        rec["mine_seconds_actual"] = _mine_actual
        rec["mining_phase_rate_per_s"] = round(mtot / _mine_actual, 4) if _mine_actual else None
        rec["mining_phase_third_share"] = (round(mining_attempts["atk"] / mtot, 5)
                                           if third and mtot else 0.0)
        rec["mining_phase_rate_by_miner"] = {n: round(a / _mine_actual, 4)
                                             for n, a in mining_attempts.items()}
        # console convenience flag only -- series_validate decides the real gate from exact
        # integer counts. Computed from the UNROUNDED fraction so the printed line cannot
        # disagree with the authoritative verdict at the boundary.
        rec["third_share_within_prereg_cap"] = (
            (mining_attempts["atk"] / mtot) <= THIRD_SHARE_MAX if (third and mtot) else True)
        rec["samples"] = samp.samples

        # ---------- branch-aware evidence, per node ----------
        views = {n: BE.node_view(ds[n], start_h) for n in NAMES}
        logs = {n: ds[n].new_log() for n in NAMES}
        parsed = {n: BE.parse_log(logs[n]) for n in NAMES}
        rec["log_summary"] = {n: {"lines": parsed[n]["log_lines"],
                                  "found_block_lines": len(parsed[n]["found"]),
                                  "reorg_log_heights": parsed[n]["reorg_heights"],
                                  "reject_reason_counts":
                                      BE.reject_summary(parsed[n]["rejects_by_hash"]),
                                  "blocks_with_a_rejection": len(parsed[n]["rejects_by_hash"])}
                              for n in NAMES}
        # ---- producer attribution from EXACT daemon-returned block_id values ----
        # Every miner's full candidate record is serialised, so this mapping and everything derived
        # from it can be recomputed offline by node/evidence_verify.py.
        producer_of = {}
        collisions = []
        for n, m in miners.items():
            for h in m.hashes:
                if h in producer_of and producer_of[h] != n:
                    collisions.append({"block_id": h, "claimed_by": [producer_of[h], n]})
                producer_of[h] = n
        rec["miner_evidence"] = {n: m.evidence() for n, m in miners.items()}
        rec["producer_of"] = producer_of
        rec["producer_id_collisions"] = collisions
        rec["ambiguous_accepted_count"] = sum(len(m.ambiguous) for m in miners.values())
        rec["unknown_outcome_count"] = sum(len(m.unknown) for m in miners.values())
        rec["attribution_exact"] = (rec["ambiguous_accepted_count"] == 0 and
                                    rec["unknown_outcome_count"] == 0 and not collisions)
        rec["attribution"] = {
            "method": "exact block_id returned by the daemon's submit_block response "
                      "(res.block_id, computed from the submitted blob by "
                      "parse_and_validate_block_from_blob); never inferred from a height lookup",
            "recorded_block_ids": {n: len(m.hashes) for n, m in miners.items()},
            "exact": rec["attribution_exact"],
            "note": "a nonzero ambiguous or unknown count invalidates producer-level conclusions "
                    "for this condition, per the operational pre-registration"}

        all_hashes = set(producer_of)
        for n in NAMES:
            all_hashes |= set(views[n]["canonical_hashes"]) | set(views[n]["alt_block_hashes"])
        rec["canonical_headers"] = {n: views[n]["canonical"] for n in NAMES}
        rec["per_node"] = {}
        for n in NAMES:
            v = views[n]
            occ = BE.rolling_window_occupancy(v["canonical"], producer_of)
            work, blocks = {}, {}
            for b in v["canonical"]:
                p = producer_of.get(b["hash"], "unattributed")
                work[p] = work.get(p, 0) + b["difficulty"]
                blocks[p] = blocks.get(p, 0) + 1
            totw = sum(work.values()) or 1
            diffs = [b["difficulty"] for b in v["canonical"]]
            rec["per_node"][n] = {
                "height": v["height"], "tip": v["tip"],
                "tip_cumulative_difficulty": v["tip_cumulative_difficulty"],
                "canonical_blocks_after_start": len(v["canonical"]),
                "alt_block_count": len(v["alt_block_hashes"]),
                "accepted_work": {p: {"blocks": blocks.get(p, 0), "work": w,
                                      "work_share": round(w / totw, 5)}
                                  for p, w in work.items()},
                "difficulty": {"min": min(diffs) if diffs else None,
                               "max": max(diffs) if diffs else None,
                               "median": int(statistics.median(diffs)) if diffs else None,
                               "blocks_le10": sum(1 for d in diffs if d <= 10)},
                "max_window_occupancy": {p: BE.max_occupancy(occ, p)
                                         for p in ("h1", "h2", "atk", "unattributed")},
                "max_window_ts_span_s": max([w["ts_span_s"] for w in occ] or [0]),
                "equilibrium": _equilibrium(diffs, rec.get("mining_phase_rate_per_s")),
            }
        rec["fork_state_final"] = BE.fork_state(views)
        # raw blobs for every canonical and known alternative block, keyed by exact block id, so a
        # partition can actually be replayed later instead of only described
        arch = os.path.join(blob_dir or evid_dir, f"blobs_{aid}.jsonl")
        rec["blob_archive"] = BE.blob_archive(ds, all_hashes, arch)
        # provenance failures are never swallowed
        prov.add_output(arch, kind="blob_archive")
        if rec["blob_archive"].get("missing_count"):
            rec["blob_archive_complete"] = False
            raise StageError("EVIDENCE_CAPTURE",
                             f"blob archive incomplete: {rec['blob_archive']['missing_count']} of "
                             f"{rec['blob_archive']['requested']} block ids absent",
                             partial=dict(rec))
        rec["blob_archive_complete"] = True
        rec["block_state_by_node"] = {n: BE.classify(ds[n], sorted(all_hashes), views[n])
                                      for n in NAMES}

        # ---------- pre-registered verdicts ----------
        # branch-derived quantities may only use samples whose branch view was READ
        mining_s = [s for s in rec["samples"]
                    if s.get("phase") == "mining" and COV.branch_readable(s)]
        post_s = [s for s in rec["samples"]
                  if s.get("phase") == "post_stop" and COV.branch_readable(s)]
        cov = COV.evaluate(rec["samples"], MINE_S, POST_S, SAMPLE_S,
                           COV_MIN_FRACTION, COV_MIN_SAMPLES, COV_MAX_NONCONFORMANT)
        rec["sample_coverage"] = cov
        # Independent branch-readability accounting. An unreadable chain read is an evidence gap,
        # never a topology verdict -- results/SMOKE_20260815_gateC4 was invalidated as
        # INVALID_TOPOLOGY_DRIFT for a run whose topology never drifted.
        bcov = COV.branch_evaluate(rec["samples"], MINE_S, POST_S, SAMPLE_S,
                                   BRANCH_MAX_UNREADABLE, BRANCH_MIN_FRACTION,
                                   BRANCH_MIN_SAMPLES)
        rec["branch_coverage"] = bcov
        # topology_conformant_throughout is the FULL conformance predicate over the FULL sample
        # sequence -- an RPC error or an unresolved peer breaks it, exactly as conformance() says.
        # The previous version looked only at missing/forbidden links on non-error samples, so it
        # could report True for a run in which conformance was actually false.
        all_samples = rec["samples"]
        # Computed only over samples where the topology observation was ATTEMPTED, and a failed
        # observation is fail-closed nonconformant (policy 1). A branch_error contributes nothing
        # here: topology failure is never inferred from an unreadable chain.
        topo_obs = [s for s in all_samples if COV.topology_observed(s)]
        conformant_throughout = bool(topo_obs) and all(
            s.get("topology_conformant") for s in topo_obs) and len(topo_obs) == len(all_samples)
        sampled = [s for s in all_samples if "links" in s and COV.topology_observed(s)]
        links_ok = bool(sampled) and all(not s.get("links_missing") for s in sampled)
        no_forbidden = bool(sampled) and all(not s.get("links_forbidden_present") for s in sampled)
        rec["topology_violations"] = {
            "samples_with_missing_required": [
                {"t": s["t"], "missing": s["links_missing"]} for s in all_samples
                if s.get("links_missing")],
            "samples_with_forbidden_edge": [
                {"t": s["t"], "forbidden": s["links_forbidden_present"]} for s in all_samples
                if s.get("links_forbidden_present")],
            "samples_non_conformant": [
                {"t": s.get("t"), "reasons": (s.get("conformance") or {}).get(
                    "non_conformance_reasons"), "topology_error": s.get("topology_error")}
                for s in all_samples if not s.get("topology_conformant")],
            "sampler_overruns": getattr(samp, "overruns", [])}
        # kept separate from topology on purpose: these are unread chains, not broken links
        rec["branch_read_failures"] = [
            {"t": s.get("t"), "phase": s.get("phase"), "error": s.get("branch_error"),
             "attempts": s.get("branch_attempts"), "retries": s.get("branch_retries")}
            for s in all_samples if not COV.branch_readable(s)]
        # An unreadable sample stays in the ordered sequence and RESETS the streak: it can hide a
        # very short event, but it can never manufacture one.
        run_fork = longest_true_run_readable(rec["samples"], "h1_h2_genuinely_forked")
        rec["verdicts"] = {
            "links_up_throughout": links_ok,
            "no_forbidden_link_throughout": no_forbidden,
            "topology_conformant_throughout": conformant_throughout,
            "links_only_ok_legacy": bool(links_ok and no_forbidden),
            "longest_h1_h2_fork_run_samples": run_fork,
            "longest_h1_h2_fork_run_seconds": round(run_fork * SAMPLE_S, 1),
            "sample_coverage_adequate": cov["adequate"],
            "branch_coverage_adequate": bcov["adequate"],
            "PARTITION": bool(conformant_throughout and cov["adequate"] and bcov["adequate"] and
                              run_fork >= PARTITION_SAMPLES),
            "partition_definition": f"links verified up AND h1/h2 genuinely forked for "
                                    f">={PARTITION_SAMPLES} consecutive {SAMPLE_S}s samples",
        }
        # P0-5: recovery is judged over the FULL ordered post sequence -- an error or
        # non-conformant sample breaks consecutiveness -- and the reported time is the start of the
        # first QUALIFYING three-sample run, not the first isolated same-tip sample.
        post_all = [s for s in rec["samples"] if s.get("phase") == "post_stop"]
        run = 0
        first_idx = None
        for i, s_ in enumerate(post_all):
            # all three must be positively observed; an unreadable branch view is not agreement
            ok = (COV.topology_observed(s_) and COV.branch_readable(s_)
                  and s_.get("topology_conformant") and s_.get("all_same_tip") is True)
            if ok:
                if run == 0:
                    start_i = i
                run += 1
                if run >= RECOVERY_SAMPLES and first_idx is None:
                    first_idx = start_i
            else:
                run = 0
        rec["verdicts"]["RECOVERY"] = first_idx is not None
        rec["verdicts"]["recovery_first_qualifying_index"] = first_idx
        rec["verdicts"]["recovery_first_sample_t"] = (
            round(post_all[first_idx].get("t_mono", 0) - _post_start_mono, 1)
            if first_idx is not None else None)
        cens = {}
        for p, m in miners.items():
            produced = len(m.hashes)
            per_obs = {}
            for n in NAMES:
                canon = set(views[n]["canonical_hashes"])
                absent = len([h for h in m.hashes if h not in canon])
                per_obs[n] = {"produced": produced, "absent_from_canonical": absent,
                              "absent_fraction": round(absent / produced, 4) if produced else None,
                              "censored_at_this_node": bool(produced >= CENSOR_MIN_BLOCKS and
                                                            produced and
                                                            absent / produced >= CENSOR_FRAC)}
            cens[p] = {"per_observer": per_obs,
                       "network_level_censored": all(v["censored_at_this_node"]
                                                     for k, v in per_obs.items() if k != p)}
        rec["censorship"] = cens
        # a run whose topology drifted, or whose sampling did not cover the run, is not evidence
        # A topology failure invalidates the record even when branch coverage is fine, and an
        # inadequate branch coverage is reported as what it is instead of being mislabelled drift.
        rec["status"] = record_status(conformant_throughout, cov["adequate"], bcov["adequate"])
        if rec["status"] == "OK":
            enter("SEALED")
    finally:
        # ORDER MATTERS: stop miners and samplers, shut the daemons down and confirm they exited,
        # and only then copy the logs. Copying while a daemon is still writing yields a truncated
        # log that nothing downstream can detect.
        # P0-3: on EVERY path -- success or exception -- close dispatch, join every created
        # thread, then stop daemons, then capture logs. The exceptional path previously set stop
        # events and went straight to stopping daemons and copying logs while workers could still
        # be inside a 120 s RPC.
        stop_third.set()
        stop_all.set()
        if clock is not None:
            for n in list(miners):
                clock.close_dispatch(n)
        joined = {}
        for n, m in miners.items():
            try:
                if m.is_alive():
                    m.join(timeout=150)
                joined[n] = {"alive_after_join": m.is_alive(), "end_reason": m.end_reason,
                             "fatal_error": m.fatal_error, "events": len(m.events),
                             "attempts": m.attempts}
            except Exception as e:
                cleanup_errors.append(f"join miner {n}: {type(e).__name__}: {e}")
        if samp is not None:
            try:
                samp.stop.set()
                if samp.is_alive():
                    samp.join(timeout=150)
                joined["sampler"] = {"alive_after_join": samp.is_alive(),
                                     "samples": len(samp.samples)}
            except Exception as e:
                cleanup_errors.append(f"join sampler: {type(e).__name__}: {e}")
        rec["thread_cleanup"] = joined
        stop_records = {}
        for n in reversed(NAMES):
            if n in ds:
                try:
                    ds[n].stop(clean_wait=20.0)
                except Exception as e:
                    stop_records[n] = {"error": f"{type(e).__name__}: {e}"}
                    cleanup_errors.append(f"stop daemon {n}: {type(e).__name__}: {e}")
                else:
                    stop_records[n] = ds[n].stop_record()
        rec["daemon_stop"] = stop_records
        # zero started daemons must NEVER read as "all exited" -- all([]) is True
        rec["daemon_counts"] = {"expected": daemons_expected, "started": len(ds),
                                "stop_records": len(stop_records),
                                "exited": sum(1 for v in stop_records.values()
                                              if v.get("exited"))}
        rec["all_daemons_exited"] = bool(
            len(ds) == daemons_expected and stop_records and
            all(v.get("exited") for v in stop_records.values()))
        try:
            rec["log_capture"] = prov.copy_logs(
                {f"{aid}_{n}": dirs[n] for n in NAMES if n in dirs},
                subdir=f"logs_{aid}", require_all=True)
        except Exception as e:
            # provenance failures are never swallowed: they invalidate the attempt
            rec["log_capture"] = {"all_present": False,
                                  "error": f"{type(e).__name__}: {e}"}
            rec["status"] = "INVALID_LOG_CAPTURE"
            cleanup_errors.append(f"log capture: {type(e).__name__}: {e}")
        rec["rpc_metrics"] = L.METRICS.export()
        rec["cleanup_errors"] = cleanup_errors
        # P0-3: every StageError carried partial=dict(rec) SNAPSHOTTED BEFORE this cleanup block,
        # so the preserved interrupted-attempt file contained no thread_cleanup, no daemon_stop,
        # no all_daemons_exited and no log_capture -- precisely the facts needed to judge whether
        # the failed attempt shut down cleanly. Rebind the partial to the post-cleanup record.
        _inflight = sys.exc_info()[1]
        if _inflight is not None:
            try:
                # ANY exception, not only StageError: a failure in a daemon constructor previously
                # produced an interrupted-attempt file with an EMPTY partial record, so the one
                # question that matters afterwards -- did this failed attempt leave three daemons
                # running? -- had no answer in the evidence.
                _inflight.partial = dict(rec)
            except Exception:
                pass
        prov.update_run(run_label, daemon_stop=stop_records,
                        log_capture=rec.get("log_capture"),
                        rpc_metrics=rec["rpc_metrics"],
                        stage_history=stage["history"],
                        ended_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        final_status=rec.get("status"))
    return rec


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    # ---- series identity, immutable evidence layout, fail-if-exists ----
    series_id = SERIES or (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) +
                           f"__r2-symmetric-{TOPOLOGY}")
    evid = EVID or os.path.join(REPO, "results", series_id)
    if not SMOKE:
        if not NS:
            print("REFUSING: a measured run requires a nonempty --ns namespace", flush=True)
            return 2
        if os.path.exists(evid) and os.listdir(evid):
            print(f"REFUSING: evidence directory already exists and is not empty: {evid}\n"
                  f"          measured output is immutable; choose a new --series/--evidence",
                  flush=True)
            return 2
        # every per-attempt data directory must be free before anything is started
        clash = []
        for rep in range(1, REPS + 1):
            for cond in CONDS:
                for att in range(1, MESH_RETRIES + 1):
                    for n in NAMES:
                        q = os.path.join(SNAPROOT, f"r2_{NS}{cond}{rep}_a{att}_{n}")
                        if os.path.exists(q):
                            clash.append(q)
        if clash:
            print(f"REFUSING: {len(clash)} per-attempt data directories already exist, e.g. "
                  f"{clash[:3]}\n          choose a new --ns namespace", flush=True)
            return 2
    os.makedirs(evid, exist_ok=True)
    RAW = os.path.join(evid, "raw")
    BLOBS = os.path.join(evid, "blobs")
    for sub in (RAW, BLOBS):
        os.makedirs(sub, exist_ok=True)
    L.DAEMON = BIN
    prov = Provenance(evid, harness=HARNESS, binary=BIN, driver_argv=sys.argv)
    prov.add_node_source_bundle()
    prov.m["resolved_config"] = {
        "series_id": series_id, "topology": TOPOLOGY, "conditions": CONDS, "replicates": REPS,
        "namespace": NS, "port_base": PORT0, "mine_seconds": MINE_S, "post_seconds": POST_S,
        "sample_seconds": SAMPLE_S, "total_rate": TOTAL_RATE, "third_fraction": THIRD_FRACTION,
        "rate_third": RATE_THIRD, "rate_honest": RATE_HONEST, "rate_tolerance": RATE_TOL,
        "third_share_cap": THIRD_SHARE_MAX, "partition_samples": PARTITION_SAMPLES,
        "recovery_samples": RECOVERY_SAMPLES, "eq_sustain": EQ_SUSTAIN,
        "coverage_min_fraction": COV_MIN_FRACTION, "coverage_min_samples": COV_MIN_SAMPLES,
        "coverage_max_nonconformant": COV_MAX_NONCONFORMANT,
        "censor_frac": CENSOR_FRAC, "censor_min_blocks": CENSOR_MIN_BLOCKS,
        "snapshot_root": SNAPROOT, "snapshot_src": SRC, "stagger_seconds": STAGGER_S,
        "setup_retry_limit": MESH_RETRIES, "evidence_dir": evid, "raw_dir": RAW,
        "blobs_dir": BLOBS, "outdir_legacy_unused": OUTDIR, "smoke": SMOKE,
        "binary": BIN,
        "branch_max_unreadable": BRANCH_MAX_UNREADABLE,
        "branch_min_readable_fraction": BRANCH_MIN_FRACTION,
        "branch_min_readable_samples": BRANCH_MIN_SAMPLES}
    # P1: the preregistrations and the harness itself are COPIED INTO the bundle, so the bundle
    # can be verified from its own contents on another machine instead of pointing checksums at
    # live repository paths that may change afterwards.
    prov.copy_inputs(["docs/round2/OPERATIONAL_PREREGISTRATION.md",
                      "docs/round2/PREREGISTRATION.md"], dest_subdir="inputs", kind="prereg")
    prov.copy_inputs(HARNESS, dest_subdir="inputs/harness", kind="harness_copy")
    prov._write()
    snap_all = json.load(open(os.path.join("docs", "lowdiff", "snapshot.json")))
    snap = dict(snap_all["identical_start_state"]["h1"])
    gts = snap_all["snapshot_build"]["genesis_ts"]
    prov.add_snapshot(SRC, os.path.join(REPO, "docs/lowdiff/snapshot.json"), chain=snap)

    # A measured run must start from a committed harness. --smoke=1 bypasses the gate for harness
    # debugging only and stamps the manifest so a smoke run can never be mistaken for evidence.
    if SMOKE:
        prov.m["SMOKE_RUN"] = ("harness debugging only -- NOT evidence, tree may be dirty")
        prov._write()
    if not SMOKE and not prov.m["repo"]["clean_tree"]:
        print("REFUSING TO MEASURE: git tree is not clean. Commit the harness first.", flush=True)
        print(json.dumps(prov.m["repo"]["uncommitted"], indent=1), flush=True)
        prov.finish(status="REFUSED_DIRTY_TREE")
        return 2

    print(f"evidence: {evid}")
    print(f"commit {prov.m['repo']['commit'][:8]} clean={prov.m['repo']['clean_tree']}  "
          f"binary {prov.m['daemon_binary']['sha256'][:16]}")
    print(f"topology={TOPOLOGY}  reps={REPS}  mine={MINE_S}s post={POST_S}s  "
          f"rates total={TOTAL_RATE} third={RATE_THIRD} honest={RATE_HONEST}")
    print(f"snapshot height {snap['height']} tip {snap['tip_hash'][:16]} D={snap['tip_difficulty']}")

    results = []
    raw_paths = []
    port = PORT0
    aborted = None
    for rep in range(1, REPS + 1):
        if aborted:
            break
        for cond in CONDS:
            if aborted:
                break
            print(f"\n=== {cond.upper()} rep {rep} (ports {port}..{port + 29}) ===", flush=True)
            attempts = []
            r = None
            for attempt in range(1, MESH_RETRIES + 1):
                try:
                    r = run_condition(cond, rep, port, gts, prov, attempt=attempt, evid_dir=evid,
                                      raw_dir=RAW, blob_dir=BLOBS, series_id=series_id)
                    break
                except Exception as e:
                    # StageError carries the stage; anything else is treated as UNKNOWN, which is
                    # never retryable because measurement may already have begun.
                    stage_name = getattr(e, "stage", "UNKNOWN")
                    msg = f"{type(e).__name__}: {e}"
                    aid = f"{NS}{cond}{rep}_a{attempt}"
                    retryable = stage_name in PRE_MINING_STAGES
                    attempts.append({"attempt": attempt, "attempt_id": aid, "port": port,
                                     "stage": stage_name, "error": msg, "retryable": retryable})
                    print(f"  ! attempt {attempt} ({aid}) failed at stage {stage_name}: {msg}",
                          flush=True)
                    ipath = _write_interrupted(evid, series_id, cond, rep, attempt, aid, port, e,
                                               prov)
                    # ONE outcome record, assigned to r exactly once. The previous version appended
                    # a failure record to `results` without assigning r, and then dereferenced
                    # r["failed_attempts"] -- a guaranteed None-deref on a first-attempt
                    # post-start failure.
                    r = {"series_id": series_id, "condition": cond, "replicate": rep,
                         "topology": TOPOLOGY, "attempt_id": aid, "stage": stage_name,
                         "status": ("ERROR" if retryable else
                                    ("INVALID_POST_START_FAILURE" if stage_name != "UNKNOWN"
                                     else "INVALID_UNKNOWN_STAGE_FAILURE")),
                         "error": msg, "interrupted_record": ipath,
                         "partial_record": getattr(e, "partial", None) or {}}
                    if not retryable:
                        print(f"  !! stage {stage_name} is at or after MINING_STARTED -- the "
                              f"matched triplet for replicate {rep} is INVALID. The series is "
                              f"sealed invalid and the driver stops. A replacement must rerun the "
                              f"whole NONE/CONTROL/ATTACK triplet under a new series identity.",
                              flush=True)
                        aborted = {"reason": "post-start or unknown-stage failure",
                                   "stage": stage_name, "condition": cond, "replicate": rep,
                                   "error": msg}
                        break
                    port += 40
            # r is always a dict here: run_condition returned one, or the handler built one.
            # The previous version appended a failure record to `results` WITHOUT assigning
            # r, then dereferenced r["failed_attempts"] -- a guaranteed None-deref on a
            # first-attempt post-start failure.
            if attempts:
                r["failed_attempts"] = attempts
            path = os.path.join(RAW, f"{series_id}__{cond}_{rep}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(r, f, indent=1)
            prov.add_output(path, kind="raw")
            results.append(r)
            raw_paths.append(path)
            # The committed policy: any condition outcome after MINING_STARTED that is not fully
            # valid OK invalidates the matched triplet. Continuing would burn hours producing a
            # series that is already unusable.
            if r.get("status") != "OK" and not aborted:
                aborted = {"reason": f"condition outcome {r.get('status')}",
                           "stage": r.get("stage"), "condition": cond, "replicate": rep,
                           "error": r.get("error")}
                print(f"  !! condition status {r.get('status')} -- series sealed invalid, "
                      f"stopping.", flush=True)
            if r.get("status") in ("OK", "INVALID_TOPOLOGY_DRIFT", "INVALID_SAMPLE_COVERAGE",
                                   "INVALID_LOG_CAPTURE"):
                v, pn = r["verdicts"], r["per_node"]
                print(f"  topology ok={r['topology_before_mining']['established']} "
                      f"links={r['topology_before_mining']['links']} "
                      f"forbidden_present={r['topology_before_mining']['forbidden_present']} "
                      f"conformant_throughout={r['verdicts']['topology_conformant_throughout']}",
                      flush=True)
                print(f"  attempts total={r['achieved_total_attempts']} "
                      f"mining-phase rate={r['mining_phase_rate_per_s']}/s "
                      f"third_share={100 * r['mining_phase_third_share']:.2f}% "
                      f"(cap ok={r['third_share_within_prereg_cap']})", flush=True)
                print(f"    per-miner rate/s {r['mining_phase_rate_by_miner']}", flush=True)
                for n in NAMES:
                    print(f"    {n}: h={pn[n]['height']} cum={pn[n]['tip_cumulative_difficulty']} "
                          f"D[max]={pn[n]['difficulty']['max']} "
                          f"maxwin={pn[n]['max_window_occupancy']} "
                          f"tsspan={pn[n]['max_window_ts_span_s']}s "
                          f"eq={pn[n]['equilibrium']['entered']}", flush=True)
                print(f"  PARTITION={v['PARTITION']} (fork run {v['longest_h1_h2_fork_run_seconds']}s"
                      f", links_up={v['links_up_throughout']})  RECOVERY={v['RECOVERY']}",
                      flush=True)
            port += 40
    summary = os.path.join(evid, "summary.json")
    validity, vres, sres = finalize_series(raw_paths, results, evid, prov)
    with open(summary, "w", encoding="utf-8") as f:
        json.dump({"topology": TOPOLOGY, "reps": REPS,
                   "series_id": series_id,
                   "series_valid": validity["series_valid"],
                   "invalid_reasons": validity["invalid_reasons"],
                   # P0-7: the partition replay gate is a MACHINE gate, so it has to be in the
                   # sealed artefact. It was previously printed to stdout and then dropped, which
                   # left the strongest claim this harness can make unrecorded in the evidence.
                   "replay_gate": validity.get("replay_gate"),
                   "partition_records": validity.get("partition_records"),
                   "verifier_results_path": validity.get("verifier_results_path"),
                   "producer_verifier": {k: {"passed": v.get("passed"),
                                             "digest": v.get("digest")}
                                         for k, v in vres.items()},
                   "sample_verifier": {k: {"passed": v.get("passed"), "digest": v.get("digest")}
                                       for k, v in sres.items()},
                   "counted": validity["counted"], "pairs": validity.get("pairs"),
                   "branch_coverage": {f"{r.get('condition')}#{r.get('replicate')}":
                                       r.get("branch_coverage") for r in results},
                   "conditions": [{k: v for k, v in r.items()
                                   if k not in ("samples", "block_state_by_node", "per_node",
                                                "miner_evidence", "canonical_headers",
                                                "producer_of")}
                                  for r in results]}, f, indent=1)
    prov.add_output(summary, kind="summary")
    prov.m["series_valid"] = validity["series_valid"]
    prov.m["invalid_reasons"] = validity["invalid_reasons"]
    prov.m["replay_gate"] = validity.get("replay_gate")
    prov.m["aborted"] = aborted
    prov.finish()
    print(f"\nSERIES_VALID = {validity['series_valid']}")
    for r in validity["invalid_reasons"]:
        print(f"  ! {r}")
    if aborted:
        print(f"  !! SERIES ABORTED: {aborted}")
    print(f"\nevidence written to {evid}")
    # manifest.status (finalized) is deliberately SEPARATE from series_valid (scientifically
    # usable). Reaching the last line is not a result, so an invalid or aborted series exits
    # nonzero.
    return 0 if (validity["series_valid"] and not aborted) else 1


if __name__ == "__main__":
    sys.exit(main())
