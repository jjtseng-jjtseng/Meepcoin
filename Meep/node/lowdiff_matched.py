#!/usr/bin/env python3
"""LD-C/D/E: matched CONTROL vs ATTACK from byte-identical low-difficulty snapshots.

THE QUESTION
    Can a real remote P2P attacker with a small share of hashing capacity HOLD a genuinely
    consensus-valid chain near minimum difficulty after independent honest miners join?

Both conditions start from a fresh copy of the SAME snapshot (height 31, tip difficulty 1, a
30-block run of D<=10, built with no consensus bypass and independently validated by an empty
daemon syncing it from genesis). The only difference between conditions is the third miner's
timestamp strategy; its capacity, code path and rate are identical.

    CONTROL   h1 + h2 mine honestly; third miner uses HONEST timestamps
    ATTACK    h1 + h2 mine honestly; third miner uses the adaptive lowest-legal / max-legal-future
              strategy under the actual current T1+T2+T4 rules

The attacker submits only to its OWN daemon. Everything else propagates over P2P.

PRODUCER ATTRIBUTION IS RECORDED, NOT INFERRED
    h1, h2   the finding node's own log line "Found block <hash> at height <h> for difficulty <d>",
             and distinct mining addresses (walletA / walletB)
    atk      the exact hashes it submitted
    A completeness check reports any block not claimed by some producer.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
No consensus rule is added or modified by this script.
"""
import json, os, re, shutil, statistics, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild, epee_median, rpc, rest, TS_WINDOW

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
HOME = os.path.expanduser("~")
ADDR_A = open(os.path.join(HOME, ".meepcoin-devnet/wallets/walletA.address.txt")).read().strip()
ADDR_B = open(os.path.join(HOME, ".meepcoin-devnet/wallets/walletB.address.txt")).read().strip()
FTL, FTL_MARGIN = 7200, 5

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 36100))
TARGET = int(ARG.get("--blocks", 100))       # final-chain blocks required AFTER the snapshot
BUDGET = int(ARG.get("--budget", 600))       # seconds per condition
THREADS = int(ARG.get("--threads", 4))
SNAPROOT = os.path.expanduser(ARG.get("--snaproot", "~/.meepcoin-lowdiff"))
SRC = os.path.join(SNAPROOT, "snap_src")
OUTDIR = ARG.get("--outdir", "docs/lowdiff")
CONDS = ARG.get("--conditions", "control,attack").split(",")
RECOVERY = int(ARG.get("--recovery", 0))   # seconds to keep honest miners running
                                           # AFTER the third miner stops

# ---------------------------------------------------------------- PRE-REGISTERED, before results
# Honest raw capacity measured in the hash-bound regime (docs/lowdiff/cap_calibrate.json):
#   222 H/s median per 4-thread miner  ->  444 H/s for the two honest nodes together.
# With DIFFICULTY_TARGET_V2 = 60 s, the difficulty this network should settle at is
#   444 * 60 = 26,640.
HONEST_RAW_HS_EACH = 222
EQUILIBRIUM_D = HONEST_RAW_HS_EACH * 2 * 60          # 26,640
EQ_LO, EQ_HI = EQUILIBRIUM_D // 4, EQUILIBRIUM_D * 4  # 6,660 .. 106,560
EQ_SUSTAIN = 20                                       # consecutive blocks required inside the band
# Interpretation thresholds, fixed before any result is seen:
TH_LONGER_FACTOR, TH_LONGER_MIN = 3.0, 30   # ATTACK holds D<=10 "materially longer"
TH_WORK_DEGRADE = 0.75                      # honest work share in ATTACK vs CONTROL
PREREG = {
    "honest_raw_hs_each": HONEST_RAW_HS_EACH,
    "equilibrium_difficulty_expected": EQUILIBRIUM_D,
    "equilibrium_band": [EQ_LO, EQ_HI], "equilibrium_sustain_blocks": EQ_SUSTAIN,
    "attack_holds_low_D_if": f"longest D<=10 run >= {TH_LONGER_FACTOR}x CONTROL and >= "
                             f"{TH_LONGER_MIN} blocks",
    "honest_work_materially_degraded_if": f"honest cumulative-work share in ATTACK < "
                                          f"{TH_WORK_DEGRADE} x its share in CONTROL",
    "recovery_prevented_if": f"ATTACK never sustains the equilibrium band within {TARGET} blocks "
                             f"while CONTROL does",
}

FOUND_RE = re.compile(r"Found block <?([0-9a-f]{64})>? at height (\d+) for difficulty:?\s*(\d+)")
REORG_RE = re.compile(r"REORGANIZE.*?on height:?\s*(\d+)")
REJECT_KEYS = ("rejected", "INVALID", "verification failed", "is not accepted",
               "Failed to", "Invalid block", "PoW", "timestamp")


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


class NodeWatcher(threading.Thread):
    """Per-node first-seen timeline. Polls the tip fast enough to time propagation, and samples
    mining speed together with the tip difficulty so the speed reading can be interpreted (it is
    only a valid capacity measure where the miner is hash-bound)."""
    def __init__(self, name, d, stop):
        super().__init__(daemon=True)
        self.name, self.d, self.stop = name, d, stop
        self.first_seen, self.tips, self.speeds, self.alts = {}, [], [], set()
        self.err = None

    def run(self):
        last, t_alt = None, 0.0
        while not self.stop.is_set():
            now = time.time()
            try:
                i = self.d.info()
                tip, h = i["top_block_hash"], int(i["height"])
                if tip != last:
                    self.first_seen.setdefault(tip, now)
                    self.tips.append({"t": now, "height": h, "tip": tip})
                    last = tip
                if now - t_alt > 1.0:
                    t_alt = now
                    try:
                        for a in (rest(self.d.rpc, "/get_alt_blocks_hashes").get("blks_hashes")
                                  or []):
                            self.alts.add(a)
                            self.first_seen.setdefault(a, now)
                    except Exception:
                        pass
                    try:
                        ms = rest(self.d.rpc, "/mining_status")
                        self.speeds.append({"t": now, "speed": ms.get("speed"), "height": h})
                    except Exception:
                        pass
            except Exception as e:
                self.err = f"{type(e).__name__}: {e}"
            time.sleep(0.02)


class ThirdMiner(threading.Thread):
    """The third miner. Identical code path and rate in both conditions; only `adaptive` differs."""
    def __init__(self, d, adaptive, stop):
        super().__init__(daemon=True)
        self.d, self.adaptive, self.stop = d, adaptive, stop
        self.attempts, self.accepted = 0, 0
        self.hashes, self.rows, self.rejects = set(), [], {}

    def run(self):
        while not self.stop.is_set():
            try:
                ch = self.d.height()
                t = self.d.template()
                diff = int(t["difficulty"])
                ts, choice = None, "honest-template"
                if self.adaptive:
                    ph = ch - 1
                    win = self.d.timestamps(max(0, ph - (TS_WINDOW - 1)), ph) if ch > 0 else []
                    med = epee_median(win) if win else 0
                    hi = int(time.time()) + FTL - FTL_MARGIN
                    ts, choice = ((hi, "max-legal-future") if ch % 2 == 0 else (med, "lowest-legal"))
                ok = False
                for i in range(400):
                    if self.stop.is_set():
                        return
                    ok, err, _ = self.d.submit(rebuild(t["blocktemplate_blob"], ts=ts,
                                                       nonce=(ch * 100003 + i) & 0xFFFFFFFF))
                    self.attempts += 1
                    if ok:
                        break
                    if err:
                        self.rejects[err] = self.rejects.get(err, 0) + 1
                if not ok:
                    continue
                self.accepted += 1
                try:
                    hdr = rpc(self.d.rpc, "get_block_header_by_height",
                              {"height": ch})["result"]["block_header"]
                    self.hashes.add(hdr["hash"])
                    self.rows.append({"height": ch, "hash": hdr["hash"], "ts": ts,
                                      "strategy": choice, "difficulty": diff})
                except Exception:
                    pass
            except Exception:
                time.sleep(0.02)


def parse_found(d):
    """Recorded attribution: the finding node's own log line."""
    out = {}
    for line in d.new_log():
        m = FOUND_RE.search(line)
        if m:
            out[m.group(1)] = {"height": int(m.group(2)), "difficulty": int(m.group(3))}
    return out


def fresh_copy(name):
    dst = os.path.join(SNAPROOT, name)
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    r = subprocess.run(["cp", "-a", "--sparse=always", SRC, dst], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"copy {SRC} -> {dst} failed: {r.stderr[:300]}")
    return dst


def first_in_band(diffs, lo, hi, sustain):
    """Index of the first block after which difficulty stays inside [lo,hi] for `sustain` blocks."""
    run = 0
    for i, dv in enumerate(diffs):
        run = run + 1 if lo <= dv <= hi else 0
        if run >= sustain:
            return i - sustain + 1
    return None


def run_condition(cond, gts, snap):
    # cond: "none"    -> no third miner at all (do the two honest nodes alone escape D<=10?)
    #       "control" -> third miner, identical loop and rate, HONEST timestamps
    #       "attack"  -> third miner, identical loop and rate, adaptive malicious timestamps
    adaptive = (cond == "attack")
    ports = {"h1": PORT, "h2": PORT + 10, "atk": PORT + 20}
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    dirs = {c: fresh_copy(f"run_{cond}_{c}") for c in ("h1", "h2", "atk")}
    ds, stop = {}, threading.Event()
    # separate event so the third miner can be stopped while the watchers and the honest miners
    # keep running -- that is what makes an attack-stop recovery measurement possible
    stop_third = threading.Event()
    rec = {"condition": cond, "adaptive_timestamps": adaptive,
           "binary": BIN, "binary_sha256": sha(BIN), "prereg": PREREG,
           "fixed_difficulty": "0 -- DISABLED, real difficulty algorithm",
           "snapshot": {k: snap[k] for k in ("genesis_hash", "tip_hash", "tip_height",
                                             "tip_difficulty", "cumulative_difficulty")}}
    try:
        for c in ("h1", "h2", "atk"):
            peers = [ports[o] for o in ports if o != c]
            extra = []
            for p in peers:
                extra += ["--add-exclusive-node", f"127.0.0.1:{p}"]
            ds[c] = L.Daemon(f"ld_{cond}_{c}", ports[c], ports[c] + 1, fixed_diff=0, offline=False,
                             extra=extra, wipe=False, data_dir=dirs[c])
        start_state = {}
        for c, d in ds.items():
            d.wait_synced(90)
            i = d.info()
            g = rpc(d.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
            th = rpc(d.rpc, "get_block_header_by_height",
                     {"height": i["height"] - 1})["result"]["block_header"]
            start_state[c] = {"genesis_hash": g["hash"], "height": int(i["height"]),
                              "tip_hash": i["top_block_hash"],
                              "tip_difficulty": int(th["difficulty"]),
                              "cumulative_difficulty": int(th.get("cumulative_difficulty", 0))}
        rec["start_state"] = start_state
        keys = ("genesis_hash", "height", "tip_hash", "tip_difficulty", "cumulative_difficulty")
        rec["start_identical"] = {k: len({start_state[c][k] for c in ds}) == 1 for k in keys}
        rec["start_matches_snapshot"] = all(
            start_state["h1"][k] == snap[{"height": "tip_height"}.get(k, k)] for k in keys
            if k != "height") and start_state["h1"]["height"] == snap["tip_height"]
        rec["peers"] = {c: int(d.info().get("outgoing_connections_count", 0)) +
                           int(d.info().get("incoming_connections_count", 0))
                        for c, d in ds.items()}
        h0 = start_state["h1"]["height"]

        for d in ds.values():
            d.mark_log()
        ws = {c: NodeWatcher(c, d, stop) for c, d in ds.items()}
        for w in ws.values():
            w.start()

        # honest internal miners, distinct addresses -> distinct producers
        rest(ds["h1"].rpc, "/start_mining", {"miner_address": ADDR_A, "threads_count": THREADS,
                                             "do_background_mining": False, "ignore_battery": True})
        rest(ds["h2"].rpc, "/start_mining", {"miner_address": ADDR_B, "threads_count": THREADS,
                                             "do_background_mining": False, "ignore_battery": True})
        third = ThirdMiner(ds["atk"], adaptive, stop_third)
        if cond != "none":
            third.start()
        # "symmetric": h1 and h2 ALSO mine through the external tight loop instead of the daemon's
        # internal miner. This separates two very different explanations for the third miner's
        # dominance -- an external loop simply out-cadencing Monero's internal miner (an artifact
        # of how the honest miners are driven), versus a structural advantage held by whoever
        # submits locally while the network is producing blocks faster than they propagate.
        ext = {}
        if cond == "symmetric":
            for c in ("h1", "h2"):
                try: rest(ds[c].rpc, "/stop_mining", {})
                except Exception: pass
                ext[c] = ThirdMiner(ds[c], False, stop_third)
                ext[c].start()

        t0 = time.time()
        reached = None
        while time.time() - t0 < BUDGET:
            try:
                if int(ds["h1"].info()["height"]) - h0 >= TARGET:
                    reached = round(time.time() - t0, 2)
                    break
            except Exception:
                pass
            time.sleep(0.05)
        elapsed = time.time() - t0
        # ---- attack stop / recovery: third miner off, honest miners still mining ----
        stop_third.set()
        if cond != "none":
            third.join(timeout=20)
        for m in ext.values():
            m.join(timeout=20)
        if RECOVERY > 0:
            def snap_state():
                st = {}
                for c, d in ds.items():
                    try:
                        i = d.info()
                        th = rpc(d.rpc, "get_block_header_by_height",
                                 {"height": int(i["height"]) - 1})["result"]["block_header"]
                        st[c] = {"height": int(i["height"]), "tip": i["top_block_hash"],
                                 "difficulty": int(th["difficulty"]),
                                 "cumulative_difficulty": int(th.get("cumulative_difficulty", 0))}
                    except Exception as e:
                        st[c] = {"error": f"{type(e).__name__}: {e}"}
                st["converged"] = len({v.get("tip") for v in st.values()
                                       if isinstance(v, dict)}) == 1
                return st
            rec["recovery"] = {"seconds": RECOVERY, "at_attack_stop": snap_state(), "timeline": []}
            t_r = time.time()
            while time.time() - t_r < RECOVERY:
                time.sleep(15.0)
                st = snap_state()
                st["t"] = round(time.time() - t_r, 1)
                rec["recovery"]["timeline"].append(st)
            rec["recovery"]["at_end"] = snap_state()
            conv = [x for x in rec["recovery"]["timeline"] if x.get("converged")]
            rec["recovery"]["converged_after_s"] = conv[0]["t"] if conv else None
            rec["recovery"]["converged_at_end"] = rec["recovery"]["at_end"]["converged"]
        stop.set()
        for c in ("h1", "h2"):
            try: rest(ds[c].rpc, "/stop_mining", {})
            except Exception: pass
        time.sleep(2.0)
        rec["elapsed_s"] = round(elapsed, 2)
        rec["reached_target_s"] = reached
        rec["target_blocks"] = TARGET

        found = {c: parse_found(ds[c]) for c in ("h1", "h2")}
        logs = {c: ds[c].new_log() for c in ds}
        rec["reorgs"] = {c: [int(m.group(1)) for l in logs[c] for m in [REORG_RE.search(l)] if m]
                         for c in ds}
        rec["reject_log"] = {c: [l for l in logs[c]
                                 if any(k.lower() in l.lower() for k in REJECT_KEYS)][:40]
                             for c in ds}

        # ------------------------------- final chains -------------------------------
        tips = {c: ds[c].info() for c in ds}
        rec["final"] = {c: {"height": int(tips[c]["height"]), "tip": tips[c]["top_block_hash"]}
                        for c in ds}
        rec["converged"] = len({tips[c]["top_block_hash"] for c in ds}) == 1
        H = int(tips["h1"]["height"])
        hdrs = []
        for lo in range(h0, H, 500):
            hdrs += rpc(ds["h1"].rpc, "get_block_headers_range",
                        {"start_height": lo, "end_height": min(lo + 499, H - 1)},
                        timeout=180)["result"]["headers"]

        def producer(bh):
            if bh in third.hashes:
                return "atk"
            for c, m in ext.items():          # symmetric condition: external honest miners
                if bh in m.hashes:
                    return c
            if bh in found["h1"]:
                return "h1"
            if bh in found["h2"]:
                return "h2"
            return "unattributed"

        chain_hashes = {h["hash"] for h in hdrs}
        blocks = []
        for h in hdrs:
            bh = h["hash"]
            blocks.append({
                "height": int(h["height"]), "hash": bh, "prev_hash": h["prev_hash"],
                "producer": producer(bh), "timestamp": int(h["timestamp"]),
                "difficulty": int(h["difficulty"]),
                "cumulative_difficulty": int(h.get("cumulative_difficulty", 0)),
                "first_seen": {c: (round(ws[c].first_seen[bh] - t0, 4)
                                   if bh in ws[c].first_seen else None) for c in ds},
                "on_final_chain": True, "orphan": False})
        # competing blocks: everything a producer made or a node held as an alt, but not on chain
        competing = set()
        for c in ds:
            competing |= ws[c].alts
        competing |= (third.hashes - chain_hashes)
        for c in ("h1", "h2"):
            competing |= (set(found[c]) - chain_hashes)
        for m in ext.values():
            competing |= (m.hashes - chain_hashes)
        competing -= chain_hashes
        for bh in sorted(competing):
            entry = {"hash": bh, "producer": producer(bh), "on_final_chain": False, "orphan": True,
                     "first_seen": {c: (round(ws[c].first_seen[bh] - t0, 4)
                                        if bh in ws[c].first_seen else None) for c in ds},
                     "accepted_on": {}}
            for c, d in ds.items():
                try:
                    r = rpc(d.rpc, "get_block_header_by_hash", {"hash": bh}, timeout=15)
                    entry["accepted_on"][c] = "result" in r
                    if "result" in r:
                        b = r["result"]["block_header"]
                        entry.setdefault("height", int(b["height"]))
                        entry.setdefault("difficulty", int(b["difficulty"]))
                        entry.setdefault("timestamp", int(b["timestamp"]))
                        entry.setdefault("prev_hash", b["prev_hash"])
                except Exception as e:
                    entry["accepted_on"][c] = f"error: {type(e).__name__}"
            blocks.append(entry)
        rec["blocks"] = blocks

        # ------------------------------- item E metrics -------------------------------
        diffs = [b["difficulty"] for b in blocks if b["on_final_chain"]]
        ts_ = [b["timestamp"] for b in blocks if b["on_final_chain"]]
        best = cur = 0
        for dv in diffs:
            cur = cur + 1 if dv <= 10 else 0
            best = max(best, cur)
        idx_gt10 = next((i for i, dv in enumerate(diffs) if dv > 10), None)
        idx_gt100 = next((i for i, dv in enumerate(diffs) if dv > 100), None)
        eq_i = first_in_band(diffs, EQ_LO, EQ_HI, EQ_SUSTAIN)
        work = {}
        for p in ("h1", "h2", "atk", "unattributed"):
            bs = [b for b in blocks if b["on_final_chain"] and b["producer"] == p]
            work[p] = {"blocks": len(bs), "cumulative_accepted_work": sum(b["difficulty"]
                                                                         for b in bs)}
        totw = sum(v["cumulative_accepted_work"] for v in work.values()) or 1
        totb = sum(v["blocks"] for v in work.values()) or 1
        for p in work:
            work[p]["block_share"] = round(work[p]["blocks"] / totb, 4)
            work[p]["work_share"] = round(work[p]["cumulative_accepted_work"] / totw, 4)
        rec["accepted_work"] = work
        rec["honest_work_share"] = round(
            (work["h1"]["cumulative_accepted_work"] + work["h2"]["cumulative_accepted_work"])
            / totw, 4)
        orph = {}
        for p in ("h1", "h2", "atk"):
            orph[p] = sum(1 for b in blocks if b["orphan"] and b["producer"] == p)
        rec["orphans_by_producer"] = orph
        rec["difficulty"] = {
            "min": min(diffs) if diffs else None, "max": max(diffs) if diffs else None,
            "median": int(statistics.median(diffs)) if diffs else None,
            "blocks_le10": sum(1 for dv in diffs if dv <= 10),
            "longest_le10_run": best,
            "height_until_gt10": (h0 + idx_gt10) if idx_gt10 is not None else None,
            "blocks_until_gt10": idx_gt10,
            "height_until_gt100": (h0 + idx_gt100) if idx_gt100 is not None else None,
            "blocks_until_gt100": idx_gt100,
            "equilibrium_entered_at_block": eq_i,
            "equilibrium_entered_at_height": (h0 + eq_i) if eq_i is not None else None,
            "sequence": diffs[:400]}
        # time until, from first-seen on h1
        def t_of(i):
            if i is None or i >= len(blocks):
                return None
            return blocks[i]["first_seen"].get("h1")
        rec["difficulty"]["seconds_until_gt10"] = t_of(idx_gt10)
        rec["difficulty"]["seconds_until_gt100"] = t_of(idx_gt100)
        rec["difficulty"]["seconds_until_equilibrium"] = t_of(eq_i)
        # tip progress gaps + propagation
        gaps = {}
        for c in ds:
            tt = [x["t"] for x in ws[c].tips]
            g = [round(b - a, 4) for a, b in zip(tt, tt[1:])]
            gaps[c] = {"n": len(g), "max_no_progress_s": max(g) if g else None,
                       "median_s": round(statistics.median(g), 4) if g else None}
        rec["tip_progress_gaps"] = gaps
        props = []
        for b in blocks:
            fs = [v for v in b["first_seen"].values() if v is not None]
            if len(fs) >= 2:
                props.append(round(max(fs) - min(fs), 4))
        rec["p2p_propagation_s"] = {
            "n": len(props),
            "min": min(props) if props else None,
            "median": round(statistics.median(props), 4) if props else None,
            "p95": round(sorted(props)[int(0.95 * (len(props) - 1))], 4) if props else None,
            "max": max(props) if props else None}
        rec["third_miner"] = {
            "raw_attempts": third.attempts, "local_accepted": third.accepted,
            "attempts_per_s": round(third.attempts / elapsed, 2),
            "distinct_reject_reasons": third.rejects,
            "note": "at difficulty ~1 nearly every attempt wins, so attempts/s measures the "
                    "template->submit round-trip rate, NOT hashing capacity"}
        rec["active_hashing_speed_samples"] = {
            c: {"max": max([s["speed"] or 0 for s in ws[c].speeds] or [0]),
                "median": int(statistics.median([s["speed"] or 0 for s in ws[c].speeds]))
                if ws[c].speeds else None, "n": len(ws[c].speeds)} for c in ("h1", "h2")}
        rec["attribution"] = {
            "h1_found_log_lines": len(found["h1"]), "h2_found_log_lines": len(found["h2"]),
            "atk_recorded_hashes": len(third.hashes),
            "external_honest_recorded_hashes": {c: len(m.hashes) for c, m in ext.items()},
            "external_honest_attempts": {c: m.attempts for c, m in ext.items()},
            "unattributed_final_chain_blocks": work["unattributed"]["blocks"],
            "method": "h1/h2 from each node's own 'Found block' log line plus distinct mining "
                      "addresses; atk from the exact hashes it submitted"}
        rec["timestamps"] = {"min": min(ts_) if ts_ else None, "max": max(ts_) if ts_ else None,
                             "span_s": (max(ts_) - min(ts_)) if ts_ else None}
    finally:
        stop.set()
        for c in ("atk", "h2", "h1"):
            if c in ds:
                try: ds[c].stop()
                except Exception: pass
    return rec


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    snapfile = os.path.join(OUTDIR, "snapshot.json")
    snap_all = json.load(open(snapfile))
    snap = dict(snap_all["identical_start_state"]["h1"])
    snap["tip_height"] = snap.pop("height")
    snap["genesis_ts"] = snap_all["snapshot_build"]["genesis_ts"]
    print("PRE-REGISTERED (fixed before this run):", json.dumps(PREREG, indent=1), flush=True)
    print(f"snapshot: height {snap['tip_height']} tip {snap['tip_hash'][:16]} "
          f"D={snap['tip_difficulty']} cum={snap['cumulative_difficulty']}", flush=True)
    out = {}
    for cond in CONDS:
        print(f"\n=== {cond.upper()} ===", flush=True)
        r = run_condition(cond, snap["genesis_ts"], snap)
        with open(os.path.join(OUTDIR, f"matched_{cond}.json"), "w", encoding="utf-8") as f:
            json.dump(r, f, indent=1)
        out[cond] = r
        d = r["difficulty"]
        print(f"  start identical: {r['start_identical']}  matches snapshot: "
              f"{r['start_matches_snapshot']}  peers {r['peers']}", flush=True)
        print(f"  final-chain blocks {sum(v['blocks'] for v in r['accepted_work'].values())} "
              f"in {r['elapsed_s']}s (target reached at {r['reached_target_s']}s)", flush=True)
        print(f"  D: min {d['min']} median {d['median']} max {d['max']}  "
              f"blocks<=10 {d['blocks_le10']}  longest run {d['longest_le10_run']}", flush=True)
        print(f"  blocks until D>10 {d['blocks_until_gt10']}  until D>100 "
              f"{d['blocks_until_gt100']}  equilibrium at block "
              f"{d['equilibrium_entered_at_block']}", flush=True)
        print(f"  accepted work: " + "  ".join(
            f"{p}={v['blocks']}blk/{100*v['work_share']:.1f}%w" for p, v in
            r["accepted_work"].items()), flush=True)
        print(f"  orphans {r['orphans_by_producer']}  reorgs "
              f"{ {c: len(v) for c, v in r['reorgs'].items()} }  converged {r['converged']}",
              flush=True)
        print(f"  third miner: {r['third_miner']['raw_attempts']} attempts "
              f"({r['third_miner']['attempts_per_s']}/s)  unattributed "
              f"{r['attribution']['unattributed_final_chain_blocks']}", flush=True)
    with open(os.path.join(OUTDIR, "matched_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"prereg": PREREG,
                   "conditions": {k: {kk: vv for kk, vv in v.items() if kk != "blocks"}
                                  for k, v in out.items()}}, f, indent=1)
    print("\nwritten to", OUTDIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
