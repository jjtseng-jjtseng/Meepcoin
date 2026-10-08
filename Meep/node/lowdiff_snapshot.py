#!/usr/bin/env python3
"""LD-B: build a REAL low-difficulty starting state, then fan it out to three byte-identical nodes.

No `--fixed-difficulty`, no consensus bypass: the daemon runs the actual T1+T2+T4 rules and the
real difficulty algorithm, and every block is accepted by ordinary consensus validation.

  1. isolated offline daemon, fresh genesis
  2. external miner (the SAME generation path the attack harness uses) mines until the tip has a
     long run of difficulty <= 10
  3. clean shutdown, verified
  4. the data directory is copied to h1 / h2 / attacker (sparse-aware copy -- the LMDB map is
     preallocated ~27 GB and must never be copied densely)
  5. all three start and are proved identical: genesis hash, height, tip hash, tip difficulty,
     cumulative difficulty
  6. INDEPENDENT VALIDATION: a fourth, completely empty daemon syncs the chain from scratch over
     P2P. If it reaches the same tip, every block was validated from genesis by a node that did
     not build them -- which is what makes "consensus-valid" a claim rather than an assumption.

Also runs an honest-timestamp control build, to record whether a long D<=10 history is reachable
at all without timestamp manipulation.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild, epee_median, rpc, rest, TS_WINDOW

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
FTL, FTL_MARGIN = 7200, 5
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 35900))
NBLOCKS = int(ARG.get("--blocks", 30))
OUT = ARG.get("--out", "docs/lowdiff/snapshot.json")
SNAPROOT = os.path.expanduser(ARG.get("--snaproot", "~/.meepcoin-lowdiff"))
COPIES = ["h1", "h2", "atk"]


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


def build(tag, port, strategy, nblocks, gts, budget=400, tolerant=False):
    """Mine `nblocks` on an isolated offline daemon.

    `tolerant` returns partial progress instead of raising, so the honest-timestamp control can
    record HOW FAR difficulty let it get rather than aborting the whole run -- with honest
    timestamps at launch, difficulty leaves reach within a handful of blocks and that is the
    measurement, not a failure."""
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    ddir = os.path.join(SNAPROOT, tag)
    if os.path.isdir(ddir):
        shutil.rmtree(ddir)
    d = L.Daemon(tag, port, port + 1, fixed_diff=0, offline=True, data_dir=ddir)
    hdrs, attempts, stopped = [], 0, None
    try:
        d.wait_synced(60)
        genesis = rpc(d.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
        while len(hdrs) < nblocks:
            ch = d.height()
            t = d.template()
            tdiff = int(t["difficulty"])
            ts = None
            if strategy == "adaptive":
                ph = ch - 1
                win = d.timestamps(max(0, ph - (TS_WINDOW - 1)), ph) if ch > 0 else []
                med = epee_median(win) if win else 0
                hi = int(time.time()) + FTL - FTL_MARGIN
                ts = hi if ch % 2 == 0 else med
            ok = False
            for i in range(budget):
                ok, _, _ = d.submit(rebuild(t["blocktemplate_blob"], ts=ts,
                                            nonce=(ch * 100003 + i) & 0xFFFFFFFF))
                attempts += 1
                if ok:
                    break
            if not ok:
                stopped = {"height": ch, "template_difficulty": tdiff, "attempts_spent": budget,
                           "reason": "difficulty rose beyond the per-block attempt budget"}
                if tolerant:
                    break
                raise RuntimeError(f"{tag}: could not extend at height {ch} "
                                   f"(template difficulty {tdiff})")
            h = rpc(d.rpc, "get_block_header_by_height", {"height": ch})["result"]["block_header"]
            hdrs.append({"height": ch, "hash": h["hash"], "prev_hash": h["prev_hash"],
                         "timestamp": int(h["timestamp"]), "difficulty": int(h["difficulty"]),
                         "cumulative_difficulty": int(h.get("cumulative_difficulty", 0))})
        tip = d.info()
    finally:
        # a snapshot must close LMDB cleanly, so wait properly for stop_daemon rather than
        # escalating to terminate after the 5 s sweep default
        d.stop(clean_wait=45.0)
    return ddir, hdrs, d.stop_path, genesis, tip, attempts, stopped


def longest_le10(hdrs):
    best = cur = 0
    for h in hdrs:
        cur = cur + 1 if h["difficulty"] <= 10 else 0
        best = max(best, cur)
    return best


def tail_le10(hdrs):
    n = 0
    for h in reversed(hdrs):
        if h["difficulty"] <= 10:
            n += 1
        else:
            break
    return n


def sizes(path):
    f = os.path.join(path, "testnet", "lmdb", "data.mdb")
    if not os.path.exists(f):
        f = next((os.path.join(r, "data.mdb") for r, _, fs in os.walk(path)
                  if "data.mdb" in fs), None)
    if not f:
        return {"data_mdb": None}
    st = os.stat(f)
    return {"data_mdb": f, "apparent_bytes": st.st_size,
            "actual_bytes": st.st_blocks * 512}


def main():
    os.makedirs(SNAPROOT, exist_ok=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "binary": BIN, "binary_sha256": sha(BIN),
           "fixed_difficulty": "0 -- DISABLED. Real difficulty algorithm, no consensus bypass.",
           "snapshot_root": SNAPROOT}

    # ---------------- honest-timestamp control build (is low D reachable honestly?) ------------
    gts_h = int(time.time())
    print("building honest-timestamp control chain …", flush=True)
    _, h_hdrs, _, _, _, h_att, h_stop = build("ctl_honest", PORT + 100, "honest", NBLOCKS, gts_h,
                                              tolerant=True)
    rec["honest_control_build"] = {
        "blocks": len(h_hdrs), "attempts": h_att, "stopped_because": h_stop,
        "longest_diff_le10_run": longest_le10(h_hdrs),
        "tail_diff_le10_run": tail_le10(h_hdrs),
        "difficulty_sequence": [h["difficulty"] for h in h_hdrs],
        "note": "honest timestamps, same miner, same rules -- shows how quickly difficulty "
                "leaves the D<=10 band without timestamp manipulation"}
    print(f"  honest: longest D<=10 run = {rec['honest_control_build']['longest_diff_le10_run']}, "
          f"tail run = {rec['honest_control_build']['tail_diff_le10_run']}", flush=True)

    # ---------------- the snapshot itself ----------------
    gts = int(time.time())
    print(f"building low-difficulty snapshot ({NBLOCKS} blocks) …", flush=True)
    src, hdrs, stop_path, genesis, tip, att, _ = build("snap_src", PORT, "adaptive",
                                                        NBLOCKS, gts)
    rec["snapshot_build"] = {
        "strategy": "adaptive lowest-legal / max-legal-future timestamps, accepted by ordinary "
                    "consensus validation (no bypass)",
        "genesis_ts": gts, "genesis_hash": genesis["hash"],
        "blocks": len(hdrs), "attempts": att, "clean_shutdown": stop_path,
        "longest_diff_le10_run": longest_le10(hdrs),
        "tail_diff_le10_run": tail_le10(hdrs),
        "tip_height": tip["height"], "tip_hash": tip["top_block_hash"],
        "headers": hdrs}
    print(f"  snapshot: height {tip['height']}, longest D<=10 run "
          f"{rec['snapshot_build']['longest_diff_le10_run']}, shutdown={stop_path}", flush=True)
    if rec["snapshot_build"]["tail_diff_le10_run"] < 10:
        raise SystemExit(f"FATAL: tip does not sit in a D<=10 run "
                         f"({rec['snapshot_build']['tail_diff_le10_run']} < 10)")
    rec["snapshot_sizes"] = sizes(src)

    # ---------------- fan out: sparse-aware copies ----------------
    print("copying snapshot to h1 / h2 / atk …", flush=True)
    rec["copies"] = {}
    for c in COPIES:
        dst = os.path.join(SNAPROOT, c)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        t0 = time.time()
        r = subprocess.run(["cp", "-a", "--sparse=always", src, dst],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"copy to {dst} failed: {r.stderr[:300]}")
        rec["copies"][c] = {"path": dst, "copy_s": round(time.time() - t0, 2), **sizes(dst)}
        print(f"  {c}: {rec['copies'][c]['copy_s']}s  "
              f"actual={rec['copies'][c]['actual_bytes']}B", flush=True)

    # ---------------- prove the three are identical, then validate independently ----------------
    print("starting the three copies and proving identical state …", flush=True)
    ports = {"h1": PORT + 20, "h2": PORT + 30, "atk": PORT + 40}
    fport = PORT + 60
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    ds = {}
    fresh = None
    try:
        for c in COPIES:
            # the validator port is included here on purpose: --add-exclusive-node restricts a node
            # to exactly the listed peers, so a validator absent from the list cannot attach.
            peers = [ports[o] for o in COPIES if o != c] + [fport]
            extra = []
            for p in peers:
                extra += ["--add-exclusive-node", f"127.0.0.1:{p}"]
            ds[c] = L.Daemon(f"snap_{c}", ports[c], ports[c] + 1, fixed_diff=0, offline=False,
                             extra=extra, wipe=False, data_dir=os.path.join(SNAPROOT, c))
        state = {}
        for c, d in ds.items():
            d.wait_synced(90)
            i = d.info()
            g = rpc(d.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
            th = rpc(d.rpc, "get_block_header_by_height",
                     {"height": i["height"] - 1})["result"]["block_header"]
            state[c] = {"genesis_hash": g["hash"], "height": i["height"],
                        "tip_hash": i["top_block_hash"], "tip_difficulty": int(th["difficulty"]),
                        "cumulative_difficulty": int(th.get("cumulative_difficulty", 0))}
        rec["identical_start_state"] = state
        keys = ("genesis_hash", "height", "tip_hash", "tip_difficulty", "cumulative_difficulty")
        rec["identical_verified"] = {k: len({state[c][k] for c in COPIES}) == 1 for k in keys}
        rec["all_identical"] = all(rec["identical_verified"].values())
        print(f"  identical: {rec['identical_verified']}  ALL={rec['all_identical']}", flush=True)

        # ---- independent full validation by a node that never saw these blocks built ----
        print("independent validation: syncing a fresh empty daemon from genesis …", flush=True)
        fdir = os.path.join(SNAPROOT, "validator")
        if os.path.isdir(fdir):
            shutil.rmtree(fdir)
        fresh = L.Daemon("snap_validator", fport, fport + 1, fixed_diff=0, offline=False,
                         extra=["--add-exclusive-node", f"127.0.0.1:{ports['h1']}"],
                         data_dir=fdir)
        target = state["h1"]["tip_hash"]
        t0 = time.time()
        got = None
        while time.time() - t0 < 180:
            try:
                i = fresh.info()
                if i["top_block_hash"] == target:
                    got = round(time.time() - t0, 2)
                    break
            except Exception:
                pass
            time.sleep(0.5)
        fi = fresh.info()
        rec["independent_validation"] = {
            "fresh_daemon_started_empty": True,
            "synced_to_snapshot_tip": got is not None,
            "sync_seconds": got,
            "fresh_height": fi["height"], "fresh_tip": fi["top_block_hash"],
            "expected_tip": target,
            "note": "a daemon with an empty database validated every block from genesis over P2P; "
                    "reaching the same tip is what makes the chain consensus-valid rather than "
                    "merely self-accepted"}
        print(f"  fresh daemon synced={got is not None} in {got}s "
              f"height={fi['height']}", flush=True)
    finally:
        if fresh:
            try: fresh.stop()
            except Exception: pass
        for c in reversed(COPIES):
            if c in ds:
                try: ds[c].stop()
                except Exception: pass

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print(f"\nwritten to {OUT}")
    ok = rec.get("all_identical") and rec["independent_validation"]["synced_to_snapshot_tip"]
    print(f"SNAPSHOT READY: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
