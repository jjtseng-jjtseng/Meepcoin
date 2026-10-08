#!/usr/bin/env python3
"""LD-A: POSITIVE CONTROL for the P2P attacker harness.

Purpose: make a later "attacker won 0 blocks" result mean something. If the attacker's block
generator were broken, a zero-block result would look identical to a successful defence. This run
proves the generator works end to end over real P2P, using the EXACT code path the attack harness
uses (same template call, same blob surgery, same submit, same adaptive timestamp selection).

Topology:
    attacker miner -> attacker daemon  ---P2P--->  passive peer
The passive peer never mines and NEVER receives a direct submit_block. Every block reaches it only
by relay, and it validates independently.

Recorded: raw attempts, attempts/s, valid PoW blocks found, blocks relayed and accepted by the
peer, propagation delay per block, and the reject reason for every rejected block on both sides.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild, epee_median, rpc, rest, TS_WINDOW

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
FTL, FTL_MARGIN = 7200, 5
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 35800))
TARGET = int(ARG.get("--blocks", 25))
BUDGET = int(ARG.get("--budget", 300))
ADAPTIVE = ARG.get("--adaptive", "1") != "0"
OUT = ARG.get("--out", "docs/lowdiff/poscontrol.json")

REJECT_KEYS = ("Block with id", "rejected", "INVALID BLOCK", "verification failed",
               "Failed to", "is not accepted", "PoW", "timestamp", "Invalid block")


def sha(p):
    return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]


def has_block(port, h):
    try:
        r = rpc(port, "get_block_header_by_hash", {"hash": h}, timeout=10)
        return "result" in r
    except Exception:
        return False


def main():
    os.makedirs(L.ROOT, exist_ok=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    gts = int(time.time())
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    pa, pp = PORT, PORT + 10
    da = L.Daemon("pc_atk", pa, pa + 1, fixed_diff=0, offline=False,
                  extra=["--add-exclusive-node", f"127.0.0.1:{pp}"],
                  data_dir=os.path.join(L.ROOT, "pc_atk"))
    dp = L.Daemon("pc_peer", pp, pp + 1, fixed_diff=0, offline=False,
                  extra=["--add-exclusive-node", f"127.0.0.1:{pa}"],
                  data_dir=os.path.join(L.ROOT, "pc_peer"))
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "binary": BIN, "binary_sha256": sha(BIN), "genesis_ts": gts,
           "adaptive_timestamps": ADAPTIVE, "target_blocks": TARGET,
           "topology": "attacker daemon --P2P--> passive peer; peer never mines, "
                       "never receives a direct submit_block",
           "attempts": [], "blocks": []}
    try:
        for d in (da, dp):
            d.wait_synced(60)
        g = rpc(da.rpc, "get_block_header_by_height", {"height": 0})["result"]["block_header"]
        rec["genesis_hash"] = g["hash"]
        rec["peer_genesis_hash"] = rpc(dp.rpc, "get_block_header_by_height",
                                       {"height": 0})["result"]["block_header"]["hash"]
        rec["peers"] = {"attacker": da.info().get("outgoing_connections_count", 0) +
                                    da.info().get("incoming_connections_count", 0),
                        "peer": dp.info().get("outgoing_connections_count", 0) +
                                dp.info().get("incoming_connections_count", 0)}
        dp.mark_log(); da.mark_log()

        attempts = 0
        found = 0
        t0 = time.time()
        while found < TARGET and time.time() - t0 < BUDGET:
            ch = da.height()
            t = da.template()
            diff = int(t["difficulty"])
            ts = None; choice = "honest-template"
            if ADAPTIVE:
                ph = ch - 1
                win = da.timestamps(max(0, ph - (TS_WINDOW - 1)), ph) if ch > 0 else []
                med = epee_median(win) if win else 0
                hi = int(time.time()) + FTL - FTL_MARGIN
                ts, choice = ((hi, "max-legal-future") if ch % 2 == 0 else (med, "lowest-legal"))
            ok = False
            for i in range(400):
                blob = rebuild(t["blocktemplate_blob"], ts=ts,
                               nonce=(ch * 100003 + i) & 0xFFFFFFFF)
                r, err, dt = da.submit(blob)
                attempts += 1
                if r:
                    ok = True
                    break
                # record only distinct reject reasons, to keep the file readable
                if err and not any(a.get("reason") == err for a in rec["attempts"]):
                    rec["attempts"].append({"height": ch, "reason": err, "difficulty": diff,
                                            "strategy": choice})
                if time.time() - t0 > BUDGET:
                    break
            if not ok:
                continue
            found += 1
            t_found = time.time()
            hdr = rpc(da.rpc, "get_block_header_by_height", {"height": ch})["result"]["block_header"]
            bh = hdr["hash"]
            # ---- P2P propagation to the passive peer (never a direct submit) ----
            prop = None
            deadline = time.time() + 20
            while time.time() < deadline:
                if has_block(dp.rpc, bh):
                    prop = round(time.time() - t_found, 4)
                    break
                time.sleep(0.02)
            rec["blocks"].append({"n": found, "height": ch, "hash": bh,
                                  "prev_hash": hdr["prev_hash"],
                                  "timestamp": hdr["timestamp"], "difficulty": int(hdr["difficulty"]),
                                  "cumulative_difficulty": int(hdr.get("cumulative_difficulty", 0)),
                                  "strategy": choice, "attempts_so_far": attempts,
                                  "peer_accepted": prop is not None,
                                  "propagation_s": prop})
        elapsed = time.time() - t0
        rec["elapsed_s"] = round(elapsed, 2)
        rec["raw_attempts"] = attempts
        rec["raw_attempts_per_s"] = round(attempts / elapsed, 2)
        rec["valid_pow_blocks_found"] = found
        rec["blocks_accepted_by_peer"] = sum(1 for b in rec["blocks"] if b["peer_accepted"])
        rec["blocks_rejected_by_peer"] = sum(1 for b in rec["blocks"] if not b["peer_accepted"])
        props = [b["propagation_s"] for b in rec["blocks"] if b["propagation_s"] is not None]
        rec["propagation_s"] = {
            "n": len(props),
            "min": round(min(props), 4) if props else None,
            "median": round(statistics.median(props), 4) if props else None,
            "max": round(max(props), 4) if props else None,
            "mean": round(statistics.mean(props), 4) if props else None}
        ia, ip = da.info(), dp.info()
        rec["final"] = {"attacker_height": ia["height"], "peer_height": ip["height"],
                        "attacker_tip": ia["top_block_hash"], "peer_tip": ip["top_block_hash"],
                        "tips_equal": ia["top_block_hash"] == ip["top_block_hash"]}
        rec["peer_reject_log"] = [l for l in dp.new_log()
                                  if any(k.lower() in l.lower() for k in REJECT_KEYS)][:60]
        rec["attacker_reject_log"] = [l for l in da.new_log()
                                      if any(k.lower() in l.lower() for k in REJECT_KEYS)][:60]
        rec["peer_alt_blocks"] = len(rest(dp.rpc, "/get_alt_blocks_hashes").get("blks_hashes") or [])
    finally:
        for d in (dp, da):
            try: d.stop()
            except Exception: pass

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print(f"genesis           {rec.get('genesis_hash','?')[:32]}")
    print(f"peer genesis      {rec.get('peer_genesis_hash','?')[:32]}  "
          f"equal={rec.get('genesis_hash')==rec.get('peer_genesis_hash')}")
    print(f"peers             {rec.get('peers')}")
    print(f"raw attempts      {rec.get('raw_attempts')}  ({rec.get('raw_attempts_per_s')} /s)")
    print(f"valid PoW blocks  {rec.get('valid_pow_blocks_found')}")
    print(f"peer accepted     {rec.get('blocks_accepted_by_peer')}  "
          f"rejected {rec.get('blocks_rejected_by_peer')}")
    print(f"propagation (s)   {rec.get('propagation_s')}")
    print(f"final             {rec.get('final')}")
    print(f"distinct reject reasons at attacker: "
          f"{[a['reason'] for a in rec['attempts']][:6]}")
    print(f"peer reject log lines: {len(rec.get('peer_reject_log', []))}")
    print(f"written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
