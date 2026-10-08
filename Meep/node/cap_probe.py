#!/usr/bin/env python3
"""Diagnose the raw-capacity measurement bug: why does the FIRST node measured in isolation
report 0 H/s while the second reports ~230 H/s?

Reproduces the exact sequence used by p2p_starvation.py -- three P2P-connected daemons on a fresh
genesis, wait_synced, then start_mining on h1 -- but prints the FULL RPC responses instead of
silently taking `.get("speed", 0)`.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rpc, rest

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
PORT = int(next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--port=")), 35600))
SECS = int(next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--secs=")), 40))
OUT = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--out=")),
           "docs/p2p_starve/cap_probe.json")


def start(tag, p2p, rpcp, peers, gts):
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    extra = []
    for pp in peers:
        extra += ["--add-exclusive-node", f"127.0.0.1:{pp}"]
    return L.Daemon(tag, p2p, rpcp, fixed_diff=0, offline=False, extra=extra,
                    data_dir=os.path.join(L.ROOT, tag))


def probe(name, d, rec):
    r = rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": 4,
                                      "do_background_mining": False, "ignore_battery": True})
    info = d.info()
    print(f"[{name}] start_mining -> {json.dumps(r)}", flush=True)
    print(f"[{name}] get_info synchronized={info.get('synchronized')} "
          f"height={info.get('height')} status={info.get('status')} "
          f"out={info.get('outgoing_connections_count')} in={info.get('incoming_connections_count')}",
          flush=True)
    samples = []
    t0 = time.time()
    while time.time() - t0 < SECS:
        try:
            ms = rest(d.rpc, "/mining_status")
        except Exception as e:
            ms = {"error": f"{type(e).__name__}: {e}"}
        samples.append({"t": round(time.time() - t0, 2), "active": ms.get("active"),
                        "speed": ms.get("speed"), "threads": ms.get("threads_count"),
                        "status": ms.get("status"),
                        "block_reward": ms.get("block_reward"), "raw": ms if "error" in ms else None})
        time.sleep(1.0)
    for s in samples:
        print(f"[{name}] t={s['t']:>5}  active={s['active']}  speed={s['speed']}  "
              f"threads={s['threads']}  status={s['status']}", flush=True)
    rest(d.rpc, "/stop_mining", {})
    rec[name] = {"start_mining": r, "info_at_start": {k: info.get(k) for k in
                 ("synchronized", "height", "status", "outgoing_connections_count",
                  "incoming_connections_count", "busy_syncing", "target_height")},
                 "samples": samples,
                 "first_nonzero_s": next((s["t"] for s in samples if (s["speed"] or 0) > 0), None),
                 "max_speed": max([(s["speed"] or 0) for s in samples] or [0])}


def main():
    os.makedirs(L.ROOT, exist_ok=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    gts = int(time.time())
    pa, p1, p2 = PORT, PORT + 10, PORT + 20
    da = start("cap_atk", pa, pa + 1, [p1, p2], gts)
    d1 = start("cap_h1", p1, p1 + 1, [pa, p2], gts)
    d2 = start("cap_h2", p2, p2 + 1, [pa, p1], gts)
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "genesis_ts": gts}
    try:
        for d in (da, d1, d2):
            ok = d.wait_synced(60)
            print(f"wait_synced({d.tag}) -> {ok}", flush=True)
        probe("h1_first", d1, rec)
        time.sleep(0.5)
        probe("h2_second", d2, rec)
        # and now h1 AGAIN, to separate "first measured" from "is h1"
        time.sleep(0.5)
        probe("h1_again", d1, rec)
    finally:
        for d in (d2, d1, da):
            try: d.stop()
            except Exception: pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print(f"\nwritten to {OUT}", flush=True)
    for k in ("h1_first", "h2_second", "h1_again"):
        if k in rec:
            print(f"{k:12} start_status={rec[k]['start_mining'].get('status')!r:24} "
                  f"max_speed={rec[k]['max_speed']}  first_nonzero_s={rec[k]['first_nonzero_s']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
