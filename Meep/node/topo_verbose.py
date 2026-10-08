#!/usr/bin/env python3
"""One three-node start with verbose P2P logging, to see WHY the third link is not dialled.

connect_to_peerlist() calls try_to_connect_and_handshake_with_new_peer() for every exclusive peer
that is not already connected outbound, so a node with two exclusive peers should dial both. The
observed adjacency shows atk dialling nobody, so the dial is failing rather than not being
attempted. The net.p2p category is normally suppressed at the log settings the harness uses, which
is why this has been invisible.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
import topology as T
from live_median_boundary import rest

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ROOT = os.path.expanduser("~/.meepcoin-lowdiff")
NAMES = ["h1", "h2", "atk"]
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 40600))
WAIT = int(ARG.get("--wait", 75))
OUT = ARG.get("--out", "docs/round2/topo_verbose.json")
KEEP = ("connect", "Connect", "handshake", "Handshake", "peer", "Peer", "exclusive", "drop",
        "Drop", "ban", "Ban", "CONNECTION", "closed", "refus", "fail", "Fail", "timeout")


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    gts = json.load(open("docs/lowdiff/snapshot.json"))["snapshot_build"]["genesis_ts"]
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    p2p = {n: PORT + 10 * i for i, n in enumerate(NAMES)}
    rpcp = {n: p2p[n] + 1 for n in NAMES}
    ds, rec = {}, {"ports": p2p}
    try:
        for n in NAMES:
            d = os.path.join(ROOT, f"verb_{n}")
            if os.path.isdir(d):
                shutil.rmtree(d)
            extra = []
            for o in NAMES:
                if o != n:
                    extra += ["--add-exclusive-node", f"127.0.0.1:{p2p[o]}"]
            ds[n] = L.Daemon(f"verb_{n}", p2p[n], rpcp[n], fixed_diff=0, offline=False,
                             extra=extra, wipe=True, data_dir=d)
            # raise the P2P category specifically; the harness default hides it
            try:
                rest(ds[n].rpc, "/set_log_categories",
                     {"categories": "*:WARNING,global:INFO,net.p2p:DEBUG,net:INFO"})
            except Exception as e:
                print(f"  ! log categories on {n}: {e}", flush=True)
            time.sleep(4)
        nodes = {n: (rpcp[n], p2p[n]) for n in NAMES}
        ok, snap, hist = T.wait_for(nodes, "full_mesh", timeout=WAIT, poll=5.0)
        rec["mesh"] = ok
        rec["links"] = snap["undirected_links"]
        rec["adjacency"] = {n: {o: [r["direction"] for r in rs] for o, rs in v.items()}
                            for n, v in snap["adjacency"].items()}
        print(f"mesh={ok} links={snap['undirected_links']}", flush=True)
        for n in NAMES:
            print(f"  {n}: {rec['adjacency'].get(n)}", flush=True)
        rec["logs"] = {}
        for n in NAMES:
            lines = [l for l in ds[n].new_log() if any(k in l for k in KEEP)]
            rec["logs"][n] = lines[-120:]
            print(f"\n===== {n} ({p2p[n]}) : {len(lines)} p2p lines =====", flush=True)
            for l in lines[-22:]:
                print("   " + l[-165:], flush=True)
    finally:
        for n in reversed(NAMES):
            if n in ds:
                try: ds[n].stop()
                except Exception: pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print(f"\nwritten to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
