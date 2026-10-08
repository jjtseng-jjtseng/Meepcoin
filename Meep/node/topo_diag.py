#!/usr/bin/env python3
"""Why does the third P2P link fail to form when nodes start from SNAPSHOT COPIES?

topology_probe.py formed a full mesh from empty data directories, but symmetric_series.py -- which
starts each node from a copy of the low-difficulty snapshot -- fails deterministically with the
atk<->h2 link missing, across three retries. The difference must be isolated before any measured
run, because a missing link is exactly the confounder this round exists to remove.

Varies snapshot-vs-fresh, --hide-my-port, and staggered-vs-simultaneous start, and prints the full
directed adjacency for each.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
import topology as T

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ROOT = os.path.expanduser("~/.meepcoin-lowdiff")
SNAP = os.path.join(ROOT, "snap_src")
NAMES = ["h1", "h2", "atk"]
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT0 = int(ARG.get("--port", 40100))
WAIT = int(ARG.get("--wait", 90))
OUT = ARG.get("--out", "docs/round2/topo_diag.json")


def run(tag, port, hide, stagger, from_snap):
    gts = json.load(open("docs/lowdiff/snapshot.json"))["snapshot_build"]["genesis_ts"]
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    p2p = {n: port + 10 * i for i, n in enumerate(NAMES)}
    rpcp = {n: p2p[n] + 1 for n in NAMES}
    ds = {}
    try:
        for n in NAMES:
            d = os.path.join(ROOT, f"diag_{tag}_{n}")
            if os.path.isdir(d):
                shutil.rmtree(d)
            if from_snap:
                subprocess.run(["cp", "-a", "--sparse=always", SNAP, d], check=True)
                tn = os.path.join(d, "testnet")
                for sub in os.listdir(tn):
                    q = os.path.join(tn, sub, "p2pstate.bin")
                    if os.path.exists(q):
                        os.remove(q)
            extra = []
            for o in NAMES:
                if o != n:
                    extra += ["--add-exclusive-node", f"127.0.0.1:{p2p[o]}"]
            ds[n] = L.Daemon(f"diag_{tag}_{n}", p2p[n], rpcp[n], fixed_diff=0, offline=False,
                             extra=extra, wipe=not from_snap, hide_port=hide, data_dir=d)
            if stagger:
                time.sleep(6)
        nodes = {n: (rpcp[n], p2p[n]) for n in NAMES}
        ok, snap, hist = T.wait_for(nodes, "full_mesh", timeout=WAIT, poll=3.0)
        adj = {n: {o: [r["direction"] for r in rs] for o, rs in v.items()}
               for n, v in snap["adjacency"].items()}
        print(f"  mesh={ok}  links={snap['undirected_links']}  "
              f"counts={snap['raw_connection_counts']}", flush=True)
        for n in NAMES:
            print(f"     {n}: " + (", ".join(f"{o}({'/'.join(d)})"
                                             for o, d in adj.get(n, {}).items()) or "(none)"),
                  flush=True)
        if snap["unresolved"]:
            print(f"     unresolved: {snap['unresolved']}", flush=True)
        return {"tag": tag, "hide_my_port": hide, "staggered": stagger, "from_snapshot": from_snap,
                "mesh": ok, "links": snap["undirected_links"], "adjacency": adj,
                "counts": snap["raw_connection_counts"], "unresolved": snap["unresolved"],
                "missing": snap.get("missing_links")}
    finally:
        for n in reversed(NAMES):
            if n in ds:
                try: ds[n].stop()
                except Exception: pass


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    cases = [("snap_hide_stag", True, True, True),
             ("snap_hide_simul", True, False, True),
             ("snap_nohide_stag", False, True, True),
             ("fresh_hide_stag", True, True, False)]
    out, port = [], PORT0
    for tag, hide, stag, snap in cases:
        print(f"--- {tag}  (hide_my_port={hide} staggered={stag} from_snapshot={snap}) ---",
              flush=True)
        try:
            out.append(run(tag, port, hide, stag, snap))
        except Exception as e:
            print(f"   ERROR {type(e).__name__}: {e}", flush=True)
            out.append({"tag": tag, "error": f"{type(e).__name__}: {e}"})
        port += 100
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "cases": out}, f, indent=1)
    print(f"\nmesh formed in: {[c['tag'] for c in out if c.get('mesh')] or 'NONE'}")
    print(f"written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
