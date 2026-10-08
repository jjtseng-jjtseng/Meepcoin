#!/usr/bin/env python3
"""Find a daemon configuration that reliably forms a three-edge FULL MESH.

Earlier runs recorded connection counts h1=2, h2=1, atk=1 -- a star, not a mesh -- while the
harness assumed a mesh. Before anything is measured again, establish empirically which start-up
configuration produces all three undirected links, proven by directed adjacency rather than counts.

Variants tried:
    hideport_simultaneous   current behaviour: --hide-my-port, all three started at once
    nohide_simultaneous     same but advertising the real listening port
    nohide_staggered        real port, started one at a time so each dials those already up
    nohide_staggered_seed   as above, but peers passed via --seed-node as well

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
import topology as T

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 38000))
WAIT = int(ARG.get("--wait", 75))
OUT = ARG.get("--out", "docs/round2/topology_probe.json")
NAMES = ["h1", "h2", "atk"]


def variant(tag, port, hide, stagger, seed):
    gts = int(time.time())
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    p2p = {n: port + 10 * i for i, n in enumerate(NAMES)}
    rpcp = {n: p2p[n] + 1 for n in NAMES}
    ds = {}
    try:
        for n in NAMES:
            extra = []
            for o in NAMES:
                if o != n:
                    extra += ["--add-exclusive-node", f"127.0.0.1:{p2p[o]}"]
                    if seed:
                        extra += ["--seed-node", f"127.0.0.1:{p2p[o]}"]
            ds[n] = L.Daemon(f"topo_{tag}_{n}", p2p[n], rpcp[n], fixed_diff=0, offline=False,
                             extra=extra, hide_port=hide,
                             data_dir=os.path.join(L.ROOT, f"topo_{tag}_{n}"))
            if stagger:
                time.sleep(6.0)
        nodes = {n: (rpcp[n], p2p[n]) for n in NAMES}
        ok, snap, hist = T.wait_for(nodes, "full_mesh", timeout=WAIT, poll=3.0)
        return {"variant": tag, "hide_my_port": hide, "staggered": stagger, "seed_node": seed,
                "full_mesh": ok, "links": snap["undirected_links"],
                "missing": snap.get("missing_links"), "counts": snap["raw_connection_counts"],
                "adjacency": {n: {o: [r["direction"] for r in rs] for o, rs in v.items()}
                              for n, v in snap["adjacency"].items()},
                "unresolved": snap["unresolved"], "history": hist[-4:],
                "argv_sample": ds[NAMES[0]].argv}
    finally:
        for n in reversed(NAMES):
            if n in ds:
                try: ds[n].stop()
                except Exception: pass


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    os.makedirs(L.ROOT, exist_ok=True)
    L.DAEMON = BIN
    variants = [("hideport_simultaneous", True, False, False),
                ("nohide_simultaneous", False, False, False),
                ("nohide_staggered", False, True, False),
                ("nohide_staggered_seed", False, True, True)]
    out = []
    p = PORT
    for tag, hide, stag, seed in variants:
        print(f"--- {tag} ---", flush=True)
        try:
            r = variant(tag, p, hide, stag, seed)
        except Exception as e:
            r = {"variant": tag, "error": f"{type(e).__name__}: {e}"}
        out.append(r)
        print(f"    full_mesh={r.get('full_mesh')}  links={r.get('links')}  "
              f"counts={r.get('counts')}  missing={r.get('missing')}", flush=True)
        if r.get("adjacency"):
            for n, v in r["adjacency"].items():
                print(f"      {n}: " + ", ".join(f"{o}({'/'.join(d)})" for o, d in v.items()),
                      flush=True)
        p += 100
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "variants": out}, f, indent=1)
    good = [r["variant"] for r in out if r.get("full_mesh")]
    print(f"\nfull-mesh variants: {good or 'NONE'}")
    print(f"written to {OUT}")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
