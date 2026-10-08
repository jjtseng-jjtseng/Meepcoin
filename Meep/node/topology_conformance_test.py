#!/usr/bin/env python3
"""Conformance test for topology enforcement, run before any STAR measurement.

The bug this guards against: peers were configured as a full mesh regardless of --topology, and the
STAR check only asked whether the two hub links existed. A STAR run could therefore form all three
edges and still be reported as a STAR.

Three live cases, each with real daemons:

    A  mesh peer config, checked as full_mesh  -> must PASS  (3 links, nothing forbidden)
    B  star peer config, checked as star       -> must PASS  (exactly 2 links, spoke link absent)
    C  mesh peer config, checked as star       -> must FAIL  (h2<->atk present and forbidden)

Case C is the one that matters: it proves the checker rejects an extra edge instead of ignoring it.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
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
PORT0 = int(ARG.get("--port", 43000))
WAIT = int(ARG.get("--wait", 90))
OUT = ARG.get("--out", "docs/round2/topology_conformance_test.json")


def peer_config(kind):
    """Exactly the mapping symmetric_series.py uses."""
    if kind == "mesh":
        return {n: [o for o in NAMES if o != n] for n in NAMES}
    hub = NAMES[0]
    cfg = {hub: [o for o in NAMES if o != hub]}
    for o in NAMES:
        if o != hub:
            cfg[o] = [hub]
    return cfg


def live_case(tag, port, cfg_kind, check_as):
    gts = json.load(open("docs/lowdiff/snapshot.json"))["snapshot_build"]["genesis_ts"]
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    p2p = {n: port + 10 * i for i, n in enumerate(NAMES)}
    rpcp = {n: p2p[n] + 1 for n in NAMES}
    cfg = peer_config(cfg_kind)
    ds = {}
    try:
        for n in NAMES:
            d = os.path.join(ROOT, f"conf_{tag}_{n}")
            if os.path.isdir(d):
                shutil.rmtree(d)
            subprocess.run(["cp", "-a", "--sparse=always", SNAP, d], check=True)
            tn = os.path.join(d, "testnet")
            for sub in os.listdir(tn):
                q = os.path.join(tn, sub, "p2pstate.bin")
                if os.path.exists(q):
                    os.remove(q)
            extra = []
            for o in cfg[n]:
                extra += ["--add-exclusive-node", f"127.0.0.1:{p2p[o]}"]
            ds[n] = L.Daemon(f"conf_{tag}_{n}", p2p[n], rpcp[n], fixed_diff=0, offline=False,
                             extra=extra, wipe=False, data_dir=d)
            time.sleep(5)
        nodes = {n: (rpcp[n], p2p[n]) for n in NAMES}
        # give the network time to settle before judging, so a PASS is not just an early snapshot
        ok, snap, hist = T.wait_for(nodes, check_as, timeout=WAIT, poll=4.0)
        time.sleep(10)
        final = T.snapshot(nodes)
        conf = T.conformance(final, NAMES, check_as)
        return {"case": tag, "peer_config": cfg_kind, "checked_as": check_as,
                "configured": cfg, "links": final["undirected_links"],
                "required": conf["required"], "forbidden": conf["forbidden"],
                "missing": conf["missing"], "forbidden_present": conf["forbidden_present"],
                "conformant": conf["conformant"],
                "wait_for_returned": ok,
                "adjacency": {n: {o: [r["direction"] for r in rs] for o, rs in v.items()}
                              for n, v in final["adjacency"].items()},
                "peer_ids": final["peer_id_map"]}
    finally:
        for n in reversed(NAMES):
            if n in ds:
                try: ds[n].stop()
                except Exception: pass


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    cases = [("A_mesh_as_mesh", "mesh", "full_mesh", True),
             ("B_star_as_star", "star", "star", True),
             ("C_mesh_as_star", "mesh", "star", False)]
    out, port, failures = [], PORT0, []
    for tag, cfg_kind, check_as, expect in cases:
        print(f"--- {tag}: peers={cfg_kind} checked_as={check_as} expect_conformant={expect} ---",
              flush=True)
        try:
            r = live_case(tag, port, cfg_kind, check_as)
        except Exception as e:
            r = {"case": tag, "error": f"{type(e).__name__}: {e}"}
        r["expected_conformant"] = expect
        r["test_passed"] = (r.get("conformant") == expect)
        out.append(r)
        print(f"    links={r.get('links')}", flush=True)
        print(f"    missing={r.get('missing')} forbidden_present={r.get('forbidden_present')} "
              f"conformant={r.get('conformant')} -> test {'PASS' if r['test_passed'] else 'FAIL'}",
              flush=True)
        if not r["test_passed"]:
            failures.append(tag)
        port += 100
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "cases": out, "all_passed": not failures}, f, indent=1)
    print(f"\nconformance test: {'ALL PASS' if not failures else 'FAILED: ' + str(failures)}")
    print(f"written to {OUT}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
