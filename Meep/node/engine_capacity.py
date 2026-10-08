#!/usr/bin/env python3
"""Hash-bound capacity of the EXACT external mining engine, measured where it is hash-bound.

Four quantities must never be mixed, and this measures only the first:

  1 capacity        MeepHash attempts/s when every attempt fails proof-of-work, i.e. the miner is
                    hash-bound rather than waiting for templates. Measured with the same
                    template -> rebuild -> submit_block path the experiment uses.
  2 cadence         low-difficulty candidate rate, template->submit round trips per second. At
                    difficulty ~1 nearly every attempt wins, so cadence measures the round trip,
                    NOT hashing.
  3 occupancy       share of the rolling 60-block timestamp-median window.
  4 accepted work   cumulative difficulty of a producer's blocks on a given node's canonical chain.

To force the hash-bound regime without a consensus bypass, this mines a throwaway chain up with the
same engine until the tip difficulty is high, then measures attempts/s against a template whose
difficulty is far above one attempt per block.

NON-EVIDENCE: a harness calibration, not a protocol result.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rebuild

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
SNAP = os.path.expanduser("~/.meepcoin-lowdiff/snap_src")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 49000))
TARGET_D = int(ARG.get("--target-difficulty", 2000))
MEASURE_S = int(ARG.get("--measure", 45))
CLIMB_S = int(ARG.get("--climb", 180))
OUT = ARG.get("--out", "docs/round2/engine_capacity.json")


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    gts = json.load(open("docs/lowdiff/snapshot.json"))["snapshot_build"]["genesis_ts"]
    os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
    d = os.path.expanduser("~/.meepcoin-lowdiff/engine_cap")
    if os.path.isdir(d):
        shutil.rmtree(d)
    subprocess.run(["cp", "-a", "--sparse=always", SNAP, d], check=True)
    tn = os.path.join(d, "testnet")
    for sub in os.listdir(tn):
        q = os.path.join(tn, sub, "p2pstate.bin")
        if os.path.exists(q):
            os.remove(q)
    dm = L.Daemon("engine_cap", PORT, PORT + 1, fixed_diff=0, offline=True, wipe=False,
                  data_dir=d)
    rec = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "label": "NON-EVIDENCE harness calibration",
           "engine": "external template -> rebuild -> submit_block (node/sym_miner.py path)",
           "binary": BIN, "target_difficulty": TARGET_D}
    try:
        dm.wait_synced(60)
        # ---- climb: same engine, unrestricted, until the tip is hard enough to be hash-bound ----
        t0 = time.time()
        n = 0
        climb = []
        while time.time() - t0 < CLIMB_S:
            t = dm.template()
            diff = int(t["difficulty"])
            if diff >= TARGET_D:
                break
            ch = dm.height()
            found = False
            for i in range(4000):
                r = dm.submit_detailed(rebuild(t["blocktemplate_blob"],
                                               nonce=(n * 7919 + i) & 0xFFFFFFFF))
                n += 1
                if r["outcome"] == "ACCEPTED":
                    found = True
                    break
                if time.time() - t0 > CLIMB_S:
                    break
            climb.append({"height": ch, "template_difficulty": diff, "found": found})
        t = dm.template()
        rec["climb"] = {"seconds": round(time.time() - t0, 1), "attempts": n,
                        "final_template_difficulty": int(t["difficulty"]),
                        "height": dm.height()}
        # ---- measure: every attempt must FAIL, so the loop is hash-bound ----
        diff = int(t["difficulty"])
        attempts, accepted = 0, 0
        t1 = time.time()
        while time.time() - t1 < MEASURE_S:
            r = dm.submit_detailed(rebuild(t["blocktemplate_blob"],
                                           nonce=(0x5000000 + attempts) & 0xFFFFFFFF))
            attempts += 1
            if r["outcome"] == "ACCEPTED":
                accepted += 1
                t = dm.template()
                diff = int(t["difficulty"])
        dur = time.time() - t1
        # A miner that mines its own chain cannot be driven past its OWN equilibrium difficulty
        # (rate x 60 s target): the difficulty algorithm follows it up and then holds. So an
        # absolute "accepted <= 1" test is unsatisfiable here by construction -- at equilibrium the
        # engine wins about one block per target interval no matter how long it runs. What matters
        # for a capacity figure is the FRACTION of attempts that had to do full work, so that is
        # what is reported, alongside the strict flag which is left visible even when it is False.
        frac = 1.0 - (accepted / attempts if attempts else 1.0)
        rec["capacity"] = {
            "template_difficulty": diff, "attempts": attempts, "seconds": round(dur, 2),
            "attempts_per_s": round(attempts / dur, 3), "accepted_during_measurement": accepted,
            "hash_bound_fraction": round(frac, 5),
            "hash_bound": bool(diff >= 1000 and frac >= 0.99),
            "strict_flag_accepted_le_1": bool(diff >= 1000 and accepted <= 1),
            "equilibrium_note": "difficulty converges to approximately attempts_per_s x 60; a "
                                "single self-mining engine cannot exceed that, so a higher target "
                                "difficulty is unreachable rather than merely slow to reach",
            "definition": "MeepHash attempts/s with the same external engine; each attempt is one "
                          "MeepHash computed by the daemon inside submit_block validation",
            "caveat": "this is quantity 1 (capacity) ONLY. It must never be divided into, or "
                      "compared with, a low-difficulty cadence figure."}
    finally:
        try: dm.stop(clean_wait=20.0)
        except Exception: pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    c = rec.get("capacity", {})
    print(f"climb: {rec['climb']}")
    print(f"capacity: {c.get('attempts_per_s')} attempts/s at difficulty "
          f"{c.get('template_difficulty')}  hash_bound={c.get('hash_bound')} "
          f"(fraction {c.get('hash_bound_fraction')}, "
          f"{c.get('accepted_during_measurement')} accepted of {c.get('attempts')})")
    print(f"written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
