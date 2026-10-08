#!/usr/bin/env python3
"""Read the genesis block timestamp straight out of each daemon binary.

The genesis timestamp is compiled in, so the authoritative value is the one the RUNNING DAEMON
reports for block 0 -- not whatever `cryptonote_config.h` happens to contain now. An earlier run
labelled itself from the config file and got it wrong; this exists so that never happens again.
"""
import os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L  # noqa: E402

BINS = sys.argv[1:] or ["meepcoind", "meepcoind.t4", "meepcoind.t4fresh", "meepcoind.baseline"]
BASE = os.path.expanduser("~/meepcoin-node/build/release/bin")

for name in BINS:
    path = os.path.join(BASE, name)
    if not os.path.exists(path):
        print(f"{name:24s} -> missing"); continue
    os.environ["MEEP_DAEMON"] = path
    import importlib
    importlib.reload(L)
    d = None
    try:
        d = L.Daemon("gprobe", 26990, 26991, fixed_diff=1)
        hdr = L.rpc(d.rpc, "get_block_header_by_height",
                    {"height": 0})["result"]["block_header"]
        ts = int(hdr["timestamp"])
        now = int(time.time())
        sha = subprocess.run(["sha256sum", path], capture_output=True, text=True).stdout.split()[0]
        print(f"{name:24s} -> genesis ts {ts}  age {now - ts:>9d} s "
              f"({(now - ts)/86400.0:8.3f} days)  hash {hdr['hash'][:16]}  bin {sha[:16]}")
    except Exception as e:
        print(f"{name:24s} -> ERROR {type(e).__name__}: {e}")
    finally:
        if d is not None:
            d.stop()
        time.sleep(1.0)
