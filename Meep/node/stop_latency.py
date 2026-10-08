#!/usr/bin/env python3
"""LD-H corroboration: measure how long a daemon actually takes to exit after `stop_daemon`.

The height-31 "hang" was diagnosed in docs/H31_DIAGNOSIS.md as harness shutdown accounting, not a
daemon defect: Daemon.stop() waited proc.wait(timeout=30) after every case, and with two daemons
per case that was 60 s of pure waiting per case across 11 heights x 15 cases.

While building the low-difficulty snapshot, stop_daemon failed to make the process exit even with a
45 s window on a 31-block OFFLINE chain, so the harness escalated to SIGTERM. That is worth an
exact number rather than an anecdote, because it is the root cause the diagnosis identified and it
also matters operationally for any future node deployment.

Measured per trial, with nothing else running:
    t_rpc     how long the stop_daemon RPC call itself takes
    t_exit    wall time from the RPC returning until the process is actually gone
    path      clean / terminated / killed

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_median_boundary as L
from live_median_boundary import rpc

BIN = os.path.expanduser("~/meepcoin-node/build/release/bin/meepcoind.expgen")
ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
PORT = int(ARG.get("--port", 37200))
TRIALS = int(ARG.get("--trials", 4))
WAIT = float(ARG.get("--wait", 60.0))
OUT = ARG.get("--out", "docs/lowdiff/stop_latency.json")


def main():
    os.makedirs(L.ROOT, exist_ok=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    L.DAEMON = BIN
    rec = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "binary": BIN, "max_wait_s": WAIT, "trials": []}
    for i in range(TRIALS):
        gts = int(time.time())
        os.environ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS"] = str(gts)
        d = L.Daemon(f"stoplat{i}", PORT + i * 4, PORT + i * 4 + 1, fixed_diff=0, offline=True,
                     data_dir=os.path.join(L.ROOT, f"stoplat{i}"))
        d.wait_synced(60)
        t0 = time.perf_counter()
        err = None
        try:
            rpc(d.rpc, "stop_daemon", timeout=10)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        t_rpc = time.perf_counter() - t0
        t1 = time.perf_counter()
        exited = None
        while time.perf_counter() - t1 < WAIT:
            if d.proc.poll() is not None:
                exited = time.perf_counter() - t1
                break
            time.sleep(0.05)
        path = "clean"
        if exited is None:
            path = "terminated"
            d.proc.terminate()
            try:
                d.proc.wait(timeout=10)
            except Exception:
                path = "killed"
                d.proc.kill()
                d.proc.wait(timeout=10)
        rec["trials"].append({"trial": i, "stop_daemon_rpc_s": round(t_rpc, 3),
                              "exit_after_rpc_s": round(exited, 3) if exited is not None else None,
                              "exited_within_max_wait": exited is not None,
                              "path": path, "rpc_error": err})
        print(f"trial {i}: rpc {t_rpc:.3f}s  exit "
              f"{('%.3fs' % exited) if exited is not None else f'NOT within {WAIT}s'}  "
              f"path={path}", flush=True)
    ex = [t["exit_after_rpc_s"] for t in rec["trials"] if t["exit_after_rpc_s"] is not None]
    rec["summary"] = {"n": len(rec["trials"]),
                      "exited_cleanly": len(ex),
                      "exit_s_min": min(ex) if ex else None,
                      "exit_s_median": round(statistics.median(ex), 3) if ex else None,
                      "exit_s_max": max(ex) if ex else None}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print(f"\n{rec['summary']}\nwritten to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
