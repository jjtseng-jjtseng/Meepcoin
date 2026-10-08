#!/usr/bin/env python3
"""Task 5 — live confirmation of difficulty candidates A and B on top of T1+T2.

Three binaries, each built from the same tree with one patch difference, are run against fresh
automatic-difficulty chains (`--fixed-difficulty 0`, so every difficulty is the daemon's own):

    T1+T2 only          bin/meepcoind
    T1+T2 + candidate A bin/meepcoind.candA     2x upward cap, heights 1-30
    T1+T2 + candidate B bin/meepcoind.candB     5 s per included interval aggregate span floor

Scenarios per binary:
    honest, internal miner, 1 thread    -- low launch hashrate
    honest, internal miner, 8 threads   -- higher launch hashrate
    adaptive attacker to height 200     -- lowest legal / maximum legal future, alternating,
                                           with "lowest legal" computed under the T1+T2 rule

Hashrate is varied by miner thread count, which is a real but coarse proxy for launch hashrate on a
single host. Simulation covers the 0.001x-1000x range; this confirms direction, not magnitude.

LOCALHOST / PRIVATE THROWAWAY CHAINS. Dev/test coins with no monetary value.
"""
import json, os, subprocess, sys, time

HOME = os.path.expanduser("~")
BINS = [("T1+T2 only", os.path.join(HOME, "meepcoin-node/build/release/bin/meepcoind")),
        ("T1+T2 + candidate A", os.path.join(HOME, "meepcoin-node/build/release/bin/meepcoind.candA")),
        ("T1+T2 + candidate B", os.path.join(HOME, "meepcoin-node/build/release/bin/meepcoind.candB"))]
HONEST_BUDGET = int(os.environ.get("MEEP_HONEST_BUDGET", "240"))
REPORT = "docs/LIVE_AB.md"
lines = []
def say(s=""):
    print(s, flush=True)
    lines.append(s)


def sha(p):
    try:
        return subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]
    except Exception:
        return "?"


def honest_run(binpath, threads, port, budget):
    os.environ["MEEP_DAEMON"] = binpath
    import importlib
    import live_median_boundary as L
    importlib.reload(L)
    d = L.Daemon(f"ab_h{port}", port, port + 1, fixed_diff=0)
    traj, t0 = [], time.time()
    try:
        r = L.rest(d.rpc, "/start_mining", {"miner_address": L.ADDR, "threads_count": threads,
                                            "do_background_mining": False, "ignore_battery": True})
        if r.get("status") != "OK":
            raise RuntimeError(f"start_mining refused: {r}")
        seen = 1
        while time.time() - t0 < budget:
            h = d.height()
            if h > seen:
                for ht in range(seen, h):
                    hdr = L.rpc(d.rpc, "get_block_header_by_height",
                                {"height": ht})["result"]["block_header"]
                    traj.append((ht, int(hdr["difficulty"]), int(hdr["timestamp"])))
                seen = h
            else:
                time.sleep(0.3)
        final_diff = int(d.template()["difficulty"])
        final_h = d.height()
    finally:
        try: L.rest(d.rpc, "/stop_mining", {})
        except Exception: pass
        d.stop()
    return traj, final_h, final_diff


def attack_run(binpath, port, target_h=200):
    os.environ["MEEP_DAEMON"] = binpath
    import importlib
    import live_median_boundary as L
    importlib.reload(L)
    FTL, W = 7200, L.TS_WINDOW
    d = L.Daemon(f"ab_a{port}", port, port + 1, fixed_diff=0)
    traj, rejected = [], 0
    try:
        while d.height() <= target_h:
            ch = d.height()
            t = d.template()
            diff = int(t["difficulty"])
            parent_h = ch - 1
            lo = max(0, parent_h - (W - 1))
            win = d.timestamps(lo, parent_h)
            med = L.epee_median(win) if win else 0
            now = int(time.time())
            ts = (now + FTL - 5) if ch % 2 == 0 else med      # lowest legal under T1+T2
            ok = False
            for i in range(300):
                ok, err, _ = d.submit(L.rebuild(t["blocktemplate_blob"], ts=ts,
                                                nonce=ch * 100003 + i))
                if ok:
                    break
            traj.append((ch, diff, ts, ok))
            if not ok:
                rejected += 1
                if rejected > 3:
                    break
            else:
                rejected = 0
        final_h, final_diff = d.height(), int(d.template()["difficulty"])
    finally:
        d.stop()
    return traj, final_h, final_diff


def main():
    say("# MeepCoin — Live Confirmation of Difficulty Candidates A and B (task 5)")
    say()
    say("> **ANALYSIS ONLY.** Fresh throwaway chains with REAL automatic difficulty. Candidates are")
    say("> built on experimental child branches and are not adopted. The preserved database and")
    say("> wallets are untouched. Dev/test coins with no monetary value.")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- Honest mining budget per run: {HONEST_BUDGET} s")
    say()
    say("| build | binary sha256 |")
    say("|---|---|")
    for name, p in BINS:
        say(f"| {name} | `{sha(p)}` |")
    say()
    say("Hashrate is varied by miner thread count -- a real but coarse proxy on one host. The")
    say("0.001x to 1000x sweep lives in the simulation; this run confirms direction, not magnitude.")
    say()

    port = 27500
    say("## Honest launch")
    say()
    say("| build | threads | blocks mined | peak difficulty | height of peak | final difficulty |")
    say("|---|---|---|---|---|---|")
    honest = {}
    for name, p in BINS:
        for th in (1, 8):
            try:
                traj, fh, fd = honest_run(p, th, port, HONEST_BUDGET)
                port += 10
                pk = max((d for _, d, _ in traj), default=0)
                pkh = next((h for h, d, _ in traj if d == pk), 0)
                honest[(name, th)] = traj
                say(f"| {name} | {th} | {len(traj)} | {pk} | {pkh} | {fd} |")
            except Exception as e:
                say(f"| {name} | {th} | — | — | — | ERROR `{type(e).__name__}: {e}` |")
                port += 10
    say()

    say("### Difficulty by height, honest, 8 threads")
    say()
    hdr = "| height | " + " | ".join(n for n, _ in BINS) + " |"
    say(hdr); say("|" + "---|" * (len(BINS) + 1))
    maxlen = max((len(honest.get((n, 8), [])) for n, _ in BINS), default=0)
    for i in range(min(16, maxlen)):
        cells = []
        for n, _ in BINS:
            t = honest.get((n, 8), [])
            cells.append(str(t[i][1]) if i < len(t) else "—")
        say(f"| {i} | " + " | ".join(cells) + " |")
    say()

    say("## Adaptive attacker: alternating lowest-legal / maximum-legal-future")
    say()
    say("The attacker computes its lowest legal timestamp under the **T1+T2** rule, so it is not")
    say("handicapped by modelling the old rule.")
    say()
    say("| build | blocks accepted | final height | final difficulty | difficulty pinned near 1? |")
    say("|---|---|---|---|---|")
    atk = {}
    for name, p in BINS:
        try:
            traj, fh, fd = attack_run(p, port)
            port += 10
            atk[name] = traj
            acc = sum(1 for _, _, _, ok in traj if ok)
            pinned = sum(1 for _, d, _, ok in traj if ok and d <= 10)
            frac = (100.0 * pinned / acc) if acc else 0
            say(f"| {name} | {acc} | {fh} | {fd} | **{frac:.0f}% of accepted blocks at difficulty "
                f"<= 10** |")
        except Exception as e:
            say(f"| {name} | — | — | — | ERROR `{type(e).__name__}: {e}` |")
            port += 10
    say()
    say("_Dev/test coins on private localhost chains. No monetary value._")

    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
