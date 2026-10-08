#!/usr/bin/env python3
# Rigorous native confirmation for frozen v1 S3x400 (CONFIRMATION_PLAN_V1).
# Pins to one core, warms up, runs multiple randomized sessions of portable vs optimized, pools
# per-hash samples, and reports median with 95% bootstrap CI. Explains portable-vs-optimized.
import os, subprocess, random, statistics, glob, sys

CORE = os.environ.get("CONFIRM_CORE", "2")
SESSIONS = int(os.environ.get("CONFIRM_SESSIONS", "5"))
TIMED = int(os.environ.get("CONFIRM_TIMED", "800"))
WARMUP = int(os.environ.get("CONFIRM_WARMUP", "200"))
ROOT = "/mnt/c/Users/tseng/meepcoin/meepow"
BINS = {"portable": f"{ROOT}/build/release/meepow-v1-confirm",
        "optimized": f"{ROOT}/build/optimized/meepow-v1-confirm"}

def cpu_info():
    info = {}
    try:
        with open("/proc/cpuinfo") as f:
            for l in f:
                if l.startswith("cpu MHz"): info.setdefault("MHz", l.split(":")[1].strip())
        gov = glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
        if gov:
            info["governor"] = open(gov[0]).read().strip()
        temps = glob.glob("/sys/class/thermal/thermal_zone*/temp")
        if temps:
            info["temp_C"] = f"{int(open(temps[0]).read())/1000:.1f}"
    except Exception as e:
        info["note"] = f"limited under WSL ({e})"
    return info

def run(variant, sess):
    dump = f"/tmp/confirm_{variant}_{sess}.txt"
    cmd = ["taskset", "-c", CORE, BINS[variant], "--warmup", str(WARMUP), "--timed", str(TIMED), "--dump", dump]
    out = subprocess.run(cmd, capture_output=True, text=True)
    samples = [float(x) for x in open(dump).read().split()]
    return samples, out.stdout.strip()

def bootstrap_ci(data, stat=statistics.median, n=2000, alpha=0.05):
    boots = []
    for _ in range(n):
        boots.append(stat(random.choices(data, k=len(data))))
    boots.sort()
    lo = boots[int(n*alpha/2)]; hi = boots[int(n*(1-alpha/2))]
    return stat(data), lo, hi

def main():
    for v, b in BINS.items():
        if not os.path.exists(b):
            print(f"MISSING build: {b}", file=sys.stderr); sys.exit(1)
    print("CPU:", cpu_info())
    print(f"core={CORE} sessions={SESSIONS} warmup={WARMUP} timed={TIMED}")
    pooled = {"portable": [], "optimized": []}
    per_session_p50 = {"portable": [], "optimized": []}
    for s in range(SESSIONS):
        order = ["portable", "optimized"]; random.shuffle(order)
        for v in order:
            samples, summary = run(v, s)
            pooled[v].extend(samples)
            per_session_p50[v].append(statistics.median(samples))
            print(f"  session {s} [{v}]: {summary}")
    print()
    res = {}
    for v in ("portable", "optimized"):
        med, lo, hi = bootstrap_ci(pooled[v])
        res[v] = med
        print(f"{v}: pooled median={med:.4f} ms  95% CI [{lo:.4f}, {hi:.4f}]  "
              f"per-session p50 range [{min(per_session_p50[v]):.4f}, {max(per_session_p50[v]):.4f}]  "
              f"H/s={1000/med:.1f}")
    fastest = min(res.values())  # fastest VALID native (lower ms)
    fv = min(res, key=res.get)
    print(f"\nFastest valid native = {fv} @ {fastest:.4f} ms ({1000/fastest:.1f} H/s)")
    print(f"portable/optimized median ratio = {res['portable']/res['optimized']:.3f} "
          f"(>1 => optimized faster; ~1 => memory-latency-bound, BLAKE3 SIMD irrelevant)")

if __name__ == "__main__":
    main()
