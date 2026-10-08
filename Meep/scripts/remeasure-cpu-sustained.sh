#!/usr/bin/env bash
# Sustained CPU re-measurement — fixes two defects in the previously reported figures:
#
#   (a) the 512.98 H/s full-device baseline was a 0.25 s BURST (128 nonces / 16 threads), which sits
#       entirely inside the CPU's turbo/thermal headroom;
#   (b) the 387.9 H/s sustained replacement came from a DIFFERENT BUILD (optimized-native, SIMD
#       BLAKE3, -march=native) than the 512.98 figure (release, portable BLAKE3). Portable BLAKE3
#       measured FASTER than optimized in this codebase, so the drop conflated two effects.
#
# This runs BOTH harnesses under BOTH presets so burst-vs-sustained and portable-vs-optimized are
# separable, producing (1) one defensible fastest-sustained CPU denominator for the GPU ratio and
# (2) a sustained-vs-sustained ratio for throughput gate 4.
#
# Run with NOTHING else heavy on the machine.
set -u
cd /mnt/c/Users/tseng/meepcoin/meepow || exit 1

THREADS=16
TRIALS=5
SECS=30
NH=16000          # full-memory T=16 runs >= 30 s at either build; attacker ~110 s

OUT=fuzz/logs/cpu_sustained_remeasure.txt
{
  echo "=== sustained CPU re-measurement ==="
  echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "threads=$THREADS trials=$TRIALS secs=$SECS nh=$NH"
  echo "conditions=clean: no Monero mining, no fuzzing, no other heavy workloads"
  echo
} > "$OUT"

for pair in "release:portable-BLAKE3" "optimized:optimized-BLAKE3+march=native"; do
  dir="${pair%%:*}"; label="${pair##*:}"
  echo "########## preset=$dir ($label) ##########" >> "$OUT"

  echo "--- sustained full-device miner, $TRIALS x ${SECS}s ---" >> "$OUT"
  for i in $(seq $TRIALS); do
    r=$(./build/$dir/meepow-v2-sustained $THREADS $SECS 2>&1 | grep -E "^RESULT")
    echo "trial$i: $r" >> "$OUT"
  done

  echo "--- throughput gate 4: full-memory vs 50% dataset budget, both sustained ---" >> "$OUT"
  ./build/$dir/meepow-v2-throughput $THREADS $NH 0 0 >> "$OUT" 2>&1
  echo >> "$OUT"
done

echo "end_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
echo "DONE" >> "$OUT"
