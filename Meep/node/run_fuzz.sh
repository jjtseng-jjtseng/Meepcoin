#!/usr/bin/env bash
# Post-freeze fuzz campaign over the existing 13 meepow targets.
# Each target gets a bounded wall-clock budget; corpora are grown in place.
set -u
M=/mnt/c/Users/tseng/meepcoin/meepow
B=$M/build/fuzzer
OUT=/tmp/fuzz_postfreeze
SECS=${1:-420}          # per-target seconds
mkdir -p "$OUT" "$M/fuzz/artifacts"

cd "$M"
COMMIT=$(git -C /mnt/c/Users/tseng/meepcoin rev-parse HEAD)
echo "commit: $COMMIT" | tee "$OUT/summary.txt"
echo "per-target budget: ${SECS}s" | tee -a "$OUT/summary.txt"
echo "sanitizer config: $(grep -o 'fsanitize=[a-z,]*' $M/CMakePresets.json | head -1)" \
  | tee -a "$OUT/summary.txt"
echo | tee -a "$OUT/summary.txt"
printf "%-28s %10s %12s %8s %8s %8s\n" target execs execs_per_s corpus crashes hangs \
  | tee -a "$OUT/summary.txt"

rebuild=0
for f in "$B"/fuzz_*; do
  [ -x "$f" ] || continue
  t=$(basename "$f")
  corp="$M/fuzz/corpora/${t#fuzz_}"
  mkdir -p "$corp"
  log="$OUT/$t.log"
  "$f" "$corp" -max_total_time="$SECS" -print_final_stats=1 \
       -artifact_prefix="$M/fuzz/artifacts/" > "$log" 2>&1
  rc=$?
  execs=$(grep -oP 'stat::number_of_executed_units:\s*\K[0-9]+' "$log" | tail -1)
  eps=$(grep -oP 'stat::average_exec_per_sec:\s*\K[0-9]+' "$log" | tail -1)
  crashes=$(grep -ac "ERROR: libFuzzer: deadly signal\|SUMMARY: .*Sanitizer" "$log" || true)
  hangs=$(grep -ac "ERROR: libFuzzer: timeout" "$log" || true)
  files=$(ls "$corp" 2>/dev/null | wc -l)
  printf "%-28s %10s %12s %8s %8s %8s\n" "$t" "${execs:-?}" "${eps:-?}" "$files" "$crashes" "$hangs" \
    | tee -a "$OUT/summary.txt"
done

echo | tee -a "$OUT/summary.txt"
arts=$(ls "$M/fuzz/artifacts" 2>/dev/null | wc -l)
echo "crash/hang artifacts on disk: $arts" | tee -a "$OUT/summary.txt"
if [ "$arts" != "0" ]; then ls -la "$M/fuzz/artifacts" | tee -a "$OUT/summary.txt"; fi
echo "FUZZ CAMPAIGN DONE" | tee -a "$OUT/summary.txt"
