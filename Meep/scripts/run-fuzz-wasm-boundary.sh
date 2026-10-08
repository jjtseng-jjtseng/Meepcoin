#!/usr/bin/env bash
# Final clean 4-hour fuzz run for the last outstanding target (v1_wasm_boundary).
#
# Run under CLEAN CONDITIONS: no Monero mining, no other heavy workloads. Earlier attempts were
# either killed by WSL teardown between agent sessions or ran concurrently with Monero mining
# (which depressed exec/s); those runs are archived as *.contaminated and are NOT used.
#
# Launch detached from Windows so a WSL teardown cannot kill it:
#   Start-Process wsl.exe -ArgumentList @("-e","bash","/mnt/c/Users/tseng/meepcoin/scripts/run-fuzz-wasm-boundary.sh") -WindowStyle Hidden
set -u
cd /mnt/c/Users/tseng/meepcoin/meepow || exit 1

T=v1_wasm_boundary
SECS=14400
LOG=fuzz/logs/$T.log
META=fuzz/logs/$T.meta
mkdir -p fuzz/logs fuzz/artifacts "fuzz/corpora/$T"

{
  echo "target=$T"
  echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "start_epoch=$(date +%s)"
  echo "corpus_files_before=$(ls -1 fuzz/corpora/$T 2>/dev/null | wc -l)"
  echo "seconds_requested=$SECS"
  echo "sanitizers=address,undefined,fuzzer"
  echo "conditions=clean: no Monero mining, no other heavy workloads"
} > "$META"

./build/fuzzer/fuzz_$T "fuzz/corpora/$T" \
  -max_total_time=$SECS -print_final_stats=1 -rss_limit_mb=4096 \
  -artifact_prefix="fuzz/artifacts/${T}_" > "$LOG" 2>&1
rc=$?

{
  echo "exit_code=$rc"
  echo "end_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "end_epoch=$(date +%s)"
  echo "corpus_files_after=$(ls -1 fuzz/corpora/$T 2>/dev/null | wc -l)"
  echo "crash_artifacts=$(ls -1 fuzz/artifacts 2>/dev/null | grep -c "^${T}_" || true)"
} >> "$META"
