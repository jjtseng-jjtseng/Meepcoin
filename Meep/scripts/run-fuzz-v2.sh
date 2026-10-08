#!/usr/bin/env bash
# Durable extended fuzz campaign for the FROZEN v2 candidate.
#
# Runs each target for SECS seconds (default 4 h) with ASan+UBSan (the `fuzzer` preset), writing
# CONTINUOUS per-target logs and a .meta file (start/end/exit) under meepow/fuzz/logs/ — inside the
# repo, so a tool/chat/WSL interruption cannot erase the evidence. Corpora are preserved in place.
#
# Usage: scripts/run-fuzz-v2.sh [seconds_per_target]
set -eu
SECS="${1:-14400}"
cd "$(dirname "$0")/../meepow"
LOGS=fuzz/logs
mkdir -p "$LOGS" fuzz/artifacts

# v2-specific targets + the parameter-boundary and wasm-export-boundary targets (v2 reuses the v1
# ParamSetV1 path via v2_ctx_create, so those two cover the v2 parameter/export boundaries as well).
TARGETS="v2_dataset v2_hash v2_backend v1_params v1_wasm_boundary"

for t in $TARGETS; do
  mkdir -p "fuzz/corpora/$t"
  {
    echo "target=$t"
    echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "start_epoch=$(date +%s)"
    echo "corpus_files_before=$(ls -1 fuzz/corpora/$t 2>/dev/null | wc -l)"
    echo "seconds_requested=$SECS"
    echo "sanitizers=address,undefined,fuzzer"
  } > "$LOGS/$t.meta"

  nohup sh -c "
    ./build/fuzzer/fuzz_$t fuzz/corpora/$t \
      -max_total_time=$SECS -print_final_stats=1 -rss_limit_mb=4096 \
      -artifact_prefix=fuzz/artifacts/${t}_ >> '$LOGS/$t.log' 2>&1
    rc=\$?
    {
      echo \"exit_code=\$rc\"
      echo \"end_utc=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
      echo \"end_epoch=\$(date +%s)\"
      echo \"corpus_files_after=\$(ls -1 fuzz/corpora/$t 2>/dev/null | wc -l)\"
      echo \"artifacts=\$(ls -1 fuzz/artifacts 2>/dev/null | grep -c '^${t}_' || true)\"
    } >> '$LOGS/$t.meta'
  " > /dev/null 2>&1 &
  echo "launched $t (pid $!)"
done
echo "all targets launched; logs: meepow/$LOGS/"
