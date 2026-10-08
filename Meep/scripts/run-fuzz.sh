#!/usr/bin/env bash
# Build and run the libFuzzer targets. Default: 10-minute smoke per target (the Phase 1A gate).
# A crash or sanitizer finding writes an artifact under meepow/fuzz/artifacts/ and fails the gate.
#
# Usage: scripts/run-fuzz.sh [seconds_per_target]
#   Reproduce a crash: ./meepow/build/fuzzer/fuzz_<target> meepow/fuzz/artifacts/<crash-file>
set -euo pipefail
SECS="${1:-600}"
cd "$(dirname "$0")/../meepow"
cmake --preset fuzzer
cmake --build --preset fuzzer
mkdir -p fuzz/artifacts
rc=0
for t in program_decode addressing vm_exec target_conv pool_msgs; do
  echo "== fuzz $t (${SECS}s) =="
  if ! ./build/fuzzer/fuzz_$t fuzz/corpora/$t -max_total_time="$SECS" \
        -artifact_prefix="fuzz/artifacts/${t}_"; then
    echo "FUZZ FAILURE in $t"; rc=1
  fi
done
exit $rc
