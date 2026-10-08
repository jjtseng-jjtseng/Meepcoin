#!/usr/bin/env bash
# Canonical native run (pipe into `ubuntu:24.04`): build, test, verify determinism, benchmark.
#   docker run --rm -i -v "$REPO:/src:ro" ubuntu:24.04 bash -s < scripts/canonical-native.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential clang cmake ninja-build >/dev/null
rm -rf /work && cp -r /src /work && rm -rf /work/meepow/build /work/meepow/wasm/obj
cd /work/meepow
gcc --version | head -1; clang --version | head -1; cmake --version | head -1
cmake --preset release   && cmake --build --preset release   && ctest --preset release   --output-on-failure
cmake --preset asan-ubsan && cmake --build --preset asan-ubsan && ctest --preset asan-ubsan --output-on-failure
mkdir -p /tmp/vec
./build/release/meepow-vectorgen /tmp/vec
if diff -q /tmp/vec/vectors_fast.json vectors/vectors_fast.json >/dev/null \
   && diff -q /tmp/vec/vectors_dev.json vectors/vectors_dev.json >/dev/null; then
  echo "VECTORS_IDENTICAL_TO_COMMITTED"
else
  echo "VECTORS_DIFFER"; exit 1
fi
./build/release/meepow-bench --param dev --hashes 300 --csv | tail -1
cmake --preset optimized-native && cmake --build --preset optimized-native
./build/optimized/meepow-bench --param dev --hashes 300 --csv | tail -1
echo CANONICAL_NATIVE_DONE
