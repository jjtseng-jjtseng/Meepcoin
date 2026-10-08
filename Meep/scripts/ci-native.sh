#!/usr/bin/env bash
# Canonical-container native CI: install pinned deps, build, test, verify vectors, smoke-fuzz.
# Intended to run inside the pinned Ubuntu image (see TOOLCHAIN.md), e.g.:
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 scripts/ci-native.sh
set -euo pipefail

if [ "${SKIP_APT:-0}" != "1" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq build-essential clang cmake ninja-build git >/dev/null
fi

cd meepow
cmake --preset release && cmake --build --preset release && ctest --preset release --output-on-failure
cmake --preset asan-ubsan && cmake --build --preset asan-ubsan && ctest --preset asan-ubsan --output-on-failure
./build/release/meepow-vectorgen vectors
./build/release/meepow-kat vectors/vectors_fast.json vectors/vectors_dev.json
# Short smoke-fuzz (gate uses 600s per target; CI default 60s for speed).
../scripts/run-fuzz.sh "${FUZZ_SECS:-60}"
