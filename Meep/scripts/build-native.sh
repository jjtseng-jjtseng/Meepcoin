#!/usr/bin/env bash
# Configure, build, and test the native release + ASan/UBSan presets. Run from WSL/Linux.
set -euo pipefail
cd "$(dirname "$0")/../meepow"
for p in release asan-ubsan; do
  echo "== $p =="
  cmake --preset "$p"
  cmake --build --preset "$p"
  ctest --preset "$p" --output-on-failure
done
