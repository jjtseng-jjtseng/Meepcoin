#!/usr/bin/env bash
# Regenerate + verify test vectors natively, then verify the same vectors under Node Wasm.
# Requires a prior native build (scripts/build-native.sh) and Wasm build (scripts/build-wasm.sh).
set -euo pipefail
cd "$(dirname "$0")/../meepow"
./build/release/meepow-vectorgen vectors
./build/release/meepow-kat vectors/vectors_fast.json vectors/vectors_dev.json
if command -v node >/dev/null 2>&1; then
  node wasm/run-vectors.mjs
else
  echo "node not on PATH; run 'node meepow/wasm/run-vectors.mjs' from an environment that has it"
fi
