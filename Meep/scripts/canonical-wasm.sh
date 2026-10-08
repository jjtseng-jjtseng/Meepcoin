#!/usr/bin/env bash
# Canonical Wasm run (pipe into `emscripten/emsdk:6.0.3`): build the module, verify Node Wasm KAT.
#   docker run --rm -i -v "$REPO:/src:ro" emscripten/emsdk:6.0.3 bash -s < scripts/canonical-wasm.sh
set -euo pipefail
cp -r /src /work && rm -rf /work/meepow/wasm/obj /work/meepow/wasm/meepow.mjs /work/meepow/wasm/meepow.wasm
cd /work
emcc --version | head -1
node --version
bash meepow/wasm/build-wasm.sh
node meepow/wasm/run-vectors.mjs
echo CANONICAL_WASM_DONE
