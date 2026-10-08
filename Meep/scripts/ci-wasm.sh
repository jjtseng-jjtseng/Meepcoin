#!/usr/bin/env bash
# Canonical-container Wasm CI: build the module with the pinned Emscripten image and verify that
# Node Wasm reproduces the committed vectors byte-for-byte. Intended to run inside emscripten/emsdk:
#   docker run --rm -v "$PWD:/src" -w /src emscripten/emsdk:6.0.3 scripts/ci-wasm.sh
set -euo pipefail
bash meepow/wasm/build-wasm.sh
node meepow/wasm/run-vectors.mjs
