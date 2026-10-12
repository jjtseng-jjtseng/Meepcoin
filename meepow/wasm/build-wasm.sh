#!/usr/bin/env bash
# Build the MeepHash-W v0 WebAssembly module with the pinned Emscripten toolchain.
# Uses the PORTABLE BLAKE3 build so Wasm output matches the native determinism reference.
# Requires emcc on PATH (source your emsdk_env.sh first, or use scripts/build-wasm.sh).
set -euo pipefail
cd "$(dirname "$0")/.."   # meepow/

OUT=wasm
TMP="$OUT/obj"
mkdir -p "$TMP"

INC="-Iinclude -Isrc -Ithird_party/blake3"
B3DEFS="-DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_NO_NEON"

# BLAKE3 C sources (no C++ std flag).
for f in blake3 blake3_dispatch blake3_portable; do
  emcc -O3 -DNDEBUG $INC $B3DEFS -c "third_party/blake3/$f.c" -o "$TMP/$f.o"
done

# meepow C++ sources.
emcc -O3 -std=c++17 -DNDEBUG $INC -c src/meepow.cpp -o "$TMP/meepow.o"
emcc -O3 -std=c++17 -DNDEBUG $INC -c wasm/meepow_wasm.cpp -o "$TMP/meepow_wasm.o"

# Link to an ES module usable from Node and browsers.
emcc -O3 "$TMP"/*.o \
  -sWASM_BIGINT=1 \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sENVIRONMENT=node,web \
  -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_FUNCTIONS='_meep_run_hash,_meepow_dataset_create,_meepow_dataset_free,_meepow_hash,_meepow_ctx_create,_meepow_ctx_free,_meepow_ctx_hash,_meep_v1_bench,_meep_v1_hashes,_meep_v1_setup,_meep_v1_run1,_meep_v2_hashes,_meep_v2_bench,_meep_v2_setup,_meep_v2_setup_ctx,_meep_v2_teardown,_meep_v2_active,_meep_v2_run1,_meep_v2_run1_checked,_meepow_dataset_bytes,_meepow_scratchpad_bytes,_meepow_difficulty_to_target,_meepow_hash_meets_target,_malloc,_free' \
  -sEXPORTED_RUNTIME_METHODS='ccall,cwrap,HEAPU8,getValue,setValue' \
  -o "$OUT/meepow.mjs"

echo "built $OUT/meepow.mjs + $OUT/meepow.wasm"
emcc --version | head -1
