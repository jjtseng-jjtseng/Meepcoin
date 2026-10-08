cmake_minimum_required(VERSION 3.16)
project(meepow LANGUAGES C CXX)

# ---------------------------------------------------------------------------------------------
# MeepHash-W v0 reference library build.
#
#   -DMEEPOW_BLAKE3_PORTABLE=ON  (default) : portable-only BLAKE3 — the determinism reference.
#   -DMEEPOW_BLAKE3_PORTABLE=OFF           : optimized BLAKE3 with x86 SIMD (benchmarks only).
#   -DMEEPOW_FUZZ=ON                       : build libFuzzer targets (clang only).
#   -DMEEPOW_SANITIZE=address,undefined    : sanitizer set (see CMakePresets.json).
# ---------------------------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(MEEPOW_BLAKE3_PORTABLE "Portable-only BLAKE3 (determinism reference)" ON)
option(MEEPOW_FUZZ "Build libFuzzer targets (clang only)" OFF)
# Build ONLY the consensus libraries (blake3, meepow, meepow_v2) and stop. Used when the MeepCoin
# daemon embeds this tree via add_subdirectory: the daemon needs the libraries, not the test,
# benchmark, fuzz and vector-generation executables. This keeps ONE copy of the frozen algorithm --
# the daemon compiles these exact sources rather than vendoring a snapshot that could drift.
option(MEEPOW_LIB_ONLY "Build only the consensus libraries (for embedding)" OFF)
set(MEEPOW_SANITIZE "" CACHE STRING "Comma-separated -fsanitize set, e.g. address,undefined")

set(B3 ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3)

# --- BLAKE3 --------------------------------------------------------------------------------
add_library(blake3 STATIC ${B3}/blake3.c ${B3}/blake3_dispatch.c ${B3}/blake3_portable.c)
target_include_directories(blake3 PUBLIC ${B3})
if(MEEPOW_BLAKE3_PORTABLE OR EMSCRIPTEN)
  target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_NO_NEON)
else()
  # Optimized x86-64 build: compile the C intrinsic SIMD paths with per-file ISA flags.
  target_sources(blake3 PRIVATE
    ${B3}/blake3_sse2.c ${B3}/blake3_sse41.c ${B3}/blake3_avx2.c ${B3}/blake3_avx512.c)
  set_source_files_properties(${B3}/blake3_sse2.c   PROPERTIES COMPILE_FLAGS "-msse2")
  set_source_files_properties(${B3}/blake3_sse41.c  PROPERTIES COMPILE_FLAGS "-msse4.1")
  set_source_files_properties(${B3}/blake3_avx2.c   PROPERTIES COMPILE_FLAGS "-mavx2")
  set_source_files_properties(${B3}/blake3_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")
endif()

# --- meepow core ---------------------------------------------------------------------------
add_library(meepow STATIC src/meepow.cpp)
target_include_directories(meepow PUBLIC include PRIVATE src)
target_link_libraries(meepow PUBLIC blake3)

# --- meepow v2 integration surface -----------------------------------------------------------
# The stable, versioned API the MeepCoin daemon links against. src/v2_api.cpp is a thin wrapper
# over the FROZEN implementation; src/v2_capi.cpp is a C ABI over v2_api.cpp. One algorithm, three
# surfaces. See docs/V2_INTEGRATION_API.md.
add_library(meepow_v2 STATIC src/v2_api.cpp src/v2_capi.cpp)
target_include_directories(meepow_v2 PUBLIC include PRIVATE src)
target_link_libraries(meepow_v2 PUBLIC blake3)
find_package(Threads REQUIRED)
target_link_libraries(meepow_v2 PUBLIC Threads::Threads)

# Embedding builds (the MeepCoin daemon) need the libraries above and nothing else.
if(MEEPOW_LIB_ONLY)
  return()
endif()

# doctest (header-only, vendored)
add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE third_party/doctest)

# Sanitizers applied to our code (not the vendored SIMD asm).
if(MEEPOW_SANITIZE)
  add_compile_options(-fsanitize=${MEEPOW_SANITIZE} -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=${MEEPOW_SANITIZE})
endif()

enable_testing()

# --- unit tests ----------------------------------------------------------------------------
add_executable(meepow-unit tests/unit_main.cpp tests/test_sparse_hardfork.cpp)
target_include_directories(meepow-unit PRIVATE src include tests
  ${CMAKE_CURRENT_SOURCE_DIR}/../pool/protocol)
target_link_libraries(meepow-unit PRIVATE meepow doctest)
add_test(NAME unit COMMAND meepow-unit)

# --- known-answer-test runner (consumes vectors/*.json) ------------------------------------
add_executable(meepow-kat tests/kat_runner.cpp)
target_include_directories(meepow-kat PRIVATE src include)
target_link_libraries(meepow-kat PRIVATE meepow)
add_test(NAME kat_fast
  COMMAND meepow-kat ${CMAKE_CURRENT_SOURCE_DIR}/vectors/vectors_fast.json)
add_test(NAME kat_dev
  COMMAND meepow-kat ${CMAKE_CURRENT_SOURCE_DIR}/vectors/vectors_dev.json)

# --- v2 hash CLI (block-vector generation / independent cross-check) ---------------------------
add_executable(meepow-v2-hash tools/v2_hash_cli.cpp)
target_link_libraries(meepow-v2-hash PRIVATE meepow_v2)

# --- long-lived v2 verification helper (Phase 1C dual-verifier cross-check) --------------------
# A small stdin/stdout service the local development pool launches so it can require the native
# frozen-v2 result and its WebAssembly result to agree before accepting a share. It contains no
# algorithm code: it only calls meepow::v2::Dataset / meepow::v2::Hasher through the public API.
add_executable(meepow-v2-helper tools/v2_verify_helper.cpp)
target_link_libraries(meepow-v2-helper PRIVATE meepow_v2)
# Build-source identity, computed by scripts/build-native-helper.sh from an explicit sorted source
# inventory and reported by the helper in HELLO. Left unset, the helper reports "unknown" and the
# pool refuses it rather than trusting a binary that cannot say what it was built from.
set(MEEPOW_HELPER_SOURCE_ID "" CACHE STRING "sha256 of the sorted helper source inventory")
if(MEEPOW_HELPER_SOURCE_ID)
  target_compile_definitions(meepow-v2-helper
    PRIVATE MEEPOW_HELPER_SOURCE_ID="${MEEPOW_HELPER_SOURCE_ID}")
endif()

# --- v2 public-API known-answer tests (every public entry point) ------------------------------
add_executable(meepow-kat-v2-api tests/kat_v2_api.cpp)
target_include_directories(meepow-kat-v2-api PRIVATE src)
target_link_libraries(meepow-kat-v2-api PRIVATE meepow_v2)
add_test(NAME kat_v2_api
  COMMAND meepow-kat-v2-api ${CMAKE_CURRENT_SOURCE_DIR}/vectors/vectors_v2.txt)

# --- vector generator ----------------------------------------------------------------------
add_executable(meepow-vectorgen tools/vectorgen/vectorgen.cpp)
target_include_directories(meepow-vectorgen PRIVATE src include tests)
target_link_libraries(meepow-vectorgen PRIVATE meepow)

# --- benchmark -----------------------------------------------------------------------------
add_executable(meepow-bench benchmarks/bench.cpp)
target_include_directories(meepow-bench PRIVATE src include)
target_link_libraries(meepow-bench PRIVATE meepow)
if(MEEPOW_BLAKE3_PORTABLE OR EMSCRIPTEN)
  target_compile_definitions(meepow-bench PRIVATE MEEPOW_BLAKE3_PORTABLE_BUILD)
endif()

# --- v1 component-timed benchmark ----------------------------------------------------------
add_executable(meepow-bench-v1 benchmarks/bench_v1.cpp)
target_include_directories(meepow-bench-v1 PRIVATE src include)
target_link_libraries(meepow-bench-v1 PRIVATE meepow)
if(MEEPOW_BLAKE3_PORTABLE OR EMSCRIPTEN)
  target_compile_definitions(meepow-bench-v1 PRIVATE MEEPOW_BLAKE3_PORTABLE_BUILD)
endif()

add_executable(meepow-v1-validate benchmarks/v1_validate.cpp)
target_include_directories(meepow-v1-validate PRIVATE src include)
target_link_libraries(meepow-v1-validate PRIVATE meepow)

add_executable(meepow-v1-adversarial benchmarks/v1_adversarial.cpp)
target_include_directories(meepow-v1-adversarial PRIVATE src include)
target_link_libraries(meepow-v1-adversarial PRIVATE meepow)

add_executable(meepow-v1-store-elision benchmarks/v1_store_elision.cpp)
target_include_directories(meepow-v1-store-elision PRIVATE src include)
target_link_libraries(meepow-v1-store-elision PRIVATE meepow)

add_executable(meepow-v1-grind benchmarks/v1_grind.cpp)
target_include_directories(meepow-v1-grind PRIVATE src include)
target_link_libraries(meepow-v1-grind PRIVATE meepow)

add_executable(meepow-v1-tmto benchmarks/v1_tmto.cpp)
target_include_directories(meepow-v1-tmto PRIVATE src include)
target_link_libraries(meepow-v1-tmto PRIVATE meepow)

add_executable(meepow-v2-experiment benchmarks/v2_experiment.cpp)
target_include_directories(meepow-v2-experiment PRIVATE src include)
target_link_libraries(meepow-v2-experiment PRIVATE meepow)

add_executable(meepow-v2-tmto-strict benchmarks/v2_tmto_strict.cpp)
target_include_directories(meepow-v2-tmto-strict PRIVATE src include)
target_link_libraries(meepow-v2-tmto-strict PRIVATE meepow)

find_package(Threads REQUIRED)
add_executable(meepow-v2-throughput benchmarks/v2_throughput.cpp)
target_include_directories(meepow-v2-throughput PRIVATE src include)
target_link_libraries(meepow-v2-throughput PRIVATE meepow Threads::Threads)

add_executable(meepow-v2-sustained benchmarks/v2_sustained.cpp)
target_include_directories(meepow-v2-sustained PRIVATE src include)
target_link_libraries(meepow-v2-sustained PRIVATE meepow Threads::Threads)

add_executable(meepow-v2-tmto-strict2 benchmarks/v2_tmto_strict2.cpp)
target_include_directories(meepow-v2-tmto-strict2 PRIVATE src include)
target_link_libraries(meepow-v2-tmto-strict2 PRIVATE meepow)

add_executable(meepow-v2-tmto-quick benchmarks/v2_tmto_quick.cpp)
target_include_directories(meepow-v2-tmto-quick PRIVATE src include)
target_link_libraries(meepow-v2-tmto-quick PRIVATE meepow)

add_executable(meepow-v2-validate benchmarks/v2_validate.cpp)
target_include_directories(meepow-v2-validate PRIVATE src include)
target_link_libraries(meepow-v2-validate PRIVATE meepow)

add_executable(meepow-v1-confirm benchmarks/v1_confirm.cpp)
target_include_directories(meepow-v1-confirm PRIVATE src include)
target_link_libraries(meepow-v1-confirm PRIVATE meepow)
if(MEEPOW_BLAKE3_PORTABLE OR EMSCRIPTEN)
  target_compile_definitions(meepow-v1-confirm PRIVATE MEEPOW_BLAKE3_PORTABLE_BUILD)
endif()

# --- adversarial tools (Phase 1A tracks) ---------------------------------------------------
add_executable(meepow-adversarial benchmarks/adversarial.cpp)
target_include_directories(meepow-adversarial PRIVATE src include)
target_link_libraries(meepow-adversarial PRIVATE meepow)

# --- libFuzzer targets (clang only) --------------------------------------------------------
if(MEEPOW_FUZZ)
  foreach(t program_decode addressing vm_exec target_conv)
    add_executable(fuzz_${t} fuzz/fuzz_${t}.cpp)
    target_include_directories(fuzz_${t} PRIVATE src include)
    target_link_libraries(fuzz_${t} PRIVATE meepow)
    target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined -g)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
  # Pool client-message parser (schema/validation only; no networking).
  add_executable(fuzz_pool_msgs fuzz/fuzz_pool_msgs.cpp)
  target_include_directories(fuzz_pool_msgs PRIVATE
    src include tests ${CMAKE_CURRENT_SOURCE_DIR}/../pool/protocol)
  target_compile_options(fuzz_pool_msgs PRIVATE -fsanitize=fuzzer,address,undefined -g)
  target_link_options(fuzz_pool_msgs PRIVATE -fsanitize=fuzzer,address,undefined)
  # v1-specific fuzz targets (link meepow for BLAKE3).
  foreach(t v1_scratch_init v1_readchain v1_params v1_hash_fast v1_wasm_boundary
            v2_dataset v2_hash v2_backend)
    add_executable(fuzz_${t} fuzz/fuzz_${t}.cpp)
    target_include_directories(fuzz_${t} PRIVATE src include)
    target_link_libraries(fuzz_${t} PRIVATE meepow)
    target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined -g)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
