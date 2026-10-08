// MeepHash-W v1 parameters (algoVersion 1). v0 remains frozen; this is additive.
// v1 reduces per-nonce BLAKE3 to a small seed and shifts work to the data-dependent VM
// (BENCHMARK_PLAN_V1.md). Three scratchpad-init candidates and configurable VM-work levels.
#ifndef MEEPOW_PARAMS_V1_HPP
#define MEEPOW_PARAMS_V1_HPP

#include <cstddef>
#include <cstdint>

namespace meepow {

// v1 domain-separation contexts. The epoch dataset reuses the v0 construction B (version-
// independent shared infrastructure); everything per-nonce is v1-tagged.
constexpr const char* CTX_V1_PROGRAM = "MEEP/PROGRAM/v1";
constexpr const char* CTX_V1_NONCE = "MEEP/NONCE/v1";
constexpr const char* CTX_V1_SCRATCHSEED = "MEEP/SCRATCHSEED/v1";
constexpr const char* CTX_V1_FINAL = "MEEP/FINAL/v1";
constexpr const char* CTX_V1_CHECKPOINT = "MEEP/CHECKPOINT/v1";

constexpr uint8_t MEEPOW_ALGO_VERSION_1 = 1;

// Scratchpad-initialization candidate (BENCHMARK_PLAN_V1.md §Design axes).
enum ScratchMode : uint8_t {
    SCRATCH_S1 = 1,  // small BLAKE3 seed region + sequential VM-dependent expansion
    SCRATCH_S2 = 2,  // tiny seed + iterative dependent mixing passes across the scratchpad
    SCRATCH_S3 = 3,  // hybrid: sparse BLAKE3 checkpoints + VM expansion between them
};

struct ParamSetV1 {
    uint8_t id;
    const char* name;
    size_t dataset_words;      // power of two
    size_t scratch_words;      // power of two
    uint32_t program_len;      // N (power of two)
    uint32_t rounds;           // VM-work level
    uint32_t steps_per_round;  // = program_len
    ScratchMode scratch_mode;
    size_t s1_seed_words;      // S1: BLAKE3-seeded prefix (power of two, <= scratch_words)
    uint32_t s2_passes;        // S2: number of dependent mixing passes
    size_t s3_stride;          // S3: BLAKE3 checkpoint every s3_stride words (power of two)
};

// v0 VM budget was 8 rounds x 256 = 2048 steps. v1 levels ~10x/20x/50x -> 80/160/400 rounds.
constexpr uint32_t V1_STEPS_PER_ROUND = 256;
constexpr uint32_t V1_ROUNDS_10X = 80;    // 20,480 steps
constexpr uint32_t V1_ROUNDS_20X = 160;   // 40,960 steps
constexpr uint32_t V1_ROUNDS_50X = 400;   // 102,400 steps

// DEV sizes match v0 (32 MiB dataset / 8 MiB scratchpad) for comparability.
constexpr size_t V1_DATASET_WORDS = 0x400000;  // 32 MiB
constexpr size_t V1_SCRATCH_WORDS = 0x100000;  // 8 MiB

// Build a v1 config for a given (mode, rounds). Mode-specific knobs are chosen so BLAKE3 is a
// small fraction of the scratchpad in every mode.
inline ParamSetV1 v1_config(uint8_t id, const char* name, ScratchMode mode, uint32_t rounds) {
    ParamSetV1 p{};
    p.id = id;
    p.name = name;
    p.dataset_words = V1_DATASET_WORDS;
    p.scratch_words = V1_SCRATCH_WORDS;
    p.program_len = V1_STEPS_PER_ROUND;
    p.rounds = rounds;
    p.steps_per_round = V1_STEPS_PER_ROUND;
    p.scratch_mode = mode;
    p.s1_seed_words = 8192;   // 64 KiB BLAKE3 seed  (0.78% of 8 MiB)
    p.s2_passes = 3;          // 3 dependent mixing passes over the scratchpad
    p.s3_stride = 64;         // 1 BLAKE3 word per 64 (1.56% of 8 MiB)
    return p;
}

// A "fast" v1 profile for cheap tests/vectors (tiny sizes, few rounds), one per mode.
inline ParamSetV1 v1_fast(ScratchMode mode) {
    ParamSetV1 p{};
    p.id = 200 + mode;
    p.name = "v1-fast";
    p.dataset_words = 0x8000;   // 256 KiB
    p.scratch_words = 0x1000;   // 32 KiB
    p.program_len = 32;
    p.rounds = 8;
    p.steps_per_round = 32;
    p.scratch_mode = mode;
    p.s1_seed_words = 256;      // 2 KiB seed
    p.s2_passes = 3;
    p.s3_stride = 16;
    return p;
}

}  // namespace meepow

#endif  // MEEPOW_PARAMS_V1_HPP
