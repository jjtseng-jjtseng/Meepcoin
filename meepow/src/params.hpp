// Parameter sets and the 256-entry opcode table (spec §2, §6).
#ifndef MEEPOW_PARAMS_HPP
#define MEEPOW_PARAMS_HPP

#include <cstddef>
#include <cstdint>

#include "meepow/meepow.h"

namespace meepow {

// Domain-separation contexts (spec §1).
constexpr const char* CTX_DATASET = "MEEP/DATASET/v0";
constexpr const char* CTX_PROGRAM = "MEEP/PROGRAM/v0";
constexpr const char* CTX_NONCE = "MEEP/NONCE/v0";
constexpr const char* CTX_SCRATCHPAD = "MEEP/SCRATCHPAD/v0";
constexpr const char* CTX_FINAL = "MEEP/FINAL/v0";
constexpr const char* CTX_CHECKPOINT = "MEEP/CHECKPOINT/v0";

// Epoch/seed-block consensus constants (spec §9, provisional).
constexpr uint64_t EPOCH_LENGTH = 2048;
constexpr uint64_t EPOCH_DELAY = 64;
constexpr uint64_t SEED_BLOCK_DELAY = 64;

constexpr size_t CHUNK_WORDS = 8192;  // 64 KiB, construction A (spec §4.1)
constexpr size_t SEED_WORDS = 8192;   // construction B seed region (spec §4.2)
constexpr unsigned MIXBACK_INTERVAL = 8;  // spec §6.2

struct ParamSet {
    uint8_t id;
    const char* name;
    size_t dataset_words;    // power of two
    size_t scratch_words;    // power of two
    uint32_t program_len;    // N
    uint32_t rounds;         // R
    uint32_t steps_per_round;
};

// Powers of two so addressing uses masks, never division (spec §2).
constexpr ParamSet PARAM_SETS[] = {
    {MEEPOW_PARAM_DEV, "dev", 0x400000, 0x100000, 256, 8, 256},   // 32 MiB / 8 MiB
    {MEEPOW_PARAM_FAST, "fast", 0x8000, 0x1000, 32, 2, 32},       // 256 KiB / 32 KiB
};
constexpr size_t NUM_PARAM_SETS = sizeof(PARAM_SETS) / sizeof(PARAM_SETS[0]);

inline const ParamSet* param_set(uint8_t id) {
    for (size_t i = 0; i < NUM_PARAM_SETS; ++i)
        if (PARAM_SETS[i].id == id) return &PARAM_SETS[i];
    return nullptr;
}

// Opcodes (spec §6).
enum Opcode : uint8_t {
    OP_ADD64 = 0, OP_XOR64, OP_MUL64, OP_MULHI64, OP_ROTL64, OP_ROTR64,
    OP_ADD32, OP_XOR32, OP_MUL32,
    OP_LOAD64_SCRATCH, OP_LOAD64_DATASET, OP_STORE64,
    OP_BRANCH_IF_BIT, OP_CSELECT, OP_BYTE_SHUFFLE,
    OP__COUNT
};

// Run-length weights (spec §6). MUST sum to 256; asserted at table build time.
struct OpWeight { Opcode op; uint16_t count; };
constexpr OpWeight OP_WEIGHTS[] = {
    {OP_ADD64, 41}, {OP_XOR64, 28}, {OP_MUL64, 20}, {OP_MULHI64, 12},
    {OP_ROTL64, 8}, {OP_ROTR64, 7},
    {OP_ADD32, 16}, {OP_XOR32, 12}, {OP_MUL32, 10},
    {OP_LOAD64_SCRATCH, 31}, {OP_LOAD64_DATASET, 15}, {OP_STORE64, 20},
    {OP_BRANCH_IF_BIT, 18}, {OP_CSELECT, 9}, {OP_BYTE_SHUFFLE, 9},
};
constexpr size_t NUM_OP_WEIGHTS = sizeof(OP_WEIGHTS) / sizeof(OP_WEIGHTS[0]);

// Build the 256-entry selector->opcode table (spec §6). Deterministic layout in list order.
inline void build_opcode_table(uint8_t table[256]) {
    size_t idx = 0;
    for (size_t i = 0; i < NUM_OP_WEIGHTS; ++i)
        for (uint16_t c = 0; c < OP_WEIGHTS[i].count; ++c) table[idx++] = OP_WEIGHTS[i].op;
    // idx must be exactly 256; callers/tests assert this.
    while (idx < 256) table[idx++] = OP_ADD64;  // unreachable if weights sum to 256
}

}  // namespace meepow

#endif  // MEEPOW_PARAMS_HPP
