// MeepHash-W v0 top-level pipeline and C API (spec §5, §6, §8, §10).
// The same source compiles native (CMake) and to WebAssembly (Emscripten).
#include "meepow/meepow.h"

#include <cstdlib>
#include <cstring>
#include <vector>

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "endian.hpp"
#include "params.hpp"
#include "program.hpp"
#include "target.hpp"
#include "vm.hpp"

using namespace meepow;

// Opaque dataset handle exposed through the C API.
struct meepow_dataset {
    uint8_t param_id;
    uint8_t construction;
    uint8_t epoch_key[32];
    std::vector<uint64_t> words;
    size_t mask;
};

extern "C" {

size_t meepow_dataset_bytes(uint8_t param_set_id) {
    const ParamSet* ps = param_set(param_set_id);
    return ps ? ps->dataset_words * 8 : 0;
}

size_t meepow_scratchpad_bytes(uint8_t param_set_id) {
    const ParamSet* ps = param_set(param_set_id);
    return ps ? ps->scratch_words * 8 : 0;
}

meepow_dataset* meepow_dataset_create(uint8_t param_set_id, uint8_t construction,
                                      const uint8_t epoch_key[32]) {
    const ParamSet* ps = param_set(param_set_id);
    if (!ps || !epoch_key) return nullptr;
    if (construction != MEEPOW_DATASET_A && construction != MEEPOW_DATASET_B) return nullptr;

    meepow_dataset* ds = new (std::nothrow) meepow_dataset();
    if (!ds) return nullptr;
    ds->param_id = param_set_id;
    ds->construction = construction;
    std::memcpy(ds->epoch_key, epoch_key, 32);
    ds->mask = ps->dataset_words - 1;
    try {
        ds->words.resize(ps->dataset_words);
    } catch (...) {
        delete ds;
        return nullptr;
    }
    if (construction == MEEPOW_DATASET_A)
        dataset_fill_A(ds->words.data(), ps->dataset_words, epoch_key, param_set_id);
    else
        dataset_fill_B(ds->words.data(), ps->dataset_words, epoch_key, param_set_id);
    return ds;
}

void meepow_dataset_free(meepow_dataset* ds) { delete ds; }

}  // extern "C"

namespace {

// Serialize 8 registers / 4 accumulator words to little-endian bytes.
void regs_to_bytes(const uint64_t r[8], uint8_t out[64]) {
    for (int i = 0; i < 8; ++i) store_u64_le(out + i * 8, r[i]);
}
void acc_to_bytes(const uint64_t a[4], uint8_t out[32]) {
    for (int i = 0; i < 4; ++i) store_u64_le(out + i * 8, a[i]);
}

// Checkpoint digest (spec §8.5): framed fields regs(64), acc(32).
void checkpoint_digest(const uint64_t r[8], const uint64_t a[4], uint8_t param_id,
                       uint8_t out[32]) {
    uint8_t rb[64], ab[32];
    regs_to_bytes(r, rb);
    acc_to_bytes(a, ab);
    Field fields[2] = {{rb, 64}, {ab, 32}};
    meep_xof(CTX_CHECKPOINT, param_id, fields, 2, out, 32);
}

}  // namespace

// Reusable per-job context (spec §5, §8). Program and buffers are allocated once here; per-nonce
// hashing (meepow_ctx_hash) then performs zero heap allocations.
struct meepow_ctx {
    const meepow_dataset* ds;
    const ParamSet* ps;
    uint8_t opcode_table[256];
    std::vector<Instr> program;      // derived once from (epochKey, seedBlockHash, height)
    std::vector<uint8_t> tmpl;       // template blob copy (constant across nonces)
    std::vector<uint64_t> scratch;   // reused scratchpad
    std::vector<uint8_t> sp_bytes;   // reused scratchpad-fill byte buffer
};

extern "C" meepow_ctx* meepow_ctx_create(const meepow_dataset* ds,
                                         const uint8_t seed_block_hash[32], uint64_t block_height,
                                         const uint8_t* template_blob, size_t template_len) {
    if (!ds || !seed_block_hash) return nullptr;
    if (template_len && !template_blob) return nullptr;
    const ParamSet* ps = param_set(ds->param_id);
    if (!ps) return nullptr;

    meepow_ctx* ctx = new (std::nothrow) meepow_ctx();
    if (!ctx) return nullptr;
    ctx->ds = ds;
    ctx->ps = ps;
    build_opcode_table(ctx->opcode_table);
    try {
        // --- Program derivation (spec §5): once per (epochKey, seedBlockHash, height). ---
        std::vector<uint8_t> prog_bytes((size_t)ps->program_len * 8);
        uint8_t h_le[8];
        store_u64_le(h_le, block_height);
        Field fields[3] = {{h_le, 8}, {ds->epoch_key, 32}, {seed_block_hash, 32}};
        meep_xof(CTX_PROGRAM, ds->param_id, fields, 3, prog_bytes.data(), prog_bytes.size());
        ctx->program.resize(ps->program_len);
        for (uint32_t i = 0; i < ps->program_len; ++i)
            ctx->program[i] = decode_instr(prog_bytes.data() + (size_t)i * 8, ctx->opcode_table);
        ctx->tmpl.assign(template_blob, template_blob + template_len);
        ctx->scratch.resize(ps->scratch_words);
        ctx->sp_bytes.resize(ps->scratch_words * 8);
    } catch (...) {
        delete ctx;
        return nullptr;
    }
    return ctx;
}

extern "C" void meepow_ctx_free(meepow_ctx* ctx) { delete ctx; }

extern "C" int meepow_ctx_hash(meepow_ctx* ctx, uint32_t nonce, uint8_t out_hash[32],
                               uint8_t out_checkpoint_round1[32],
                               uint8_t out_checkpoint_round_half[32]) {
    if (!ctx || !out_hash) return 1;
    const ParamSet* ps = ctx->ps;
    const uint8_t param_id = ctx->ds->param_id;

    // --- Per-nonce seed (spec §8 step 1-2): framed fields LE32(nonce), templateBlob. ---
    uint8_t seed[96];
    {
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field fields[2] = {{n_le, 4}, {ctx->tmpl.data(), ctx->tmpl.size()}};
        meep_xof(CTX_NONCE, param_id, fields, 2, seed, sizeof(seed));
    }

    VmState vm;
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(seed + i * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(seed + 64 + i * 8);
    vm.D = ctx->ds->words.data();
    vm.datasetMask = ctx->ds->mask;
    vm.scratchMask = ps->scratch_words - 1;
    for (int i = 0; i < 8; ++i) vm.lastStores[i] = 0;
    vm.storePos = 0;
    vm.SP = ctx->scratch.data();

    // --- Scratchpad init (spec §8 step 3): reuse the context byte buffer, no allocation. ---
    {
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field fields[2] = {{n_le, 4}, {seed, sizeof(seed)}};
        meep_xof(CTX_SCRATCHPAD, param_id, fields, 2, ctx->sp_bytes.data(), ctx->sp_bytes.size());
        for (size_t w = 0; w < ps->scratch_words; ++w)
            vm.SP[w] = load_u64_le(ctx->sp_bytes.data() + w * 8);
    }

    // --- Execute R rounds with a fixed step budget (spec §6.3, §8 step 5). ---
    const uint32_t half = ps->rounds / 2;
    uint64_t t = 0;  // global executed-step counter
    for (uint32_t round = 0; round < ps->rounds; ++round) {
        uint32_t pc = 0;
        for (uint32_t step = 0; step < ps->steps_per_round; ++step) {
            const Instr& I = ctx->program[pc];
            bool taken = execute_step(vm, I);
            ++t;
            if ((t % MIXBACK_INTERVAL) == 0) {  // periodic mix-back (spec §6.2)
                unsigned j = (unsigned)((t / MIXBACK_INTERVAL) & 7u);
                vm.r[j] ^= vm.SP[vm.lastStores[j] & vm.scratchMask];
            }
            if (taken)
                pc = (uint32_t)((pc + 1 + (I.imm & (ps->program_len - 1))) % ps->program_len);
            else
                pc = (pc + 1) % ps->program_len;
        }
        if (round == 0 && out_checkpoint_round1)
            checkpoint_digest(vm.r, vm.acc, param_id, out_checkpoint_round1);
        if (round == half && out_checkpoint_round_half)
            checkpoint_digest(vm.r, vm.acc, param_id, out_checkpoint_round_half);
    }

    // --- Final walk (spec §8.4): force recent store sites + a data-dependent walk. ---
    uint64_t w[32];
    for (int k = 0; k < 8; ++k) w[k] = vm.SP[vm.lastStores[k] & vm.scratchMask];
    for (int k = 0; k < 24; ++k) {
        uint64_t idx = (vm.acc[k & 3] ^ vm.r[k & 7] ^ (uint64_t)k * 0x9E3779B97F4A7C15ULL) &
                       vm.scratchMask;
        w[8 + k] = vm.SP[idx];
    }
    vm.acc[0] ^= w[0];
    vm.acc[1] += w[8];
    vm.acc[2] ^= w[16];
    vm.acc[3] += w[24];

    // --- Finalize (spec §8 step 7): fields regs(64), acc(32), finalSample(256). ---
    uint8_t rb[64], ab[32], sample[256];
    regs_to_bytes(vm.r, rb);
    acc_to_bytes(vm.acc, ab);
    for (int k = 0; k < 32; ++k) store_u64_le(sample + k * 8, w[k]);
    Field fields[3] = {{rb, 64}, {ab, 32}, {sample, 256}};
    meep_xof(CTX_FINAL, param_id, fields, 3, out_hash, 32);
    return 0;
}

// One-shot hash: a thin wrapper over the context path, so both produce identical output.
extern "C" int meepow_hash(const meepow_dataset* ds, const uint8_t seed_block_hash[32],
                           uint64_t block_height, const uint8_t* template_blob,
                           size_t template_len, uint32_t nonce, uint8_t out_hash[32],
                           uint8_t out_checkpoint_round1[32],
                           uint8_t out_checkpoint_round_half[32]) {
    meepow_ctx* ctx =
        meepow_ctx_create(ds, seed_block_hash, block_height, template_blob, template_len);
    if (!ctx) return 1;
    int rc = meepow_ctx_hash(ctx, nonce, out_hash, out_checkpoint_round1, out_checkpoint_round_half);
    meepow_ctx_free(ctx);
    return rc;
}

extern "C" int meepow_difficulty_to_target(uint64_t difficulty, uint8_t out_target[32]) {
    if (!out_target) return 1;
    return difficulty_to_target(difficulty, out_target) ? 0 : 1;
}

extern "C" int meepow_hash_meets_target(const uint8_t hash[32], const uint8_t target[32]) {
    if (!hash || !target) return 0;
    return hash_meets_target(hash, target) ? 1 : 0;
}
