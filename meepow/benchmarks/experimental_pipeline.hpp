// EXPERIMENTAL variant pipeline — used ONLY by benchmarks/adversarial tools, never by the
// consensus library. It mirrors the reference pipeline (meepow.cpp) but exposes attacker knobs:
//   * no_store          : skip physical scratchpad writes (store-elision attack).
//   * lazy_dataset_A    : regenerate the accessed 64 KiB chunk on every dataset load instead of
//                         storing the full dataset (construction-A time-memory tradeoff).
// With default opts and a stored dataset it MUST equal meepow_hash (asserted by the tools).
#ifndef MEEPOW_EXPERIMENTAL_PIPELINE_HPP
#define MEEPOW_EXPERIMENTAL_PIPELINE_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "endian.hpp"
#include "params.hpp"
#include "program.hpp"
#include "vm.hpp"

namespace meepow {

struct VariantOpts {
    bool no_store = false;
    bool lazy_dataset_A = false;  // regenerate chunk per dataset access (needs epoch_key)
};

// Regenerate one construction-A chunk and return word `off` (recompute-on-access).
inline uint64_t lazy_dataset_word_A(const uint8_t epoch_key[32], uint8_t param_id, size_t off) {
    size_t chunk = off / CHUNK_WORDS;
    size_t within = off % CHUNK_WORDS;
    std::vector<uint8_t> tmp(CHUNK_WORDS * 8);
    uint8_t idx_le[8];
    store_u64_le(idx_le, (uint64_t)chunk);
    Field fields[2] = {{idx_le, 8}, {epoch_key, 32}};
    meep_xof(CTX_DATASET, param_id, fields, 2, tmp.data(), tmp.size());
    return load_u64_le(tmp.data() + within * 8);
}

// Run one hash with attacker knobs. `ds_words` may be null iff opts.lazy_dataset_A is set.
inline void run_variant(uint8_t param_id, const uint8_t epoch_key[32],
                        const uint64_t* ds_words, size_t ds_word_count,
                        const uint8_t seed_block_hash[32], uint64_t block_height,
                        const uint8_t* tmpl, size_t tmpl_len, uint32_t nonce,
                        const VariantOpts& opts, uint8_t out_hash[32]) {
    const ParamSet* ps = param_set(param_id);
    uint8_t opcode_table[256];
    build_opcode_table(opcode_table);

    std::vector<uint8_t> prog_bytes((size_t)ps->program_len * 8);
    {
        uint8_t h_le[8];
        store_u64_le(h_le, block_height);
        Field f[3] = {{h_le, 8}, {epoch_key, 32}, {seed_block_hash, 32}};
        meep_xof(CTX_PROGRAM, param_id, f, 3, prog_bytes.data(), prog_bytes.size());
    }
    std::vector<Instr> program(ps->program_len);
    for (uint32_t i = 0; i < ps->program_len; ++i)
        program[i] = decode_instr(prog_bytes.data() + (size_t)i * 8, opcode_table);

    uint8_t seed[96];
    {
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field f[2] = {{n_le, 4}, {tmpl, tmpl_len}};
        meep_xof(CTX_NONCE, param_id, f, 2, seed, sizeof(seed));
    }
    VmState vm;
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(seed + i * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(seed + 64 + i * 8);
    vm.D = ds_words;
    vm.datasetMask = ds_word_count ? ds_word_count - 1 : (ps->dataset_words - 1);
    vm.scratchMask = ps->scratch_words - 1;
    for (int i = 0; i < 8; ++i) vm.lastStores[i] = 0;
    vm.storePos = 0;

    std::vector<uint64_t> scratch(ps->scratch_words);
    vm.SP = scratch.data();
    {
        std::vector<uint8_t> sp_bytes(ps->scratch_words * 8);
        uint8_t n_le[4];
        store_u32_le(n_le, nonce);
        Field f[2] = {{n_le, 4}, {seed, sizeof(seed)}};
        meep_xof(CTX_SCRATCHPAD, param_id, f, 2, sp_bytes.data(), sp_bytes.size());
        for (size_t w = 0; w < ps->scratch_words; ++w)
            vm.SP[w] = load_u64_le(sp_bytes.data() + w * 8);
    }

    const uint32_t N = ps->program_len;
    uint64_t t = 0;
    for (uint32_t round = 0; round < ps->rounds; ++round) {
        uint32_t pc = 0;
        for (uint32_t step = 0; step < ps->steps_per_round; ++step) {
            const Instr& I = program[pc];
            // Custom execution to allow lazy dataset + no-store while matching reference exactly
            // when opts are default.
            bool taken = false;
            if (opts.no_store && I.op == OP_STORE64) {
                // Attacker: skip the physical write but keep the ring + accumulator update so it
                // "looks" compliant (the whole point of the elision experiment).
                uint64_t addr = (vm.r[I.dst] + (uint64_t)I.imm) & vm.scratchMask;
                uint64_t value = vm.r[I.src];
                vm.lastStores[vm.storePos & 7u] = addr;
                vm.storePos++;
                vm.acc[0] = rotl64(vm.acc[0] + (uint64_t)I.op + (uint64_t)I.imm, 1);
                vm.acc[1] = vm.acc[1] ^ vm.r[I.dst] ^ (((uint64_t)I.dst << 3) | (uint64_t)I.src);
                vm.acc[2] = vm.acc[2] * (vm.r[I.src] | 1ULL) + vm.acc[0];
                vm.acc[3] = rotl64(vm.acc[3] ^ addr, 17) + value;
            } else if (opts.lazy_dataset_A && I.op == OP_LOAD64_DATASET) {
                uint64_t off = (vm.r[I.src] ^ (uint64_t)I.imm ^ vm.acc[0]) & vm.datasetMask;
                uint64_t value = lazy_dataset_word_A(epoch_key, param_id, (size_t)off);
                vm.r[I.dst] = value;
                vm.acc[0] = rotl64(vm.acc[0] + (uint64_t)I.op + (uint64_t)I.imm, 1);
                vm.acc[1] = vm.acc[1] ^ vm.r[I.dst] ^ (((uint64_t)I.dst << 3) | (uint64_t)I.src);
                vm.acc[2] = vm.acc[2] * (vm.r[I.src] | 1ULL) + vm.acc[0];
                vm.acc[3] = rotl64(vm.acc[3] ^ off, 17) + value;
            } else {
                taken = execute_step(vm, I);
            }
            ++t;
            if ((t % MIXBACK_INTERVAL) == 0) {
                unsigned j = (unsigned)((t / MIXBACK_INTERVAL) & 7u);
                vm.r[j] ^= vm.SP[vm.lastStores[j] & vm.scratchMask];
            }
            if (taken)
                pc = (uint32_t)((pc + 1 + (I.imm & (N - 1))) % N);
            else
                pc = (pc + 1) % N;
        }
    }

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

    uint8_t rb[64], ab[32], sample[256];
    for (int i = 0; i < 8; ++i) store_u64_le(rb + i * 8, vm.r[i]);
    for (int i = 0; i < 4; ++i) store_u64_le(ab + i * 8, vm.acc[i]);
    for (int k = 0; k < 32; ++k) store_u64_le(sample + k * 8, w[k]);
    Field f[3] = {{rb, 64}, {ab, 32}, {sample, 256}};
    meep_xof(CTX_FINAL, param_id, f, 3, out_hash, 32);
}

}  // namespace meepow

#endif  // MEEPOW_EXPERIMENTAL_PIPELINE_HPP
