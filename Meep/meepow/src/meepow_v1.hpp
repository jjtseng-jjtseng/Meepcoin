// MeepHash-W v1 pipeline (algoVersion 1). v0 stays frozen; this reuses the version-independent
// low-level pieces (endian, VM, program decode, dataset construction B) and adds v1's reduced-
// BLAKE3 scratchpad-init candidates + configurable VM-work levels (BENCHMARK_PLAN_V1.md).
//
// Structured as phase functions so the benchmark can time each component separately:
//   v1_nonce_seed | v1_scratch_init | v1_run_vm | v1_finalize.
// Allocation-free per nonce via a reusable V1Ctx.
#ifndef MEEPOW_V1_HPP
#define MEEPOW_V1_HPP

#include <cstdint>
#include <cstring>
#include <vector>

#include "blake3_xof.hpp"
#include "dataset.hpp"
#include "endian.hpp"
#include "params.hpp"
#include "params_v1.hpp"
#include "program.hpp"
#include "vm.hpp"

namespace meepow {

// Cheap latency-bound integer mixing used for VM-style scratchpad expansion (no BLAKE3).
inline uint64_t mixV1(uint64_t a, uint64_t b, uint64_t w) {
    uint64_t x = a + b;
    x ^= rotl64(x, 29);
    x = x * (b | 1ULL);
    x ^= w;
    x = rotl64(x, 17);
    x = x + a;
    return x;
}

struct V1Ctx {
    ParamSetV1 ps;
    const uint64_t* dataset = nullptr;
    size_t dmask = 0;
    uint8_t epoch_key[32];
    std::vector<Instr> program;
    uint8_t opcode_table[256];
    std::vector<uint64_t> scratch;
    std::vector<uint8_t> seedbytes;  // reusable BLAKE3 output buffer for scratch seed/checkpoints
    std::vector<uint8_t> tmpl;
};

// Create a reusable context: derive the v1 program once, allocate reusable buffers.
inline V1Ctx* v1_ctx_create(const ParamSetV1& ps, const uint64_t* dataset, size_t dataset_words,
                            const uint8_t epoch_key[32], const uint8_t seed_block_hash[32],
                            uint64_t block_height, const uint8_t* tmpl, size_t tmpl_len) {
    V1Ctx* c = new V1Ctx();
    c->ps = ps;
    c->dataset = dataset;
    c->dmask = dataset_words - 1;
    std::memcpy(c->epoch_key, epoch_key, 32);
    build_opcode_table(c->opcode_table);
    std::vector<uint8_t> prog_bytes((size_t)ps.program_len * 8);
    uint8_t h_le[8];
    store_u64_le(h_le, block_height);
    Field pf[3] = {{h_le, 8}, {epoch_key, 32}, {seed_block_hash, 32}};
    meep_xof(CTX_V1_PROGRAM, ps.id, pf, 3, prog_bytes.data(), prog_bytes.size());
    c->program.resize(ps.program_len);
    for (uint32_t i = 0; i < ps.program_len; ++i)
        c->program[i] = decode_instr(prog_bytes.data() + (size_t)i * 8, c->opcode_table);
    c->tmpl.assign(tmpl, tmpl + tmpl_len);
    c->scratch.resize(ps.scratch_words);
    // Largest transient BLAKE3 output we need: S1 seed region, or S3 checkpoints.
    size_t maxseed = ps.s1_seed_words * 8;
    size_t ckpt = (ps.scratch_words / ps.s3_stride) * 8;
    c->seedbytes.resize(maxseed > ckpt ? maxseed : ckpt);
    return c;
}
inline void v1_ctx_free(V1Ctx* c) { delete c; }

// Phase 1: per-nonce seed (96 bytes: 8 registers + 4 accumulator words).
inline void v1_nonce_seed(V1Ctx* c, uint32_t nonce, uint8_t seed[96]) {
    uint8_t n_le[4];
    store_u32_le(n_le, nonce);
    Field f[2] = {{n_le, 4}, {c->tmpl.data(), c->tmpl.size()}};
    meep_xof(CTX_V1_NONCE, c->ps.id, f, 2, seed, 96);
}

// Phase 2: scratchpad initialization — one of three candidates (reduced BLAKE3).
inline void v1_scratch_init(V1Ctx* c, uint32_t nonce, const uint8_t seed[96]) {
    const ParamSetV1& ps = c->ps;
    uint64_t* SP = c->scratch.data();
    const size_t W = ps.scratch_words;
    uint8_t n_le[4];
    store_u32_le(n_le, nonce);

    if (ps.scratch_mode == SCRATCH_S1) {
        // Small BLAKE3 seed region, then sequential VM-dependent expansion.
        const size_t S = ps.s1_seed_words;
        Field f[2] = {{n_le, 4}, {seed, 96}};
        meep_xof(CTX_V1_SCRATCHSEED, ps.id, f, 2, c->seedbytes.data(), S * 8);
        for (size_t w = 0; w < S; ++w) SP[w] = load_u64_le(c->seedbytes.data() + w * 8);
        for (size_t w = S; w < W; ++w) {
            uint64_t prev = SP[w - 1];
            uint64_t back = prev % (uint64_t)w;  // data-dependent backward reference
            SP[w] = mixV1(prev, SP[back], (uint64_t)w);
        }
    } else if (ps.scratch_mode == SCRATCH_S2) {
        // Tiny seed -> cheap counter fill -> P iterative dependent mixing passes.
        uint8_t st_bytes[32];
        Field f[2] = {{n_le, 4}, {seed, 96}};
        meep_xof(CTX_V1_SCRATCHSEED, ps.id, f, 2, st_bytes, 32);
        uint64_t st = load_u64_le(st_bytes) ^ load_u64_le(st_bytes + 8) ^
                      load_u64_le(st_bytes + 16) ^ load_u64_le(st_bytes + 24);
        for (size_t w = 0; w < W; ++w) {
            st = st * 0x9E3779B97F4A7C15ULL + (uint64_t)w + 1;
            SP[w] = st ^ rotl64(st, 31);
        }
        const size_t mask = W - 1;
        for (uint32_t pass = 0; pass < ps.s2_passes; ++pass)
            for (size_t w = 0; w < W; ++w) {
                uint64_t j = (SP[(w - 1) & mask] + (uint64_t)w) & mask;  // data-dependent address
                SP[w] = mixV1(SP[w], SP[j], (uint64_t)w + (uint64_t)pass * W);
            }
    } else {  // SCRATCH_S3
        // Sparse BLAKE3 checkpoints every `stride` words; VM expansion between them.
        const size_t stride = ps.s3_stride;
        const size_t nck = W / stride;
        Field f[2] = {{n_le, 4}, {seed, 96}};
        meep_xof(CTX_V1_SCRATCHSEED, ps.id, f, 2, c->seedbytes.data(), nck * 8);
        for (size_t k = 0; k < nck; ++k) SP[k * stride] = load_u64_le(c->seedbytes.data() + k * 8);
        for (size_t w = 0; w < W; ++w) {
            if (w % stride == 0) continue;  // checkpoint already set
            uint64_t prev = SP[w - 1];
            uint64_t anchor = SP[(w / stride) * stride];  // nearest lower checkpoint
            SP[w] = mixV1(prev, anchor, (uint64_t)w);
        }
    }
}

// Phase 3: run the data-dependent VM for `rounds` x `steps_per_round`. When stub_dataset is true,
// dataset reads are redirected to a 1-word in-L1 buffer (for the dataset-access differential).
inline void v1_run_vm(V1Ctx* c, const uint8_t seed[96], VmState& vm, bool stub_dataset,
                      uint8_t* out_c1, uint8_t* out_ch) {
    const ParamSetV1& ps = c->ps;
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(seed + i * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(seed + 64 + i * 8);
    vm.SP = c->scratch.data();
    vm.scratchMask = ps.scratch_words - 1;
    for (int i = 0; i < 8; ++i) vm.lastStores[i] = 0;
    vm.storePos = 0;

    static const uint64_t one_word = 0xA5A5A5A5A5A5A5A5ULL;
    if (stub_dataset) {
        vm.D = &one_word;
        vm.datasetMask = 0;
    } else {
        vm.D = c->dataset;
        vm.datasetMask = c->dmask;
    }

    const uint32_t N = ps.program_len;
    const uint32_t half = ps.rounds / 2;
    uint64_t t = 0;
    for (uint32_t round = 0; round < ps.rounds; ++round) {
        uint32_t pc = 0;
        for (uint32_t step = 0; step < ps.steps_per_round; ++step) {
            const Instr& I = c->program[pc];
            bool taken = execute_step(vm, I);
            // Mandatory data-dependent dataset read per step: a serial latency chain (each address
            // depends on the previous read) that makes the VM loop memory-latency-bound and hard
            // to parallelize within a nonce (v1; BENCHMARK_PLAN_V1.md). In stub mode datasetMask==0
            // so this hits L1, isolating the dataset-access latency in the differential.
            uint64_t da = (vm.acc[2] ^ vm.r[step & 7]) & vm.datasetMask;
            uint64_t dv = vm_dataset_read(vm, da);  // null-safe: v1 (ds_read==null) reads vm.D[da]
            vm.acc[3] ^= dv;
            vm.acc[2] = rotl64(vm.acc[2] + dv, 23);
            ++t;
            if ((t % MIXBACK_INTERVAL) == 0) {
                unsigned j = (unsigned)((t / MIXBACK_INTERVAL) & 7u);
                vm.r[j] ^= vm_scratch_read(vm, vm.lastStores[j] & vm.scratchMask);
            }
            if (taken)
                pc = (uint32_t)((pc + 1 + (I.imm & (N - 1))) % N);
            else
                pc = (pc + 1) % N;
        }
        if (round == 0 && out_c1) {
            uint8_t rb[64], ab[32];
            for (int i = 0; i < 8; ++i) store_u64_le(rb + i * 8, vm.r[i]);
            for (int i = 0; i < 4; ++i) store_u64_le(ab + i * 8, vm.acc[i]);
            Field f[2] = {{rb, 64}, {ab, 32}};
            meep_xof(CTX_V1_CHECKPOINT, ps.id, f, 2, out_c1, 32);
        }
        if (round == half && out_ch) {
            uint8_t rb[64], ab[32];
            for (int i = 0; i < 8; ++i) store_u64_le(rb + i * 8, vm.r[i]);
            for (int i = 0; i < 4; ++i) store_u64_le(ab + i * 8, vm.acc[i]);
            Field f[2] = {{rb, 64}, {ab, 32}};
            meep_xof(CTX_V1_CHECKPOINT, ps.id, f, 2, out_ch, 32);
        }
    }
}

// Phase 4: final walk + finalization.
inline void v1_finalize(V1Ctx* c, VmState& vm, uint8_t out_hash[32]) {
    uint64_t w[32];
    for (int k = 0; k < 8; ++k) w[k] = vm_scratch_read(vm, vm.lastStores[k] & vm.scratchMask);
    for (int k = 0; k < 24; ++k) {
        uint64_t idx = (vm.acc[k & 3] ^ vm.r[k & 7] ^ (uint64_t)k * 0x9E3779B97F4A7C15ULL) &
                       vm.scratchMask;
        w[8 + k] = vm_scratch_read(vm, idx);
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
    meep_xof(CTX_V1_FINAL, c->ps.id, f, 3, out_hash, 32);
}

// Compose a full v1 hash (allocation-free given a context).
inline void v1_hash(V1Ctx* c, uint32_t nonce, uint8_t out_hash[32], uint8_t* out_c1,
                    uint8_t* out_ch) {
    uint8_t seed[96];
    v1_nonce_seed(c, nonce, seed);
    v1_scratch_init(c, nonce, seed);
    VmState vm{};
    v1_run_vm(c, seed, vm, false, out_c1, out_ch);
    v1_finalize(c, vm, out_hash);
}

}  // namespace meepow

#endif  // MEEPOW_V1_HPP
