// MeepHash-W VM state and single-step execution (spec §6, §7).
// Header-only so the reference library, benchmarks, and adversarial tools share one definition.
#ifndef MEEPOW_VM_HPP
#define MEEPOW_VM_HPP

#include <cstddef>
#include <cstdint>

#include "endian.hpp"
#include "params.hpp"
#include "program.hpp"

namespace meepow {

struct VmState {
    uint64_t r[8];
    uint64_t acc[4];
    uint64_t* SP;         // scratchpad words (scratchMask+1 words)
    const uint64_t* D;    // epoch dataset words (datasetMask+1 words)
    size_t scratchMask;   // scratchWords - 1
    size_t datasetMask;   // datasetWords - 1
    uint64_t lastStores[8];
    uint64_t storePos;
    // Optional pluggable dataset reader (v2 TMTO adversarial analysis). When ds_read is null the VM
    // reads vm.D[index] directly — so v0/v1 behavior is byte-for-byte unchanged. When set, ALL
    // dataset reads (LOAD64_DATASET here, and the v2 read-chain) go through it, letting the SAME
    // consensus VM run against reduced-memory storage backends without any hand-transcribed loop.
    uint64_t (*ds_read)(void* ctx, uint64_t index) = nullptr;
    void* ds_ctx = nullptr;
    // Optional pluggable scratchpad backend (v1/v2 store-elision adversarial analysis). When
    // sp_read/sp_write are null the VM uses vm.SP directly — v0/v1 behavior byte-for-byte unchanged.
    // The scratchpad is filled directly into vm.SP by scratch-init; these hooks only intercept the
    // VM's stores/loads so store-elision attackers share the exact consensus code.
    uint64_t (*sp_read)(void* ctx, uint64_t off) = nullptr;
    void (*sp_write)(void* ctx, uint64_t off, uint64_t val) = nullptr;
    void* sp_ctx = nullptr;
};

// Read a dataset word, through the pluggable backend if present (else direct).
inline uint64_t vm_dataset_read(const VmState& vm, uint64_t index) {
    return vm.ds_read ? vm.ds_read(vm.ds_ctx, index) : vm.D[index];
}
inline uint64_t vm_scratch_read(const VmState& vm, uint64_t off) {
    return vm.sp_read ? vm.sp_read(vm.sp_ctx, off) : vm.SP[off];
}
inline void vm_scratch_write(VmState& vm, uint64_t off, uint64_t val) {
    if (vm.sp_write) vm.sp_write(vm.sp_ctx, off, val); else vm.SP[off] = val;
}

// Scratch load address with data-dependent RAW redirect to a recent store site (spec §6.2).
inline uint64_t scratch_load_addr(const VmState& vm, uint64_t v, uint64_t imm) {
    uint64_t off = (v + imm) & vm.scratchMask;
    if (((vm.acc[1] ^ v) & 3u) == 0)
        off = vm.lastStores[(vm.acc[1] >> 2) & 7u] & vm.scratchMask;
    return off;
}

// Execute one instruction, then fold the accumulator (spec §6.1, §7). Returns true if this was
// a BRANCH_IF_BIT whose bit was set (branch taken) — the caller redirects the program counter.
inline bool execute_step(VmState& vm, const Instr& I) {
    uint64_t* r = vm.r;
    uint64_t* acc = vm.acc;
    const uint8_t d = I.dst, s = I.src, a = I.aux;
    const uint64_t imm64 = (uint64_t)I.imm;
    uint64_t addr = 0, value = 0;
    bool hadMem = false, taken = false;

    switch (I.op) {
        case OP_ADD64: r[d] = r[d] + r[s] + imm64; break;
        case OP_XOR64: r[d] = r[d] ^ r[s] ^ imm64; break;
        case OP_MUL64: r[d] = r[d] * (r[s] | 1ULL); break;
        case OP_MULHI64: r[d] = mulhi64(r[d], r[s]); break;
        case OP_ROTL64: r[d] = rotl64(r[d], (unsigned)((r[s] + imm64) & 63u)); break;
        case OP_ROTR64: r[d] = rotr64(r[d], (unsigned)((r[s] + imm64) & 63u)); break;
        case OP_ADD32:
            r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] + (uint32_t)r[s] + I.imm);
            break;
        case OP_XOR32:
            r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] ^ (uint32_t)r[s] ^ I.imm);
            break;
        case OP_MUL32:
            r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] * ((uint32_t)r[s] | 1u));
            break;
        case OP_LOAD64_SCRATCH:
            addr = scratch_load_addr(vm, r[s], imm64);
            value = vm_scratch_read(vm, addr);
            r[d] = value;
            hadMem = true;
            break;
        case OP_LOAD64_DATASET:
            addr = (r[s] ^ imm64 ^ acc[0]) & vm.datasetMask;
            value = vm_dataset_read(vm, addr);
            r[d] = value;
            hadMem = true;
            break;
        case OP_STORE64:
            addr = (r[d] + imm64) & vm.scratchMask;
            value = r[s];
            vm_scratch_write(vm, addr, value);
            vm.lastStores[vm.storePos & 7u] = addr;
            vm.storePos++;
            hadMem = true;
            break;
        case OP_BRANCH_IF_BIT: taken = ((r[s] >> a) & 1u) != 0; break;
        case OP_CSELECT: r[d] = (r[s] & 1u) ? (r[d] + imm64) : (r[d] ^ r[s]); break;
        case OP_BYTE_SHUFFLE: r[d] = byte_shuffle(r[d], r[s]); break;
        default: break;  // unreachable: table maps every selector to a defined opcode
    }

    // Accumulator fold (spec §7) — includes memory address/value so work cannot be skipped.
    acc[0] = rotl64(acc[0] + (uint64_t)I.op + imm64, 1);
    acc[1] = acc[1] ^ r[d] ^ (((uint64_t)d << 3) | (uint64_t)s);
    acc[2] = acc[2] * (r[s] | 1ULL) + acc[0];
    if (hadMem)
        acc[3] = rotl64(acc[3] ^ addr, 17) + value;
    else
        acc[3] = acc[3] + acc[2];

    return taken;
}

}  // namespace meepow

#endif  // MEEPOW_VM_HPP
