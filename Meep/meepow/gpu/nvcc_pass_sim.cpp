// nvcc two-pass PARSE simulation (no GPU needed).
//
// nvcc parses the ENTIRE translation unit in BOTH its host pass and its device pass. A function
// that host code calls must therefore be *visible* in both passes, even though it is only compiled
// for the host. Guarding such a function with #if !defined(__CUDA_ARCH__) hides it from the device
// pass and produces "identifier ... is undefined" at the call site — exactly the T4 failure.
//
// This file mimics v2_gpu.cu's host main() and is compiled twice with g++ under each pass's macro
// state, catching that class of error locally.
//
// Build (device pass):  g++ -std=c++17 -fsyntax-only -D__CUDACC__ -D__CUDA_ARCH__=750 \
//                           -D__host__= -D__device__= -I. nvcc_pass_sim.cpp
// Build (host pass):    same without -D__CUDA_ARCH__
#include <stdint.h>
#include <stdlib.h>

// CUDA device intrinsic used inside an __CUDA_ARCH__ branch of the core; stub it for the sim.
static inline uint64_t __umul64hi(uint64_t a, uint64_t b) {
    uint64_t aL = a & 0xffffffffULL, aH = a >> 32, bL = b & 0xffffffffULL, bH = b >> 32;
    uint64_t ll = aL * bL, lh = aL * bH, hl = aH * bL, hh = aH * bH;
    uint64_t cr = (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    return hh + (lh >> 32) + (hl >> 32) + (cr >> 32);
}

#include "v2_cuda_core.cuh"

#include <vector>

// Mirrors v2_gpu.cu main(): host code calling the host-only dataset builder and the
// __host__ __device__ helpers, so both must be visible in whichever pass is being simulated.
int main() {
    MeepKeys hK;
    meep_init_keys(&hK);
    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    std::vector<uint64_t> D(DATASET_WORDS);
    meep_v2_build_dataset(&hK, ek, D.data());          // <-- the line that failed on the T4
    std::vector<MInstr> prog(PROG_LEN);
    std::vector<uint8_t> pb(PROG_LEN * 8);
    uint8_t fb[256];
    meep_derive_program(&hK, ek, sh, 4096, prog.data(), pb.data(), fb);
    return (int)(D[0] ^ prog[0].imm);
}
