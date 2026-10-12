// libFuzzer target: memory addressing must always stay within bounds for arbitrary state.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

#include "endian.hpp"
#include "params.hpp"
#include "vm.hpp"

using namespace meepow;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 64) return 0;
    // Small power-of-two scratch/dataset so out-of-range access would be caught by ASan.
    const size_t scratchWords = 256, datasetWords = 256;
    std::vector<uint64_t> sp(scratchWords), ds(datasetWords);
    VmState vm{};
    vm.SP = sp.data();
    vm.D = ds.data();
    vm.scratchMask = scratchWords - 1;
    vm.datasetMask = datasetWords - 1;
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(data + (i % 6) * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(data + 8 + (i % 6) * 8);
    for (int i = 0; i < 8; ++i) vm.lastStores[i] = load_u64_le(data + (i % 7) * 8);
    vm.storePos = data[0];

    for (size_t off = 0; off + 12 <= size; off += 12) {
        uint64_t v = load_u64_le(data + off);
        uint32_t imm = load_u32_le(data + off + 8);
        uint64_t a1 = scratch_load_addr(vm, v, imm);
        if (a1 > vm.scratchMask) __builtin_trap();
        uint64_t a2 = (v ^ (uint64_t)imm ^ vm.acc[0]) & vm.datasetMask;  // dataset addr (spec §4.3)
        if (a2 > vm.datasetMask) __builtin_trap();
        (void)vm.SP[a1];
        (void)vm.D[a2];
    }
    return 0;
}
