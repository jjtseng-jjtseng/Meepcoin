// libFuzzer target: executing arbitrary decoded programs over arbitrary state must not invoke
// UB or access memory out of bounds (ASan/UBSan enforce this).
#include <cstdint>
#include <cstddef>
#include <vector>

#include "endian.hpp"
#include "params.hpp"
#include "program.hpp"
#include "vm.hpp"

using namespace meepow;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 96) return 0;
    uint8_t table[256];
    build_opcode_table(table);

    const size_t scratchWords = 512, datasetWords = 512;
    std::vector<uint64_t> sp(scratchWords), ds(datasetWords);
    for (size_t i = 0; i < scratchWords; ++i) sp[i] = 0x9E3779B97F4A7C15ULL * (i + 1);
    for (size_t i = 0; i < datasetWords; ++i) ds[i] = 0xD1B54A32D192ED03ULL * (i + 1);

    VmState vm{};
    vm.SP = sp.data();
    vm.D = ds.data();
    vm.scratchMask = scratchWords - 1;
    vm.datasetMask = datasetWords - 1;
    for (int i = 0; i < 8; ++i) vm.r[i] = load_u64_le(data + i * 8);
    for (int i = 0; i < 4; ++i) vm.acc[i] = load_u64_le(data + 64 + i * 8);
    vm.storePos = 0;

    // Decode and execute up to a bounded number of instructions from the remaining bytes.
    size_t pos = 96;
    int budget = 4096;
    while (pos + 8 <= size && budget-- > 0) {
        Instr ins = decode_instr(data + pos, table);
        (void)execute_step(vm, ins);
        pos += 8;
    }
    return 0;
}
