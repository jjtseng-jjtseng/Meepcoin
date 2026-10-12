// libFuzzer target: instruction decoding must accept every byte sequence and keep fields in range.
#include <cstdint>
#include <cstddef>

#include "params.hpp"
#include "program.hpp"

using namespace meepow;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t table[256];
    build_opcode_table(table);
    for (size_t off = 0; off + 8 <= size; off += 8) {
        Instr ins = decode_instr(data + off, table);
        if (ins.op >= OP__COUNT) __builtin_trap();
        if (ins.dst > 7 || ins.src > 7 || ins.aux > 63) __builtin_trap();
    }
    return 0;
}
