// VM program decoding (spec §5, §6). Every 8-byte word decodes to a valid instruction.
#ifndef MEEPOW_PROGRAM_HPP
#define MEEPOW_PROGRAM_HPP

#include <cstdint>

#include "endian.hpp"
#include "params.hpp"

namespace meepow {

struct Instr {
    uint8_t op;   // Opcode
    uint8_t dst;  // 0..7
    uint8_t src;  // 0..7
    uint8_t aux;  // 0..63 (branch bit index / shuffle control)
    uint32_t imm;
};

// Decode one 8-byte instruction word (spec §5) using a prebuilt 256-entry opcode table.
inline Instr decode_instr(const uint8_t* p, const uint8_t opcode_table[256]) {
    Instr ins;
    ins.op = opcode_table[p[0]];
    ins.dst = p[1] & 7u;
    ins.src = p[2] & 7u;
    ins.aux = p[3] & 63u;
    ins.imm = load_u32_le(p + 4);
    return ins;
}

}  // namespace meepow

#endif  // MEEPOW_PROGRAM_HPP
