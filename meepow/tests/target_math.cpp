// Verify floor((2^256-1)/d) by independent base-2^32 multiplication.
#include "target.hpp"
#include <array>
#include <cstdint>
#include <cstdio>

static bool verify(uint64_t d) {
    uint8_t target[32];
    if (!meepow::difficulty_to_target(d, target)) return false;
    uint32_t q[8];
    for (unsigned i = 0; i < 8; ++i) {
        q[i] = uint32_t(target[4*i]) | (uint32_t(target[4*i+1]) << 8) |
            (uint32_t(target[4*i+2]) << 16) | (uint32_t(target[4*i+3]) << 24);
    }
    const uint32_t divisor[2] = {uint32_t(d), uint32_t(d >> 32)};
    std::array<uint32_t, 10> product{};
    for (unsigned i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (unsigned j = 0; j < 2; ++j) {
            const uint64_t sum = uint64_t(q[i]) * divisor[j] + product[i+j] + carry;
            product[i+j] = uint32_t(sum);
            carry = sum >> 32;
        }
        product[i+2] = uint32_t(carry);
    }
    // q*d <= 2^256-1, but q*d+d must exceed it. These two inequalities
    // uniquely determine the quotient, without using division or 128-bit math.
    if (product[8] || product[9]) return false;
    uint64_t carry = 0;
    for (unsigned i = 0; i < 10; ++i) {
        const uint64_t sum = uint64_t(product[i]) + (i < 2 ? divisor[i] : 0) + carry;
        product[i] = uint32_t(sum);
        carry = sum >> 32;
    }
    return product[8] || product[9] || carry;
}

int main() {
    uint8_t untouched[32];
    for (auto& b : untouched) b = 0x5a;
    if (meepow::difficulty_to_target(0, untouched)) return 1;
    for (auto b : untouched) if (b != 0x5a) return 1;
    unsigned checked = 0;
    for (unsigned bit = 0; bit < 64; ++bit) {
        const uint64_t pivot = uint64_t(1) << bit;
        for (uint64_t d : {pivot, pivot + 1, pivot == 1 ? uint64_t(1) : pivot - 1}) {
            if (!verify(d)) return 1;
            ++checked;
        }
    }
    if (!verify(UINT64_MAX)) return 1;
    ++checked;
    uint64_t random = 0x5d9d34ca109b2e71ULL;
    for (unsigned i = 0; i < 10000; ++i) {
        random ^= random << 13; random ^= random >> 7; random ^= random << 17;
        if (!verify(random ? random : 1)) return 1;
        ++checked;
    }
    std::printf("TARGET_MATH_PASS %u independent quotient checks; zero rejected without output mutation\n", checked);
}
