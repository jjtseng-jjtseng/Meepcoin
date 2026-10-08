// libFuzzer: v1 dataset read-chain address must always be in bounds.
#include <cstdint>
#include <cstddef>
#include "endian.hpp"
using namespace meepow;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size<24) return 0;
  for(size_t off=0; off+24<=size; off+=24){
    uint64_t acc2=load_u64_le(data+off), r=load_u64_le(data+off+8);
    uint64_t dmask=(1ull<<(load_u64_le(data+off+16)%24|1))-1; // arbitrary power-of-two mask
    uint64_t da=(acc2^r)&dmask; if(da>dmask) __builtin_trap();
  }
  return 0;
}
