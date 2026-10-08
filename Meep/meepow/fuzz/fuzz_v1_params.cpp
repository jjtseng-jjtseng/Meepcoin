// libFuzzer: v1 parameter selection must yield valid power-of-two sizes / no overflow.
#include <cstdint>
#include <cstddef>
#include "endian.hpp"
#include "params_v1.hpp"
using namespace meepow;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size<8) return 0;
  uint8_t m=data[0]%3; ScratchMode mode=(ScratchMode)(m+1);
  uint32_t rounds=1+(load_u32_le(data+1)%512);
  ParamSetV1 ps=v1_config(50,"f",mode,rounds);
  if(ps.scratch_words==0 || (ps.scratch_words&(ps.scratch_words-1))) __builtin_trap();
  if(ps.dataset_words==0 || (ps.dataset_words&(ps.dataset_words-1))) __builtin_trap();
  if(ps.steps_per_round==0 || ps.program_len==0) __builtin_trap();
  ParamSetV1 pf=v1_fast(mode);
  if(pf.scratch_words&(pf.scratch_words-1)) __builtin_trap();
  return 0;
}
