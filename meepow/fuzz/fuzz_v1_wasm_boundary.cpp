// libFuzzer: v1 wasm-export boundary logic — arbitrary profile + bounded count writes exactly
// count*32 bytes and never overruns (mirrors meep_v1_hashes / meep_v1_setup+run1).
#include <cstdint>
#include <cstddef>
#include <vector>
#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"
using namespace meepow;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size<2) return 0;
  unsigned char profile=data[0];
  unsigned count=(data[1]%8);           // bounded, like a small worker batch
  ParamSetV1 ps=(profile==0)?v1_fast(SCRATCH_S3):v1_fast((ScratchMode)((profile%3)+1));
  uint8_t ek[32]={3}, sh[32]={4}, tm[32]={0};
  std::vector<uint64_t> ds(ps.dataset_words); dataset_fill_B(ds.data(),ps.dataset_words,ek,0);
  V1Ctx* c=v1_ctx_create(ps, ds.data(), ps.dataset_words, ek, sh, 4096, tm, 4);
  if(!c) return 0;
  std::vector<uint8_t> out(count?count*32:32,0);
  for(unsigned n=0;n<count;++n) v1_hash(c,n,out.data()+(size_t)n*32,nullptr,nullptr);
  v1_ctx_free(c);
  return 0;
}
