// libFuzzer: full v1 hash pipeline (fast profile) must not crash/UB for arbitrary block inputs.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "endian.hpp"
#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"
using namespace meepow;
static std::vector<uint64_t>* gds=nullptr; static uint8_t g_ek[32];
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size<44) return 0;
  ParamSetV1 ps=v1_fast(SCRATCH_S3);
  if(!gds){ for(int i=0;i<32;++i) g_ek[i]=(uint8_t)(i+1); gds=new std::vector<uint64_t>(ps.dataset_words); dataset_fill_B(gds->data(),ps.dataset_words,g_ek,0); }
  uint8_t sh[32]; std::memcpy(sh,data,32);
  uint64_t height=load_u64_le(data+32);
  uint32_t nonce=load_u32_le(data+40);
  size_t tlen = size>44 ? (size-44<64?size-44:64) : 0;
  V1Ctx* c=v1_ctx_create(ps, gds->data(), ps.dataset_words, g_ek, sh, height, data+44, tlen);
  if(!c) return 0;
  uint8_t h[32], c1[32], ch[32];
  v1_hash(c,nonce,h,c1,ch);
  v1_ctx_free(c);
  return 0;
}
