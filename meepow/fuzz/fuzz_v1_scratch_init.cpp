// libFuzzer: S3 scratchpad initialization must stay in bounds for arbitrary seeds (ASan/UBSan).
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"
using namespace meepow;
static V1Ctx* g=nullptr; static std::vector<uint64_t>* gds=nullptr;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  if(size<96) return 0;
  if(!g){ ParamSetV1 ps=v1_fast(SCRATCH_S3); uint8_t ek[32]={1},sh[32]={2},tm[8]={0};
    gds=new std::vector<uint64_t>(ps.dataset_words); dataset_fill_B(gds->data(),ps.dataset_words,ek,0);
    g=v1_ctx_create(ps,gds->data(),ps.dataset_words,ek,sh,0,tm,8); }
  uint8_t seed[96]; std::memcpy(seed,data,96);
  v1_scratch_init(g,(uint32_t)data[0],seed);
  return 0;
}
