// libFuzzer: full frozen-v2 hash pipeline (small profile) over arbitrary block inputs.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "endian.hpp"
#include "dataset_v2.hpp"
#include "meepow_v2.hpp"
using namespace meepow;
static std::vector<uint64_t>* g = nullptr;
static uint8_t g_ek[32];
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 44) return 0;
  if (!g) { for (int i=0;i<32;++i) g_ek[i]=(uint8_t)(i+1); g = new std::vector<uint64_t>(V2_SEED_WORDS*2); v2_dataset_fill(g->data(), g->size(), g_ek, 4); }
  ParamSetV1 ps = v1_fast(SCRATCH_S3);
  ps.dataset_words = g->size();
  uint8_t sh[32]; std::memcpy(sh, data, 32);
  uint64_t height = load_u64_le(data+32);
  uint32_t nonce = load_u32_le(data+40);
  size_t tlen = size > 44 ? (size-44 < 64 ? size-44 : 64) : 0;
  V1Ctx* c = v1_ctx_create(ps, g->data(), g->size(), g_ek, sh, height, data+44, tlen);
  if (!c) return 0;
  uint8_t h[32];
  v2_hash(c, nonce, h, nullptr, nullptr);
  v1_ctx_free(c);
  return 0;
}
