// libFuzzer: the pluggable dataset backend + strict attacker reconstruction must be memory-safe and
// EXACT for arbitrary retained sets (a lossless backend must reproduce the true dataset word).
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "dataset_v2.hpp"
#include "tmto_strict2.hpp"
using namespace meepow;
static std::vector<uint64_t>* g = nullptr;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) return 0;
  static uint8_t ek[32];
  if (!g) { for (int i=0;i<32;++i) ek[i]=(uint8_t)(i*3+1); g = new std::vector<uint64_t>(V2_SEED_WORDS*2); v2_dataset_fill(g->data(), g->size(), ek, 4); }
  Attacker2 a;
  size_t budget = (size_t)(g->size()*8) / (1 + (data[0] % 8));   // arbitrary budget fraction
  CacheRep rep = (CacheRep)(data[1] % 8);
  a2_init(a, *g, 4, budget, rep);
  size_t idx = V2_SEED_WORDS + ((size_t)data[2] | ((size_t)data[3] << 8)) % (g->size() - V2_SEED_WORDS);
  uint64_t v = a2_read(&a, idx);
  if (v != (*g)[idx]) __builtin_trap();   // lossless backends must be EXACT
  return 0;
}
