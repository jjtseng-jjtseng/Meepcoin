// libFuzzer: v2 dataset word generation/reconstruction must stay in bounds and terminate for
// arbitrary seeds (parents are data-dependent; indices must always be < w).
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "dataset_v2.hpp"
using namespace meepow;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 40) return 0;
  // small dataset so every fuzz input is cheap; structure identical to the frozen construction
  static std::vector<uint64_t>* ds = nullptr;
  if (!ds) { ds = new std::vector<uint64_t>(V2_SEED_WORDS * 2); }
  uint8_t ek[32]; std::memcpy(ek, data, 32);
  int np = 1 + (data[32] % 4);
  v2_dataset_fill(ds->data(), ds->size(), ek, np);
  // single-word recompute path (the shared v2_word used by every adversary)
  uint64_t ops = 0;
  size_t w = V2_SEED_WORDS + (size_t)(data[33] | (data[34] << 8)) % (ds->size() - V2_SEED_WORDS);
  uint64_t v = v2_word(w, (*ds)[0], np, [&](size_t i) { if (i >= ds->size()) __builtin_trap(); return (*ds)[i]; }, ops);
  if (v != (*ds)[w]) __builtin_trap();   // recompute must equal generation
  return 0;
}
