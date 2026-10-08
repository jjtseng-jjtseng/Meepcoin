// Thin Wasm convenience wrapper over the meepow C API. Builds a dataset, hashes one nonce, and
// frees the dataset in a single call so the JS/TS side only marshals byte buffers.
// The SAME src/meepow.cpp compiles here as natively — this file adds no algorithm logic.
#include "meepow/meepow.h"

#include <algorithm>
#include <chrono>
#include <new>      // std::nothrow
#include <vector>

#include "dataset.hpp"
#include "meepow_v1.hpp"
#include "meepow_v2.hpp"
#include "dataset_v2.hpp"
#include "params_v1.hpp"

extern "C" {

// v2 reference: build a v2 dataset (32 MiB, given nparents) + ctx, hash `count` nonces (no backend),
// write count*32 bytes. For native/Wasm determinism regression.
void meep_v2_hashes(unsigned int nparents, unsigned int count, unsigned char* out) {
    using namespace meepow;
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> ds(V2_SEED_WORDS * 512);  // 32 MiB
    v2_dataset_fill(ds.data(), ds.size(), epochKey, (int)nparents);
    V1Ctx* c = v2_ctx_create(ds, epochKey, seedHash, 4096, tmpl, 8);
    for (unsigned int n = 0; n < count; ++n) v2_hash(c, n, out + (size_t)n * 32, nullptr, nullptr);
    v1_ctx_free(c);
}

// v2 reference per-hash median (ms) over `hashes` nonces, for the native:browser ratio.
double meep_v2_bench(unsigned int nparents, unsigned int hashes) {
    using namespace meepow;
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> ds(V2_SEED_WORDS * 512);
    v2_dataset_fill(ds.data(), ds.size(), epochKey, (int)nparents);
    V1Ctx* c = v2_ctx_create(ds, epochKey, seedHash, 4096, tmpl, 8);
    uint8_t h[32]; v2_hash(c, 0, h, nullptr, nullptr);
    std::vector<double> per;
    for (unsigned int n = 0; n < hashes; ++n) {
        auto a = std::chrono::steady_clock::now();
        v2_hash(c, n + 1, h, nullptr, nullptr);
        per.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - a).count());
    }
    v1_ctx_free(c);
    std::sort(per.begin(), per.end());
    return per[per.size() / 2];
}

// v1 benchmark: build a 32 MiB construction-B dataset + a v1 context for (mode, rounds), hash
// `hashes` nonces, and return the median per-hash time in ms. Used for the native:browser ratio.
double meep_v1_bench(unsigned char mode, unsigned int rounds, unsigned int hashes) {
    using namespace meepow;
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    std::vector<uint64_t> ds(V1_DATASET_WORDS);
    dataset_fill_B(ds.data(), V1_DATASET_WORDS, epochKey, 0);
    ParamSetV1 ps = v1_config(50, "v1-finalist", (ScratchMode)mode, rounds);
    V1Ctx* c = v1_ctx_create(ps, ds.data(), V1_DATASET_WORDS, epochKey, seedHash, 4096, tmpl, 32);
    uint8_t h[32];
    v1_hash(c, 0, h, nullptr, nullptr);  // warm
    std::vector<double> per;
    per.reserve(hashes);
    for (unsigned int n = 0; n < hashes; ++n) {
        auto a = std::chrono::steady_clock::now();
        v1_hash(c, n + 1, h, nullptr, nullptr);
        per.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - a).count());
    }
    v1_ctx_free(c);
    std::sort(per.begin(), per.end());
    return per[per.size() / 2];
}

// Stateful v2 (FROZEN) for browser workers: build the v2 dataset + ctx once, then hash one nonce at
// a time so the worker can measure per-hash latency and check a stop flag between hashes.
//
// THE CONTEXT IS NOW A PARAMETER, NOT A CONSTANT. meep_v2_setup() used to hard-code one synthetic
// epoch key, seed hash, height and 8-byte template, so a browser could only ever hash that one
// fixture. meep_v2_setup_ctx() takes the four consensus inputs the daemon itself supplies, which is
// what lets a worker hash a REAL MeepCoin block template.
//
// NO ALGORITHM CHANGE. These functions marshal arguments and manage lifetime. The hashing call is
// still meepow::v2_hash on a context from meepow::v2_ctx_create, with the same frozen dataset size
// (32 MiB), the same nparents=4, and the same v1 consensus pipeline. If you find yourself editing
// mixing or compression logic here, that is a bug.
//
// WHY HEIGHT ARRIVES AS TWO uint32 HALVES. The daemon's height is a uint64. JavaScript's Number
// cannot hold every uint64 exactly, so marshalling one through a `double` would silently round
// heights above 2^53 and hash a DIFFERENT context than the daemon did. Splitting it into an
// explicit (lo, hi) pair keeps the value exact on both sides of the boundary with no dependence on
// how a particular Emscripten build maps i64.
static meepow::V1Ctx* g_v2ctx = nullptr;
static std::vector<uint64_t>* g_v2ds = nullptr;
static int g_v2_active = 0;

// Mirrors meepow::v2::MAX_TEMPLATE_BYTES in include/meepow/v2.hpp. A real block hashing blob is
// ~152 bytes; this only has to refuse an absurd allocation request before it is made.
#define MEEP_V2_MAX_TEMPLATE_BYTES (1u << 20)

// Fail-closed return codes. 0 is the ONLY success value.
#define MEEP_V2_OK            0
#define MEEP_V2_ERR_NULL      1   // a required pointer was null
#define MEEP_V2_ERR_TEMPLATE  2   // template length 0 or above MEEP_V2_MAX_TEMPLATE_BYTES
#define MEEP_V2_ERR_ALLOC     3   // dataset or context allocation failed
#define MEEP_V2_ERR_NO_CTX    4   // hash requested with no active context

// Release the active context and dataset. Safe to call when nothing is active, and safe to call
// twice. After this, meep_v2_active() is 0 and meep_v2_run1_checked() refuses.
void meep_v2_teardown(void) {
    if (g_v2ctx) { meepow::v1_ctx_free(g_v2ctx); g_v2ctx = nullptr; }
    if (g_v2ds) { delete g_v2ds; g_v2ds = nullptr; }
    g_v2_active = 0;
}

// 1 when a context is live and hashing is permitted, 0 otherwise.
int meep_v2_active(void) { return g_v2_active; }

// Build a hashing context for an ARBITRARY frozen-v2 job.
//
//   epoch_key   32 bytes  -- the dataset is a pure function of this
//   seed_hash   32 bytes  -- the delayed seed block hash
//   height      (lo, hi)  -- uint64 block height, exact
//   tmpl/len              -- the block hashing blob WITH THE NONCE FIELD ZEROED
//
// The daemon (src/crypto/meep-hash.cpp) passes the SAME 32 bytes as both the epoch key and the
// seed hash, because meep_slow_hash() receives one seed hash and uses it for Dataset::create and
// Hasher::create alike. Both are taken separately here because meepow::v2_ctx_create takes them
// separately; a caller mirroring the daemon simply passes the same bytes twice.
//
// Any previous context is torn down FIRST, so a failed setup can never leave the old one active
// and a caller cannot accidentally keep hashing a stale template.
int meep_v2_setup_ctx(const unsigned char* epoch_key, const unsigned char* seed_hash,
                      unsigned int height_lo, unsigned int height_hi,
                      const unsigned char* tmpl, unsigned int tmpl_len) {
    using namespace meepow;
    meep_v2_teardown();
    if (!epoch_key || !seed_hash || !tmpl) return MEEP_V2_ERR_NULL;
    if (tmpl_len == 0 || tmpl_len > MEEP_V2_MAX_TEMPLATE_BYTES) return MEEP_V2_ERR_TEMPLATE;

    const uint64_t height = ((uint64_t)height_hi << 32) | (uint64_t)height_lo;
    const size_t words = (size_t)V2_SEED_WORDS * 512;   // 32 MiB, the frozen v2 dataset size

    std::vector<uint64_t>* ds = new (std::nothrow) std::vector<uint64_t>();
    if (!ds) return MEEP_V2_ERR_ALLOC;
    ds->resize(words);
    // Belt and braces. This build links without C++ exception catching, so a genuinely failed
    // resize aborts rather than returning; the check still catches a short allocation and keeps
    // the failure path honest rather than hashing a partly-filled dataset.
    if (ds->size() != words) { delete ds; return MEEP_V2_ERR_ALLOC; }

    v2_dataset_fill(ds->data(), ds->size(), epoch_key, 4);
    V1Ctx* c = v2_ctx_create(*ds, epoch_key, seed_hash, height, tmpl, (size_t)tmpl_len);
    if (!c) { delete ds; return MEEP_V2_ERR_ALLOC; }

    g_v2ds = ds;
    g_v2ctx = c;
    g_v2_active = 1;
    return MEEP_V2_OK;
}

// The ORIGINAL fixed synthetic context, kept verbatim as a compatibility wrapper so the existing
// local demo and the committed vectors_v2.txt known-answer vectors keep working unchanged. Every
// constant below is the one meep_v2_setup() always used.
int meep_v2_setup(void) {
    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    // height 4096, 8-byte template: the exact context vectors_v2.txt was generated from.
    return meep_v2_setup_ctx(ek, sh, 4096u, 0u, tmpl, 8u);
}

// Hash one nonce into out[32]. Returns 0 only if a hash actually happened.
//
// Prefer this over meep_v2_run1(): a use-after-teardown here is a reported error instead of a
// zeroed buffer that looks like a real result.
int meep_v2_run1_checked(unsigned int nonce, unsigned char* out) {
    if (!out) return MEEP_V2_ERR_NULL;
    if (!g_v2_active || !g_v2ctx) return MEEP_V2_ERR_NO_CTX;
    meepow::v2_hash(g_v2ctx, nonce, out, nullptr, nullptr);
    return MEEP_V2_OK;
}

// Legacy void-returning entry point. It cannot report failure, so with no active context it now
// writes 32 zero bytes instead of dereferencing a null context. Zeros are NOT a valid result --
// callers that need to tell the difference must use meep_v2_run1_checked().
void meep_v2_run1(unsigned int nonce, unsigned char* out) {
    static uint8_t scratch[32];
    unsigned char* dst = out ? out : scratch;
    if (!g_v2_active || !g_v2ctx) { for (int i = 0; i < 32; ++i) dst[i] = 0; return; }
    meepow::v2_hash(g_v2ctx, nonce, dst, nullptr, nullptr);
}

// Stateful v1 for browser workers: setup once (build dataset + ctx), then hash one nonce at a
// time so the worker can measure per-hash latency and check a stop flag between hashes.
static meepow::V1Ctx* g_v1ctx = nullptr;
static std::vector<uint64_t>* g_v1ds = nullptr;

int meep_v1_setup(unsigned char profile) {
    using namespace meepow;
    if (g_v1ctx) { v1_ctx_free(g_v1ctx); g_v1ctx = nullptr; }
    if (g_v1ds) { delete g_v1ds; g_v1ds = nullptr; }
    ParamSetV1 ps = (profile == 0) ? v1_config(50, "v1-finalist", SCRATCH_S3, V1_ROUNDS_50X)
                                   : v1_fast(SCRATCH_S3);
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    g_v1ds = new std::vector<uint64_t>(ps.dataset_words);
    dataset_fill_B(g_v1ds->data(), ps.dataset_words, epochKey, 0);
    g_v1ctx = v1_ctx_create(ps, g_v1ds->data(), ps.dataset_words, epochKey, seedHash, 4096, tmpl, 32);
    return g_v1ctx ? 0 : 1;
}

// Hash one nonce reusing the setup context; writes 32 bytes to out (may be 0 to discard).
void meep_v1_run1(unsigned int nonce, unsigned char* out) {
    static uint8_t scratch[32];
    meepow::v1_hash(g_v1ctx, nonce, out ? out : scratch, nullptr, nullptr);
}

// v1 determinism: write `count` consecutive 32-byte hashes (nonces 0..count-1) for a fixed
// profile into out. profile 0 = finalist (S3, 400 rounds, 32 MiB/8 MiB); 1 = v1-fast (tiny).
// Native and Wasm must produce identical bytes.
void meep_v1_hashes(unsigned char profile, unsigned int count, unsigned char* out) {
    using namespace meepow;
    ParamSetV1 ps = (profile == 0) ? v1_config(50, "v1-finalist", SCRATCH_S3, V1_ROUNDS_50X)
                                   : v1_fast(SCRATCH_S3);
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 7 + 1); seedHash[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> ds(ps.dataset_words);
    dataset_fill_B(ds.data(), ps.dataset_words, epochKey, 0);
    V1Ctx* c = v1_ctx_create(ps, ds.data(), ps.dataset_words, epochKey, seedHash, 4096, tmpl, 8);
    for (unsigned int n = 0; n < count; ++n) v1_hash(c, n, out + (size_t)n * 32, nullptr, nullptr);
    v1_ctx_free(c);
}

// Returns 0 on success. out_hash[32] required; out_c1[32]/out_ch[32] optional (may be null).
int meep_run_hash(unsigned char param, unsigned char construction, const unsigned char* epoch_key,
                  const unsigned char* seed_block_hash, unsigned long long block_height,
                  const unsigned char* template_blob, unsigned long template_len,
                  unsigned int nonce, unsigned char* out_hash, unsigned char* out_c1,
                  unsigned char* out_ch) {
    meepow_dataset* ds = meepow_dataset_create(param, construction, epoch_key);
    if (!ds) return 2;
    int rc = meepow_hash(ds, seed_block_hash, (unsigned long long)block_height, template_blob,
                         (size_t)template_len, nonce, out_hash, out_c1, out_ch);
    meepow_dataset_free(ds);
    return rc;
}

}  // extern "C"
