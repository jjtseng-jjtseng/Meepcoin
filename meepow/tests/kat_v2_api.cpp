/*
 * Known-answer tests for the MeepHash-W v2 public integration surface.
 *
 * The point of this test is NOT that "v2 works" — that is already established by the frozen
 * vectors. The point is that the NEW PUBLIC ENTRY POINTS reach the same frozen implementation and
 * produce byte-identical results. Every public hashing path is exercised against the committed
 * meepow/vectors/vectors_v2.txt:
 *
 *   1. C++  Hasher::hash()                     (single)
 *   2. C++  Hasher::hash_batch()               (batch, whole range)
 *   3. C++  Hasher::hash_batch()               (batch, split into chunks at an offset)
 *   4. C    meepow_v2_hash()                   (single)
 *   5. C    meepow_v2_hash_batch()             (batch)
 *   6. internal frozen meepow::v2_hash()       (the path that generated the vectors)
 *
 * Plus: dataset reuse across hashers, error paths, epoch scheduling, difficulty/target, and a
 * thread-safety check that N hashers sharing ONE dataset agree with the single-threaded results.
 *
 * Usage: meepow-kat-v2-api <path/to/vectors_v2.txt>
 */
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "meepow/v2.hpp"
#include "meepow/v2_c.h"

// The internal frozen path, for the direct cross-check (case 6).
#include "dataset_v2.hpp"
#include "meepow_v2.hpp"

namespace v2 = meepow::v2;

static int g_failures = 0;
static int g_checks = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) { ++g_failures; std::printf("  FAIL  %s\n", what); }
    else       { std::printf("  ok    %s\n", what); }
}

static std::string to_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) { s[i * 2] = d[p[i] >> 4]; s[i * 2 + 1] = d[p[i] & 15]; }
    return s;
}

// --- the exact inputs that produced vectors_v2.txt (benchmarks/v2_validate.cpp) ----------------
struct VectorInputs {
    uint8_t epoch_key[32];
    uint8_t seed_hash[32];
    uint8_t tmpl[8];
    uint64_t height;
};
static VectorInputs vector_inputs() {
    VectorInputs v{};
    for (int i = 0; i < 32; ++i) {
        v.epoch_key[i] = (uint8_t)(i * 7 + 1);
        v.seed_hash[i] = (uint8_t)(i * 3 + 9);
    }
    for (int i = 0; i < 8; ++i) v.tmpl[i] = (uint8_t)(i + 1);
    v.height = 4096;
    return v;
}

// Parse "v2 <nparents> <nonce> <hex64>" lines into an ordered list of expected hex hashes.
static bool load_vectors(const char* path, std::vector<std::string>& out) {
    std::FILE* f = std::fopen(path, "r");
    if (!f) return false;
    char line[512];
    while (std::fgets(line, sizeof(line), f)) {
        char tag[8]; unsigned np, nonce; char hex[128];
        if (std::sscanf(line, "%7s %u %u %127s", tag, &np, &nonce, hex) == 4 &&
            std::strcmp(tag, "v2") == 0) {
            if (out.size() != nonce) { std::fclose(f); return false; }  // must be dense, in order
            out.emplace_back(hex);
        }
    }
    std::fclose(f);
    return !out.empty();
}

int main(int argc, char** argv) {
    const char* vpath = argc > 1 ? argv[1] : "vectors/vectors_v2.txt";
    std::vector<std::string> expect;
    if (!load_vectors(vpath, expect)) {
        std::printf("FATAL: could not load vectors from %s\n", vpath);
        return 2;
    }
    const size_t N = expect.size();
    std::printf("loaded %zu committed v2 vectors from %s\n\n", N, vpath);

    const VectorInputs vi = vector_inputs();

    // ------------------------------------------------------------------------------------------
    std::printf("[constants] frozen identity exposed by the API\n");
    check(v2::ALGO_VERSION == 2, "ALGO_VERSION == 2");
    check(v2::PARAM_SET_ID == 60, "PARAM_SET_ID == 60");
    check(v2::DATASET_BYTES == 32u << 20, "DATASET_BYTES == 32 MiB");
    check(v2::SCRATCHPAD_BYTES == 8u << 20, "SCRATCHPAD_BYTES == 8 MiB");
    check(v2::TOTAL_VM_STEPS == 102400, "TOTAL_VM_STEPS == 102400");
    check(v2::EPOCH_LENGTH == 2048 && v2::EPOCH_DELAY == 64, "epoch schedule 2048/64");

    // ------------------------------------------------------------------------------------------
    std::printf("\n[dataset] build once, reuse for every entry point\n");
    v2::Error err = v2::Error::Ok;
    auto ds = v2::Dataset::create(vi.epoch_key, &err);
    check(ds != nullptr && err == v2::Error::Ok, "Dataset::create succeeds");
    if (!ds) { std::printf("FATAL: no dataset\n"); return 2; }
    check(ds->size_bytes() == v2::DATASET_BYTES, "dataset is 32 MiB");
    check(std::memcmp(ds->epoch_key(), vi.epoch_key, 32) == 0, "dataset retains its epoch key");

    auto hasher = v2::Hasher::create(*ds, vi.seed_hash, vi.height, vi.tmpl, sizeof(vi.tmpl), &err);
    check(hasher != nullptr && err == v2::Error::Ok, "Hasher::create succeeds");
    if (!hasher) { std::printf("FATAL: no hasher\n"); return 2; }
    check(hasher->block_height() == vi.height, "Hasher reports its block height");

    // --- 1. C++ single ------------------------------------------------------------------------
    std::printf("\n[1/6] C++ Hasher::hash() vs committed vectors\n");
    {
        size_t bad = 0;
        for (size_t n = 0; n < N; ++n) {
            uint8_t h[32];
            if (hasher->hash((uint32_t)n, h) != v2::Error::Ok) { ++bad; continue; }
            if (to_hex(h, 32) != expect[n]) ++bad;
        }
        check(bad == 0, "all vectors reproduced through C++ single-hash");
    }

    // --- 2. C++ batch, whole range ------------------------------------------------------------
    std::printf("\n[2/6] C++ Hasher::hash_batch() vs committed vectors\n");
    {
        std::vector<uint8_t> out(N * 32);
        v2::Error e = hasher->hash_batch(0, N, out.data(), out.size());
        check(e == v2::Error::Ok, "hash_batch returns Ok");
        size_t bad = 0;
        for (size_t n = 0; n < N; ++n)
            if (to_hex(out.data() + n * 32, 32) != expect[n]) ++bad;
        check(bad == 0, "all vectors reproduced through C++ batch");
    }

    // --- 3. C++ batch, chunked at an offset ---------------------------------------------------
    std::printf("\n[3/6] C++ hash_batch() chunked (offset ranges must match too)\n");
    {
        const uint32_t first = 5, count = 7;
        std::vector<uint8_t> out(count * 32);
        v2::Error e = hasher->hash_batch(first, count, out.data(), out.size());
        check(e == v2::Error::Ok, "chunked hash_batch returns Ok");
        size_t bad = 0;
        for (uint32_t i = 0; i < count; ++i)
            if (to_hex(out.data() + i * 32, 32) != expect[first + i]) ++bad;
        check(bad == 0, "offset batch matches the corresponding vectors");
    }

    // --- 4/5. C ABI ---------------------------------------------------------------------------
    std::printf("\n[4/6] C ABI meepow_v2_hash() vs committed vectors\n");
    {
        meepow_v2_dataset* cds = nullptr;
        int rc = meepow_v2_dataset_create(vi.epoch_key, &cds);
        check(rc == MEEPOW_V2_OK && cds != nullptr, "meepow_v2_dataset_create succeeds");
        check(meepow_v2_dataset_size_bytes(cds) == MEEPOW_V2_DATASET_BYTES, "C dataset is 32 MiB");

        meepow_v2_hasher* ch = nullptr;
        rc = meepow_v2_hasher_create(cds, vi.seed_hash, vi.height, vi.tmpl, sizeof(vi.tmpl), &ch);
        check(rc == MEEPOW_V2_OK && ch != nullptr, "meepow_v2_hasher_create succeeds");

        size_t bad = 0;
        for (size_t n = 0; n < N; ++n) {
            uint8_t h[32];
            if (meepow_v2_hash(ch, (uint32_t)n, h) != MEEPOW_V2_OK) { ++bad; continue; }
            if (to_hex(h, 32) != expect[n]) ++bad;
        }
        check(bad == 0, "all vectors reproduced through C ABI single-hash");

        std::printf("\n[5/6] C ABI meepow_v2_hash_batch() vs committed vectors\n");
        std::vector<uint8_t> out(N * 32);
        rc = meepow_v2_hash_batch(ch, 0, N, out.data(), out.size());
        check(rc == MEEPOW_V2_OK, "meepow_v2_hash_batch returns OK");
        bad = 0;
        for (size_t n = 0; n < N; ++n)
            if (to_hex(out.data() + n * 32, 32) != expect[n]) ++bad;
        check(bad == 0, "all vectors reproduced through C ABI batch");

        meepow_v2_hasher_free(ch);
        meepow_v2_dataset_free(cds);
        meepow_v2_hasher_free(nullptr);   // must be a safe no-op
        meepow_v2_dataset_free(nullptr);
        check(true, "freeing NULL handles is a no-op");
    }

    // --- 6. direct frozen path ----------------------------------------------------------------
    std::printf("\n[6/6] internal frozen meepow::v2_hash() (the vector-generating path)\n");
    {
        std::vector<uint64_t> raw(meepow::V2_SEED_WORDS * 512);
        meepow::v2_dataset_fill(raw.data(), raw.size(), vi.epoch_key, 4);
        meepow::V1Ctx* c = meepow::v2_ctx_create(raw, vi.epoch_key, vi.seed_hash, vi.height,
                                                 vi.tmpl, sizeof(vi.tmpl));
        size_t bad = 0;
        for (size_t n = 0; n < N; ++n) {
            uint8_t h[32];
            meepow::v2_hash(c, (uint32_t)n, h, nullptr, nullptr);
            if (to_hex(h, 32) != expect[n]) ++bad;
        }
        meepow::v1_ctx_free(c);
        check(bad == 0, "frozen path still reproduces the vectors (API adds no divergence)");
    }

    // --- dataset reuse ------------------------------------------------------------------------
    std::printf("\n[reuse] a second Hasher on the SAME dataset agrees\n");
    {
        auto h2 = v2::Hasher::create(*ds, vi.seed_hash, vi.height, vi.tmpl, sizeof(vi.tmpl), &err);
        check(h2 != nullptr, "second Hasher from the same Dataset");
        size_t bad = 0;
        for (size_t n = 0; n < N && h2; ++n) {
            uint8_t h[32];
            h2->hash((uint32_t)n, h);
            if (to_hex(h, 32) != expect[n]) ++bad;
        }
        check(bad == 0, "second Hasher reproduces the vectors");
    }

    // --- thread safety ------------------------------------------------------------------------
    std::printf("\n[threads] 4 Hashers sharing ONE immutable Dataset, concurrently\n");
    {
        const int T = 4;
        std::atomic<size_t> bad{0};
        std::vector<std::thread> th;
        for (int t = 0; t < T; ++t) th.emplace_back([&, t]{
            v2::Error e;
            auto hh = v2::Hasher::create(*ds, vi.seed_hash, vi.height, vi.tmpl, sizeof(vi.tmpl), &e);
            if (!hh) { bad += N; return; }
            for (size_t n = t; n < N; n += T) {     // disjoint nonce subsets
                uint8_t h[32];
                hh->hash((uint32_t)n, h);
                if (to_hex(h, 32) != expect[n]) ++bad;
            }
        });
        for (auto& x : th) x.join();
        check(bad.load() == 0, "concurrent hashers on a shared dataset match the vectors");
    }

    // --- error handling -----------------------------------------------------------------------
    std::printf("\n[errors] explicit failure modes\n");
    {
        v2::Error e;
        check(v2::Dataset::create(nullptr, &e) == nullptr && e == v2::Error::NullArgument,
              "Dataset::create(nullptr) -> NullArgument");
        check(v2::Hasher::create(*ds, vi.seed_hash, 0, vi.tmpl, 0, &e) == nullptr &&
              e == v2::Error::InvalidTemplate, "zero-length template -> InvalidTemplate");
        check(v2::Hasher::create(*ds, vi.seed_hash, 0, vi.tmpl, v2::MAX_TEMPLATE_BYTES + 1, &e)
                  == nullptr && e == v2::Error::InvalidTemplate,
              "oversize template -> InvalidTemplate");
        check(v2::Hasher::create(*ds, nullptr, 0, vi.tmpl, 8, &e) == nullptr &&
              e == v2::Error::NullArgument, "null seed hash -> NullArgument");

        check(hasher->hash(0, nullptr) == v2::Error::NullArgument, "hash(null out) -> NullArgument");

        uint8_t small[32];
        check(hasher->hash_batch(0, 2, small, sizeof(small)) == v2::Error::BufferTooSmall,
              "batch into an undersized buffer -> BufferTooSmall");
        check(hasher->hash_batch(0, 0, small, sizeof(small)) == v2::Error::InvalidCount,
              "batch count 0 -> InvalidCount");
        std::vector<uint8_t> big(64);
        check(hasher->hash_batch(UINT32_MAX, 2, big.data(), big.size()) == v2::Error::InvalidCount,
              "nonce range overflowing uint32 -> InvalidCount");

        check(meepow_v2_hash(nullptr, 0, small) == MEEPOW_V2_ERR_NULL_ARGUMENT,
              "C ABI null hasher -> NULL_ARGUMENT");
        check(meepow_v2_dataset_create(nullptr, nullptr) == MEEPOW_V2_ERR_NULL_ARGUMENT,
              "C ABI null out-param -> NULL_ARGUMENT");
        check(std::strcmp(meepow_v2_error_string(MEEPOW_V2_OK), "ok") == 0,
              "error_string(OK) == \"ok\"");
        check(meepow_v2_error_string(999) != nullptr, "error_string(unknown) is never NULL");
    }

    // --- epoch scheduling ---------------------------------------------------------------------
    std::printf("\n[epoch] schedule arithmetic and reorg semantics\n");
    {
        check(v2::epoch_index(0) == 0 && v2::epoch_index(64) == 0, "heights <= 64 are epoch 0");
        check(v2::epoch_index(65) == 0, "height 65 -> epoch 0 (1/2048)");
        check(v2::epoch_index(2112) == 1, "height 2112 (=2048+64) -> epoch 1");
        check(v2::epoch_index(4160) == 2, "height 4160 (=4096+64) -> epoch 2");

        uint64_t h = 0;
        check(!v2::epoch_source_height(100, &h), "epoch 0 has no source height (genesis seed)");
        check(v2::epoch_source_height(2112, &h) && h == 2047, "epoch 1 source height == 2047");
        check(v2::epoch_source_height(4160, &h) && h == 4095, "epoch 2 source height == 4095");

        check(!v2::seed_block_height(63, &h), "height < 64 uses the genesis seed block");
        check(v2::seed_block_height(4096, &h) && h == 4032, "seed block for 4096 is 4032");

        // Reorg: the key changes iff its source height lies strictly above the fork point.
        check(v2::epoch_key_changes_on_reorg(2112, 2046), "fork below source -> epoch key changes");
        check(!v2::epoch_key_changes_on_reorg(2112, 2047), "fork at source -> key unchanged");
        check(!v2::epoch_key_changes_on_reorg(2112, 3000), "fork above source -> key unchanged");
        check(v2::seed_block_changes_on_reorg(4096, 4031), "fork below seed block -> changes");
        check(!v2::seed_block_changes_on_reorg(4096, 4032), "fork at seed block -> unchanged");

        // C ABI agrees with C++.
        uint64_t ch = 0;
        check(meepow_v2_epoch_index(2112) == 1, "C ABI epoch_index agrees");
        check(meepow_v2_epoch_source_height(2112, &ch) == 1 && ch == 2047,
              "C ABI epoch_source_height agrees");
        check(meepow_v2_seed_block_height(4096, &ch) == 1 && ch == 4032,
              "C ABI seed_block_height agrees");
    }

    // --- difficulty / target ------------------------------------------------------------------
    std::printf("\n[target] difficulty conversion and comparison\n");
    {
        uint8_t tgt[32];
        check(v2::difficulty_to_target(0, tgt) == v2::Error::InvalidDifficulty,
              "difficulty 0 -> InvalidDifficulty");
        check(v2::difficulty_to_target(1, tgt) == v2::Error::Ok, "difficulty 1 -> Ok");
        bool all_ff = true;
        for (int i = 0; i < 32; ++i) if (tgt[i] != 0xff) all_ff = false;
        check(all_ff, "difficulty 1 -> target is 2^256-1 (all 0xff)");

        uint8_t zero[32] = {0};
        check(v2::hash_meets_target(zero, tgt), "hash 0 meets the maximum target");
        check(v2::hash_meets_target(tgt, tgt), "hash exactly equal to target passes");

        // target(2) = 0x7fff...ffff, so the LOW limb is all-ones: incrementing byte 0 would wrap
        // downward. Add 1 with carry across the little-endian buffer instead.
        uint8_t t2[32];
        v2::difficulty_to_target(2, t2);
        uint8_t just_over[32];
        std::memcpy(just_over, t2, 32);
        for (int i = 0; i < 32; ++i) { if (++just_over[i] != 0) break; }   // +1, LE carry
        check(!v2::hash_meets_target(just_over, t2), "hash exactly one above target fails");

        uint8_t just_under[32];
        std::memcpy(just_under, t2, 32);
        for (int i = 0; i < 32; ++i) { if (just_under[i]-- != 0) break; }  // -1, LE borrow
        check(v2::hash_meets_target(just_under, t2), "hash exactly one below target passes");

        check(!v2::hash_meets_target(nullptr, t2), "null hash -> false, no crash");

        // C ABI agrees.
        uint8_t ctgt[32];
        check(meepow_v2_difficulty_to_target(0, ctgt) == MEEPOW_V2_ERR_INVALID_DIFFICULTY,
              "C ABI difficulty 0 rejected");
        check(meepow_v2_difficulty_to_target(2, ctgt) == MEEPOW_V2_OK &&
              std::memcmp(ctgt, t2, 32) == 0, "C ABI target matches C++ target");
        check(meepow_v2_hash_meets_target(zero, ctgt) == 1, "C ABI comparison agrees");
    }

    std::printf("\n==================================================\n");
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    std::printf("%s\n", g_failures == 0 ? "KAT v2 API: PASS" : "KAT v2 API: FAIL");
    return g_failures == 0 ? 0 : 1;
}
