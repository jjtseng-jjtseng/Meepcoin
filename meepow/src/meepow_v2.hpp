// MeepHash-W v2 (algoVersion 2): identical to v1 EXCEPT the epoch dataset construction. The hash
// runs the exact v1 consensus pipeline (v1_scratch_init + v1_run_vm + v1_finalize) with the v2
// dataset served through a pluggable backend. Reference and adversaries call this SAME function;
// only the backend differs — no transcribed loops.
#ifndef MEEPOW_V2_HPP
#define MEEPOW_V2_HPP

#include <cstdint>
#include <vector>

#include "dataset_backend.hpp"
#include "dataset_v2.hpp"
#include "meepow_v1.hpp"
#include "params_v1.hpp"

namespace meepow {

// Build a v1 context whose program/scratch come from v1 but whose dataset is the full v2 array.
inline V1Ctx* v2_ctx_create(const std::vector<uint64_t>& full_v2_dataset, const uint8_t epoch_key[32],
                            const uint8_t seed_block_hash[32], uint64_t block_height,
                            const uint8_t* tmpl, size_t tmpl_len) {
    ParamSetV1 ps = v1_config(60, "v2", SCRATCH_S3, V1_ROUNDS_50X);  // v1 finalist params, v2 dataset
    ps.dataset_words = full_v2_dataset.size();
    return v1_ctx_create(ps, full_v2_dataset.data(), full_v2_dataset.size(), epoch_key,
                         seed_block_hash, block_height, tmpl, tmpl_len);
}

// Generic v2 hash: plug ANY dataset/scratchpad reader via raw hooks (NO auto-reset), so an attacker
// cache can PERSIST across nonces (cross-hash caching model). Runs the exact v1 consensus pipeline.
inline void v2_hash_raw(V1Ctx* c, uint32_t nonce, uint8_t out[32],
                        uint64_t (*dsread)(void*, uint64_t), void* dsctx) {
    uint8_t seed[96];
    v1_nonce_seed(c, nonce, seed);
    v1_scratch_init(c, nonce, seed);
    VmState vm{};
    vm.ds_read = dsread;
    vm.ds_ctx = dsctx;
    v1_run_vm(c, seed, vm, false, nullptr, nullptr);
    v1_finalize(c, vm, out);
}

// One v2 hash. dsb==null => direct read of the ctx's full v2 dataset (reference/production).
// dsb!=null => dataset served by the backend (TMTO adversary). spb!=null => scratchpad store-elision.
inline void v2_hash(V1Ctx* c, uint32_t nonce, uint8_t out[32], V2DsBackend* dsb = nullptr,
                    V2SpBackend* spb = nullptr) {
    uint8_t seed[96];
    v1_nonce_seed(c, nonce, seed);
    v1_scratch_init(c, nonce, seed);
    VmState vm{};
    if (dsb) {
        vm.ds_read = v2_ds_read;
        vm.ds_ctx = dsb;
        dsb->ops = 0; dsb->reads = 0; dsb->misses = 0; dsb->capped = false;
        // Per-hash memo: a smart attacker recomputes each missing word once per hash and caches it
        // for the rest of THAT hash (transient working memory, reused across hashes). Cleared here.
        v2_ds_reset_memo(dsb);
    }
    if (spb) {
        vm.sp_read = v2_sp_read;
        vm.sp_write = v2_sp_write;
        vm.sp_ctx = spb;
        spb->buf.clear();
        spb->sp = c->scratch.data();
        spb->mask = c->ps.scratch_words - 1;
    }
    v1_run_vm(c, seed, vm, false, nullptr, nullptr);
    v1_finalize(c, vm, out);
}

}  // namespace meepow

#endif  // MEEPOW_V2_HPP
