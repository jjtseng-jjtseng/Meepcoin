// EXACT MeepHash-W v2 (frozen) core — self-contained, compiles as CUDA device code AND as plain
// host C++ (so byte-exactness can be verified on the CPU before any GPU run).
//
// This is NOT a simplified performance model: it implements the full frozen v2 hash — BLAKE3
// (derive-key + XOF), the framed meep_xof, the v2 dataset word function, S3 scratchpad
// initialization, the complete VM opcode set, the mandatory dataset read-chain, mix-back, the final
// walk and finalization. It must reproduce meepow/vectors/vectors_v2.txt byte-for-byte.
//
// Build as host C++: #define MEEP_HOST_ONLY before including.
#ifndef MEEP_V2_CUDA_CORE_CUH
#define MEEP_V2_CUDA_CORE_CUH

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MEEP_HOST_ONLY) || !defined(__CUDACC__)
  #define MHD
  #define MDEV
#else
  #define MHD __host__ __device__
  #define MDEV __device__
#endif

// ------------------------------------------------------------------ frozen v2 constants -------
#define MEEP_ALGO_VERSION 0        /* meep_xof frames this byte (see blake3_xof.hpp) */
#define MEEP_PARAM_PIPE   60       /* param-set id used by v2_ctx_create (v1_config(60,...)) */
#define MEEP_PARAM_DS     0        /* param-set id used by the v2 dataset seed XOF */
#define V2_SEED_WORDS     8192u
#define V2_NPARENTS       4
#define DATASET_WORDS     0x400000u   /* 32 MiB */
#define SCRATCH_WORDS     0x100000u   /* 8 MiB  */
#define PROG_LEN          256u
#define ROUNDS            400u
#define STEPS_PER_ROUND   256u
#define S3_STRIDE         64u
#define MIXBACK_INTERVAL  8u

// ------------------------------------------------------------------------ BLAKE3 -------------
#define B3_CHUNK_START 1u
#define B3_CHUNK_END   2u
#define B3_ROOT        8u
#define B3_DERIVE_KEY_CONTEXT  32u
#define B3_DERIVE_KEY_MATERIAL 64u

MHD inline uint32_t b3_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

MHD inline void b3_g(uint32_t* s, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;  s[d] = b3_rotr(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];       s[b] = b3_rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;  s[d] = b3_rotr(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];       s[b] = b3_rotr(s[b] ^ s[c], 7);
}

MHD inline void b3_round(uint32_t* s, const uint32_t* m) {
    b3_g(s, 0, 4, 8, 12, m[0], m[1]);   b3_g(s, 1, 5, 9, 13, m[2], m[3]);
    b3_g(s, 2, 6, 10, 14, m[4], m[5]);  b3_g(s, 3, 7, 11, 15, m[6], m[7]);
    b3_g(s, 0, 5, 10, 15, m[8], m[9]);  b3_g(s, 1, 6, 11, 12, m[10], m[11]);
    b3_g(s, 2, 7, 8, 13, m[12], m[13]); b3_g(s, 3, 4, 9, 14, m[14], m[15]);
}

MHD inline void b3_permute(uint32_t* m) {
    const int P[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    uint32_t t[16];
    for (int i = 0; i < 16; ++i) t[i] = m[P[i]];
    for (int i = 0; i < 16; ++i) m[i] = t[i];
}

// Full 16-word compression output (state after feed-forward).
MHD inline void b3_compress(const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
                            uint32_t block_len, uint32_t flags, uint32_t out[16]) {
    const uint32_t IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
    uint32_t s[16] = {cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                      IV[0], IV[1], IV[2], IV[3],
                      (uint32_t)(counter & 0xFFFFFFFFu), (uint32_t)(counter >> 32), block_len, flags};
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = block[i];
    for (int r = 0; r < 7; ++r) { b3_round(s, m); if (r < 6) b3_permute(m); }
    for (int i = 0; i < 8; ++i) { s[i] ^= s[i + 8]; s[i + 8] ^= cv[i]; }
    for (int i = 0; i < 16; ++i) out[i] = s[i];
}

MHD inline void b3_words_from_le(const uint8_t* p, uint32_t* w, int n) {
    for (int i = 0; i < n; ++i)
        w[i] = (uint32_t)p[4 * i] | ((uint32_t)p[4 * i + 1] << 8) |
               ((uint32_t)p[4 * i + 2] << 16) | ((uint32_t)p[4 * i + 3] << 24);
}

// Single-chunk (len <= 1024) keyed hash + XOF. Covers every meep_xof call in frozen v2.
MHD inline void b3_xof_1chunk(const uint32_t key[8], const uint8_t* in, uint32_t len,
                              uint32_t base_flags, uint8_t* out, uint32_t outlen) {
    uint32_t cv[8];
    for (int i = 0; i < 8; ++i) cv[i] = key[i];
    uint32_t nblocks = (len + 63) / 64; if (nblocks == 0) nblocks = 1;
    uint32_t last_block[16];
    uint32_t last_len = 0, last_flags = 0;
    for (uint32_t b = 0; b < nblocks; ++b) {
        uint8_t buf[64];
        uint32_t blen = (b + 1 == nblocks) ? (len - b * 64) : 64;
        if (len == 0) blen = 0;
        for (int i = 0; i < 64; ++i) buf[i] = (i < (int)blen) ? in[b * 64 + i] : 0;
        uint32_t blk[16];
        b3_words_from_le(buf, blk, 16);
        uint32_t fl = base_flags | (b == 0 ? B3_CHUNK_START : 0u) |
                      (b + 1 == nblocks ? B3_CHUNK_END : 0u);
        if (b + 1 == nblocks) {
            for (int i = 0; i < 16; ++i) last_block[i] = blk[i];
            last_len = blen; last_flags = fl | B3_ROOT;
        } else {
            uint32_t st[16];
            b3_compress(cv, blk, 0, 64, fl, st);
            for (int i = 0; i < 8; ++i) cv[i] = st[i];
        }
    }
    uint32_t produced = 0, ctr = 0;
    while (produced < outlen) {
        uint32_t st[16];
        b3_compress(cv, last_block, ctr, last_len, last_flags, st);
        for (int w = 0; w < 16 && produced < outlen; ++w)
            for (int b = 0; b < 4 && produced < outlen; ++b)
                out[produced++] = (uint8_t)((st[w] >> (8 * b)) & 0xFF);
        ++ctr;
    }
}

// Derive-key context key: hash the context string with key=IV, flags=DERIVE_KEY_CONTEXT.
MHD inline void b3_context_key(const char* ctx, uint32_t len, uint32_t out_key[8]) {
    const uint32_t IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
    uint8_t out32[32];
    b3_xof_1chunk(IV, (const uint8_t*)ctx, len, B3_DERIVE_KEY_CONTEXT, out32, 32);
    b3_words_from_le(out32, out_key, 8);
}

// ---------------------------------------------------------------- framed meep_xof ------------
struct MField { const uint8_t* p; uint32_t n; };

// Builds ALGO_VERSION || PARAM_ID || (LE64(len)||bytes)* into `buf`, then keyed XOF.
MHD inline void meep_xof(const uint32_t ctx_key[8], uint8_t param_id, const MField* f, int nf,
                         uint8_t* buf, uint8_t* out, uint32_t outlen) {
    uint32_t n = 0;
    buf[n++] = (uint8_t)MEEP_ALGO_VERSION;
    buf[n++] = param_id;
    for (int i = 0; i < nf; ++i) {
        uint64_t L = f[i].n;
        for (int b = 0; b < 8; ++b) buf[n++] = (uint8_t)((L >> (8 * b)) & 0xFF);
        for (uint32_t k = 0; k < f[i].n; ++k) buf[n++] = f[i].p[k];
    }
    b3_xof_1chunk(ctx_key, buf, n, B3_DERIVE_KEY_MATERIAL, out, outlen);
}

// --------------------------------------------------------------- 64-bit helpers --------------
MHD inline uint64_t rotl64d(uint64_t x, unsigned n) { n &= 63; return n ? ((x << n) | (x >> (64 - n))) : x; }
MHD inline uint64_t rotr64d(uint64_t x, unsigned n) { n &= 63; return n ? ((x >> n) | (x << (64 - n))) : x; }
MHD inline uint64_t mulhi64d(uint64_t a, uint64_t b) {
#if defined(__CUDA_ARCH__)
    return __umul64hi(a, b);
#else
    uint64_t aL = a & 0xffffffffULL, aH = a >> 32, bL = b & 0xffffffffULL, bH = b >> 32;
    uint64_t ll = aL * bL, lh = aL * bH, hl = aH * bL, hh = aH * bH;
    uint64_t cross = (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    return hh + (lh >> 32) + (hl >> 32) + (cross >> 32);
#endif
}
MHD inline uint64_t ld64le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}
MHD inline void st64le(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
MHD inline void st32le(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
MHD inline uint64_t byteshufd(uint64_t x, uint64_t sel) {
    uint8_t in[8], out[8];
    st64le(in, x);
    for (int i = 0; i < 8; ++i) out[i] = in[(sel >> (3 * i)) & 7u];
    return ld64le(out);
}

// ---------------------------------------------------------------- v2 dataset ------------------
MHD inline uint64_t v2_splitmixd(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
MHD inline uint64_t v2_mixd(uint64_t a, uint64_t b, uint64_t w) {
    uint64_t x = a + b;
    x ^= rotl64d(x, 29);
    x = x * (b | 1ULL);
    x ^= w;
    x = rotl64d(x, 17);
    return x + a;
}

// ---------------------------------------------------------------- opcodes ---------------------
enum { OP_ADD64 = 0, OP_XOR64, OP_MUL64, OP_MULHI64, OP_ROTL64, OP_ROTR64, OP_ADD32, OP_XOR32,
       OP_MUL32, OP_LOAD64_SCRATCH, OP_LOAD64_DATASET, OP_STORE64, OP_BRANCH_IF_BIT, OP_CSELECT,
       OP_BYTE_SHUFFLE };
// Run-length weights (must sum to 256), identical to params.hpp.
MHD inline void build_opcode_table(uint8_t t[256]) {
    const uint8_t ops[15] = {OP_ADD64, OP_XOR64, OP_MUL64, OP_MULHI64, OP_ROTL64, OP_ROTR64,
                             OP_ADD32, OP_XOR32, OP_MUL32, OP_LOAD64_SCRATCH, OP_LOAD64_DATASET,
                             OP_STORE64, OP_BRANCH_IF_BIT, OP_CSELECT, OP_BYTE_SHUFFLE};
    const uint16_t cnt[15] = {41, 28, 20, 12, 8, 7, 16, 12, 10, 31, 15, 20, 18, 9, 9};
    int idx = 0;
    for (int i = 0; i < 15; ++i)
        for (uint16_t c = 0; c < cnt[i]; ++c) t[idx++] = ops[i];
}
struct MInstr { uint8_t op, d, s, a; uint32_t imm; };

// ---------------------------------------------------------------- per-nonce pipeline ----------
// Context keys, precomputed once (host) and passed to the device.
struct MeepKeys {
    uint32_t k_dataset[8], k_program[8], k_nonce[8], k_scratchseed[8], k_final[8];
};
MHD inline void meep_init_keys(MeepKeys* K) {
    b3_context_key("MEEP/DATASET/v2", 15, K->k_dataset);
    b3_context_key("MEEP/PROGRAM/v1", 15, K->k_program);
    b3_context_key("MEEP/NONCE/v1", 13, K->k_nonce);
    b3_context_key("MEEP/SCRATCHSEED/v1", 19, K->k_scratchseed);
    b3_context_key("MEEP/FINAL/v1", 13, K->k_final);
}

// Derive the per-job program (constant across nonces).
MHD inline void meep_derive_program(const MeepKeys* K, const uint8_t epochKey[32],
                                    const uint8_t seedHash[32], uint64_t height,
                                    MInstr* prog, uint8_t* scratchbuf /*>=2048*/,
                                    uint8_t* framebuf /*>=128*/) {
    uint8_t h_le[8];
    st64le(h_le, height);
    MField f[3] = {{h_le, 8}, {epochKey, 32}, {seedHash, 32}};
    meep_xof(K->k_program, MEEP_PARAM_PIPE, f, 3, framebuf, scratchbuf, PROG_LEN * 8);
    uint8_t tab[256];
    build_opcode_table(tab);
    for (uint32_t i = 0; i < PROG_LEN; ++i) {
        const uint8_t* p = scratchbuf + i * 8;
        prog[i].op = tab[p[0]];
        prog[i].d = p[1] & 7u;
        prog[i].s = p[2] & 7u;
        prog[i].a = p[3] & 63u;
        prog[i].imm = (uint32_t)p[4] | ((uint32_t)p[5] << 8) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
    }
}

// Scratchpad addressing: `sp_stride` selects the layout.
//   contiguous per-thread : base = pool + tid*SCRATCH_WORDS, sp_stride = 1
//   interleaved (coalesced): base = pool + tid,              sp_stride = nthreads
// One implementation serves both GPU mappings, so exactness is identical in each.
#define SP_AT(SP, i) (SP)[(uint64_t)(i) * sp_stride]

// Full per-nonce hash. `SP` must provide SCRATCH_WORDS words for this nonce.
MHD inline void meep_v2_hash_one(const MeepKeys* K, const uint64_t* dataset, const MInstr* prog,
                                 const uint8_t* tmpl, uint32_t tmpl_len, uint32_t nonce,
                                 uint64_t* SP, uint64_t sp_stride, uint8_t* framebuf /*>=512*/,
                                 uint8_t* out32) {
    // 1) per-nonce seed (96 bytes)
    uint8_t seed[96];
    {
        uint8_t n_le[4];
        st32le(n_le, nonce);
        MField f[2] = {{n_le, 4}, {tmpl, tmpl_len}};
        meep_xof(K->k_nonce, MEEP_PARAM_PIPE, f, 2, framebuf, seed, 96);
    }
    // 2) S3 scratchpad init: sparse BLAKE3 checkpoints + dependent expansion
    {
        const uint32_t nck = SCRATCH_WORDS / S3_STRIDE;
        uint8_t n_le[4];
        st32le(n_le, nonce);
        MField f[2] = {{n_le, 4}, {seed, 96}};
        // checkpoints are produced in chunks to bound temp memory: XOF is deterministic over the
        // whole stream, so we generate it in 64-byte blocks directly into the scratchpad slots.
        // (Equivalent to one XOF of nck*8 bytes.)
        uint8_t ckbuf[64];
        uint32_t produced = 0;
        // Build the framed input once, then stream XOF blocks.
        uint32_t n = 0;
        framebuf[n++] = (uint8_t)MEEP_ALGO_VERSION;
        framebuf[n++] = MEEP_PARAM_PIPE;
        for (int i = 0; i < 2; ++i) {
            uint64_t L = f[i].n;
            for (int b = 0; b < 8; ++b) framebuf[n++] = (uint8_t)((L >> (8 * b)) & 0xFF);
            for (uint32_t k = 0; k < f[i].n; ++k) framebuf[n++] = f[i].p[k];
        }
        // single-chunk XOF, streaming 64 bytes at a time
        uint32_t cv[8];
        for (int i = 0; i < 8; ++i) cv[i] = K->k_scratchseed[i];
        uint32_t nblocks = (n + 63) / 64; if (nblocks == 0) nblocks = 1;
        uint32_t last_block[16], last_len = 0, last_flags = 0;
        for (uint32_t b = 0; b < nblocks; ++b) {
            uint8_t bb[64];
            uint32_t blen = (b + 1 == nblocks) ? (n - b * 64) : 64;
            for (int i = 0; i < 64; ++i) bb[i] = (i < (int)blen) ? framebuf[b * 64 + i] : 0;
            uint32_t blk[16];
            b3_words_from_le(bb, blk, 16);
            uint32_t fl = B3_DERIVE_KEY_MATERIAL | (b == 0 ? B3_CHUNK_START : 0u) |
                          (b + 1 == nblocks ? B3_CHUNK_END : 0u);
            if (b + 1 == nblocks) {
                for (int i = 0; i < 16; ++i) last_block[i] = blk[i];
                last_len = blen; last_flags = fl | B3_ROOT;
            } else {
                uint32_t st[16];
                b3_compress(cv, blk, 0, 64, fl, st);
                for (int i = 0; i < 8; ++i) cv[i] = st[i];
            }
        }
        uint32_t ctr = 0, ck = 0;
        while (ck < nck) {
            uint32_t st[16];
            b3_compress(cv, last_block, ctr, last_len, last_flags, st);
            for (int w = 0; w < 16; ++w) st32le(ckbuf + w * 4, st[w]);
            for (int q = 0; q < 8 && ck < nck; ++q, ++ck)
                SP_AT(SP, (uint64_t)ck * S3_STRIDE) = ld64le(ckbuf + q * 8);
            ++ctr;
            produced += 64;
        }
        (void)produced;
        for (uint32_t w = 0; w < SCRATCH_WORDS; ++w) {
            if (w % S3_STRIDE == 0) continue;
            uint64_t prev = SP_AT(SP, w - 1);
            uint64_t anchor = SP_AT(SP, (w / S3_STRIDE) * S3_STRIDE);
            SP_AT(SP, w) = v2_mixd(prev, anchor, (uint64_t)w);
        }
    }
    // 3) VM: ROUNDS x STEPS with the mandatory dataset read-chain and mix-back
    uint64_t r[8], acc[4], last[8], spos = 0;
    for (int i = 0; i < 8; ++i) r[i] = ld64le(seed + i * 8);
    for (int i = 0; i < 4; ++i) acc[i] = ld64le(seed + 64 + i * 8);
    for (int i = 0; i < 8; ++i) last[i] = 0;
    const uint64_t smask = SCRATCH_WORDS - 1, dmask = DATASET_WORDS - 1;
    uint64_t t = 0;
    for (uint32_t round = 0; round < ROUNDS; ++round) {
        uint32_t pc = 0;
        for (uint32_t step = 0; step < STEPS_PER_ROUND; ++step) {
            MInstr I = prog[pc];
            uint64_t d = I.d, s = I.s, a = I.a, imm = I.imm;
            uint64_t addr = 0, val = 0;
            bool mem = false, taken = false;
            switch (I.op) {
                case OP_ADD64: r[d] = r[d] + r[s] + imm; break;
                case OP_XOR64: r[d] = r[d] ^ r[s] ^ imm; break;
                case OP_MUL64: r[d] = r[d] * (r[s] | 1ULL); break;
                case OP_MULHI64: r[d] = mulhi64d(r[d], r[s]); break;
                case OP_ROTL64: r[d] = rotl64d(r[d], (unsigned)((r[s] + imm) & 63)); break;
                case OP_ROTR64: r[d] = rotr64d(r[d], (unsigned)((r[s] + imm) & 63)); break;
                case OP_ADD32: r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] + (uint32_t)r[s] + (uint32_t)imm); break;
                case OP_XOR32: r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] ^ (uint32_t)r[s] ^ (uint32_t)imm); break;
                case OP_MUL32: r[d] = (uint64_t)(uint32_t)((uint32_t)r[d] * ((uint32_t)r[s] | 1u)); break;
                case OP_LOAD64_SCRATCH: {
                    uint64_t off = (r[s] + imm) & smask;
                    if (((acc[1] ^ r[s]) & 3u) == 0) off = last[(acc[1] >> 2) & 7u] & smask;
                    val = SP_AT(SP, off); r[d] = val; addr = off; mem = true;
                } break;
                case OP_LOAD64_DATASET: {
                    uint64_t off = (r[s] ^ imm ^ acc[0]) & dmask;
                    val = dataset[off]; r[d] = val; addr = off; mem = true;
                } break;
                case OP_STORE64: {
                    uint64_t off = (r[d] + imm) & smask;
                    val = r[s];
                    SP_AT(SP, off) = val;
                    last[spos & 7u] = off; spos++;
                    addr = off; mem = true;
                } break;
                case OP_BRANCH_IF_BIT: taken = ((r[s] >> a) & 1u) != 0; break;
                case OP_CSELECT: r[d] = (r[s] & 1u) ? (r[d] + imm) : (r[d] ^ r[s]); break;
                case OP_BYTE_SHUFFLE: r[d] = byteshufd(r[d], r[s]); break;
                default: break;
            }
            acc[0] = rotl64d(acc[0] + (uint64_t)I.op + imm, 1);
            acc[1] = acc[1] ^ r[d] ^ (((uint64_t)d << 3) | (uint64_t)s);
            acc[2] = acc[2] * (r[s] | 1ULL) + acc[0];
            if (mem) acc[3] = rotl64d(acc[3] ^ addr, 17) + val; else acc[3] = acc[3] + acc[2];
            // mandatory data-dependent dataset read-chain
            uint64_t da = (acc[2] ^ r[step & 7]) & dmask;
            uint64_t dv = dataset[da];
            acc[3] ^= dv;
            acc[2] = rotl64d(acc[2] + dv, 23);
            ++t;
            if ((t % MIXBACK_INTERVAL) == 0) {
                unsigned j = (unsigned)((t / MIXBACK_INTERVAL) & 7u);
                r[j] ^= SP_AT(SP, last[j] & smask);
            }
            if (taken) pc = (uint32_t)((pc + 1 + (I.imm & (PROG_LEN - 1))) % PROG_LEN);
            else pc = (pc + 1) % PROG_LEN;
        }
    }
    // 4) final walk + finalization
    uint64_t w32[32];
    for (int k = 0; k < 8; ++k) w32[k] = SP_AT(SP, last[k] & smask);
    for (int k = 0; k < 24; ++k) {
        uint64_t idx = (acc[k & 3] ^ r[k & 7] ^ (uint64_t)k * 0x9E3779B97F4A7C15ULL) & smask;
        w32[8 + k] = SP_AT(SP, idx);
    }
    acc[0] ^= w32[0]; acc[1] += w32[8]; acc[2] ^= w32[16]; acc[3] += w32[24];
    uint8_t rb[64], ab[32], sample[256];
    for (int i = 0; i < 8; ++i) st64le(rb + i * 8, r[i]);
    for (int i = 0; i < 4; ++i) st64le(ab + i * 8, acc[i]);
    for (int k = 0; k < 32; ++k) st64le(sample + k * 8, w32[k]);
    MField f3[3] = {{rb, 64}, {ab, 32}, {sample, 256}};
    meep_xof(K->k_final, MEEP_PARAM_PIPE, f3, 3, framebuf, out32, 32);
}

// ------------------------------------------------------------ host-side dataset build ---------
// HOST-ONLY BY ANNOTATION, NOT BY PREPROCESSOR. This function has no MHD/__device__ marker, so nvcc
// generates code for it only on the host — exactly what we want (it uses malloc/free and runs once
// per epoch before upload).
//
// Do NOT wrap it in a preprocessor guard. Two guards were tried and both were wrong:
//   #if !defined(__CUDACC__)   -> nvcc defines __CUDACC__ in BOTH its host and device passes, so
//                                 the function vanished from every nvcc build.
//   #if !defined(__CUDA_ARCH__)-> __CUDA_ARCH__ is only defined in the device pass, but nvcc still
//                                 PARSES the whole translation unit (including main()) during that
//                                 pass, so main()'s call site saw an undefined identifier.
// Leaving it unguarded is both simpler and correct: visible to every pass, compiled only for host.
inline void meep_v2_build_dataset(const MeepKeys* K, const uint8_t epochKey[32], uint64_t* D) {
    // seed region via framed XOF (field order: LE64(0), epochKey), param id 0
    static uint8_t framebuf[128];
    uint8_t idx0[8];
    st64le(idx0, 0);
    MField f[2] = {{idx0, 8}, {epochKey, 32}};
    uint8_t* tmp = (uint8_t*)malloc((size_t)V2_SEED_WORDS * 8);
    meep_xof(K->k_dataset, MEEP_PARAM_DS, f, 2, framebuf, tmp, V2_SEED_WORDS * 8);
    for (uint32_t w = 0; w < V2_SEED_WORDS; ++w) D[w] = ld64le(tmp + w * 8);
    free(tmp);
    uint64_t seedconst = D[0];
    for (uint64_t w = V2_SEED_WORDS; w < DATASET_WORDS; ++w) {
        uint64_t h = v2_splitmixd(w ^ seedconst);
        uint64_t p1 = h % w;              uint64_t d1 = D[p1];
        uint64_t acc = v2_mixd(d1, h, w);
        uint64_t p2 = (d1 ^ (h >> 13)) % w; uint64_t d2 = D[p2];
        acc = v2_mixd(acc, d2, w ^ rotl64d(d1, 32));
        uint64_t p3 = (d1 ^ d2 ^ (h >> 29)) % w; uint64_t d3 = D[p3];
        acc = v2_mixd(acc, d3, w ^ rotl64d(d2, 17));
        uint64_t p4 = (d2 ^ d3 ^ (h >> 7)) % w; uint64_t d4 = D[p4];
        D[w] = v2_mixd(acc, d4, w ^ rotl64d(d3, 41));
    }
}

#endif  // MEEP_V2_CUDA_CORE_CUH
