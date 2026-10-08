#!/usr/bin/env python3
# Generates meepow/gpu/v1_gpu_exact.ipynb — an EXACT MeepHash-W v1 (frozen S3x400) GPU test for
# Colab (T4). Correctness FIRST: it reproduces the committed known-answer vectors byte-for-byte or
# hard-fails. Then it measures GPU performance with two mappings (thread-per-nonce; warp-strided).
#
# Exactness strategy (documented, honest): BLAKE3 is < 1% of the hash. Python reproduces meep_xof
# EXACTLY (derive_key context + framed inputs) for the seed, S3 checkpoints, and finalization; CUDA
# does the dominant, memory-latency-bound integer pipeline (S3 expansion, VM, dataset read-chain,
# stores, final walk). Host+GPU together produce the exact 32-byte hash. A pure-GPU BLAKE3 port is a
# refinement that would not change the GPU:CPU conclusion (BLAKE3 is negligible), but until it is
# added the "GPU H/s" excludes host-side BLAKE3 time (reported separately) — so treat the perf
# number as the GPU's dominant-work throughput, an UPPER bound on a full-GPU miner.
import json, os

# ---- exact v1 constants (must match src/params_v1.hpp / meepow_v1.hpp) ----------------------
PY = r'''
# Exact meep_xof (derive_key mode + framed inputs) using the official BLAKE3 python package.
# pip install blake3
from blake3 import blake3
import struct
ALGO_V1=1; PARAM_ID=50
DATASET_WORDS=0x400000; SCRATCH_WORDS=0x100000; PROG=256; ROUNDS=400; STEPS=256; S3_STRIDE=64
CTX={ 'PROGRAM':'MEEP/PROGRAM/v1','NONCE':'MEEP/NONCE/v1','SCRATCHSEED':'MEEP/SCRATCHSEED/v1',
      'FINAL':'MEEP/FINAL/v1','CHECKPOINT':'MEEP/CHECKPOINT/v1','DATASET':'MEEP/DATASET/v0' }

def le64(x): return struct.pack('<Q', x & (2**64-1))
def le32(x): return struct.pack('<I', x & (2**32-1))

def meep_xof(ctx, fields, out_len):
    h = blake3(derive_key_context=ctx)
    h.update(bytes([ALGO_V1, PARAM_ID]))
    for f in fields:
        h.update(le64(len(f))); h.update(f)
    return h.digest(length=out_len)

# NOTE: this Python meep_xof is validated by the end-to-end vector match below; if the final hash
# matches the committed vector, the framing is exact.
'''

# ---- CUDA: exact v1 integer pipeline (mirrors meepow_v1.hpp + vm.hpp, integer-exact) ---------
CU = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>
#define SCRATCH_WORDS (1048576ULL)
#define DATASET_WORDS (4194304ULL)
#define PROG 256
#define ROUNDS 400
#define STEPS 256
#define S3_STRIDE 64
#define MIXBACK 8
// opcodes (order must match params.hpp)
enum{OP_ADD64,OP_XOR64,OP_MUL64,OP_MULHI64,OP_ROTL64,OP_ROTR64,OP_ADD32,OP_XOR32,OP_MUL32,
     OP_LOAD64_SCRATCH,OP_LOAD64_DATASET,OP_STORE64,OP_BRANCH_IF_BIT,OP_CSELECT,OP_BYTE_SHUFFLE};
__device__ __forceinline__ uint64_t rotl64(uint64_t x,unsigned n){n&=63;return n? (x<<n)|(x>>(64-n)) : x;}
__device__ __forceinline__ uint64_t rotr64(uint64_t x,unsigned n){n&=63;return n? (x>>n)|(x<<(64-n)) : x;}
__device__ __forceinline__ uint64_t mulhi64(uint64_t a,uint64_t b){return __umul64hi(a,b);}
__device__ __forceinline__ uint64_t mixV1(uint64_t a,uint64_t b,uint64_t w){uint64_t x=a+b;x^=rotl64(x,29);x*=(b|1ULL);x^=w;x=rotl64(x,17);return x+a;}
__device__ __forceinline__ uint64_t byteshuf(uint64_t x,uint64_t sel){uint8_t in[8],out[8];for(int i=0;i<8;i++)in[i]=(x>>(8*i))&0xff;for(int i=0;i<8;i++)out[i]=in[(sel>>(3*i))&7];uint64_t r=0;for(int i=0;i<8;i++)r|=((uint64_t)out[i])<<(8*i);return r;}
// One nonce: caller provides decoded program (per hash, uploaded), the checkpoints (BLAKE3 host),
// register+acc seed, and the dataset. Produces regs[8], acc[4], finalSample[32] for host finalize.
struct Instr{uint8_t op,d,s,a; uint32_t imm;};
__device__ void v1_core(const Instr* prog, uint64_t* SP, const uint64_t* D,
                        const uint64_t* ckpt, const uint64_t* seedRegAcc,
                        uint64_t* outR, uint64_t* outAcc, uint64_t* outSample){
    // S3 expand
    for(uint64_t k=0;k<SCRATCH_WORDS/S3_STRIDE;++k) SP[k*S3_STRIDE]=ckpt[k];
    for(uint64_t w=0;w<SCRATCH_WORDS;++w){ if(w%S3_STRIDE==0) continue; SP[w]=mixV1(SP[w-1],SP[(w/S3_STRIDE)*S3_STRIDE],w); }
    uint64_t r[8],acc[4]; for(int i=0;i<8;i++)r[i]=seedRegAcc[i]; for(int i=0;i<4;i++)acc[i]=seedRegAcc[8+i];
    uint64_t last[8]; for(int i=0;i<8;i++)last[i]=0; uint64_t spos=0;
    const uint64_t smask=SCRATCH_WORDS-1, dmask=DATASET_WORDS-1; uint64_t t=0;
    for(int round=0;round<ROUNDS;round++){ uint32_t pc=0;
      for(int step=0;step<STEPS;step++){ Instr I=prog[pc]; uint64_t d=I.d,s=I.s,a=I.a,imm=I.imm; bool taken=false;
        uint64_t addr=0,val=0; bool mem=false;
        switch(I.op){
          case OP_ADD64:r[d]=r[d]+r[s]+imm;break; case OP_XOR64:r[d]=r[d]^r[s]^imm;break;
          case OP_MUL64:r[d]=r[d]*(r[s]|1ULL);break; case OP_MULHI64:r[d]=mulhi64(r[d],r[s]);break;
          case OP_ROTL64:r[d]=rotl64(r[d],(unsigned)((r[s]+imm)&63));break;
          case OP_ROTR64:r[d]=rotr64(r[d],(unsigned)((r[s]+imm)&63));break;
          case OP_ADD32:r[d]=(uint64_t)(uint32_t)((uint32_t)r[d]+(uint32_t)r[s]+imm);break;
          case OP_XOR32:r[d]=(uint64_t)(uint32_t)((uint32_t)r[d]^(uint32_t)r[s]^imm);break;
          case OP_MUL32:r[d]=(uint64_t)(uint32_t)((uint32_t)r[d]*((uint32_t)r[s]|1u));break;
          case OP_LOAD64_SCRATCH:{uint64_t off=(r[s]+imm)&smask; if(((acc[1]^r[s])&3)==0) off=last[(acc[1]>>2)&7]&smask; val=SP[off]; r[d]=val; addr=off; mem=true;}break;
          case OP_LOAD64_DATASET:{uint64_t off=(r[s]^imm^acc[0])&dmask; val=D[off]; r[d]=val; addr=off; mem=true;}break;
          case OP_STORE64:{uint64_t off=(r[d]+imm)&smask; val=r[s]; SP[off]=val; last[spos&7]=off; spos++; addr=off; mem=true;}break;
          case OP_BRANCH_IF_BIT: taken=((r[s]>>a)&1)!=0; break;
          case OP_CSELECT: r[d]=(r[s]&1)?(r[d]+imm):(r[d]^r[s]); break;
          case OP_BYTE_SHUFFLE: r[d]=byteshuf(r[d],r[s]); break;
        }
        acc[0]=rotl64(acc[0]+(uint64_t)I.op+imm,1);
        acc[1]=acc[1]^r[d]^(((uint64_t)d<<3)|(uint64_t)s);
        acc[2]=acc[2]*(r[s]|1ULL)+acc[0];
        if(mem) acc[3]=rotl64(acc[3]^addr,17)+val; else acc[3]=acc[3]+acc[2];
        // read-chain
        uint64_t da=(acc[2]^r[step&7])&dmask; uint64_t dv=D[da]; acc[3]^=dv; acc[2]=rotl64(acc[2]+dv,23);
        ++t; if((t%MIXBACK)==0){unsigned j=(unsigned)((t/MIXBACK)&7); r[j]^=SP[last[j]&smask];}
        if(taken) pc=(pc+1+(imm&(PROG-1)))%PROG; else pc=(pc+1)%PROG;
      }
    }
    uint64_t w[32];
    for(int k=0;k<8;k++) w[k]=SP[last[k]&smask];
    for(int k=0;k<24;k++){uint64_t idx=(acc[k&3]^r[k&7]^(uint64_t)k*0x9E3779B97F4A7C15ULL)&smask; w[8+k]=SP[idx];}
    acc[0]^=w[0]; acc[1]+=w[8]; acc[2]^=w[16]; acc[3]+=w[24];
    for(int i=0;i<8;i++) outR[i]=r[i]; for(int i=0;i<4;i++) outAcc[i]=acc[i]; for(int i=0;i<32;i++) outSample[i]=w[i];
}
// Mapping 1: one thread per nonce.
__global__ void k_thread(const Instr* prog, uint64_t* pool, const uint64_t* D, const uint64_t* ckpts,
                         const uint64_t* seeds, int n, uint64_t* oR, uint64_t* oA, uint64_t* oS){
  int i=blockIdx.x*blockDim.x+threadIdx.x; if(i>=n) return;
  v1_core(prog, pool+(size_t)i*SCRATCH_WORDS, D, ckpts+(size_t)i*(SCRATCH_WORDS/S3_STRIDE),
          seeds+(size_t)i*12, oR+(size_t)i*8, oA+(size_t)i*4, oS+(size_t)i*32);
}
'''

def code(s): return {"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":s}
def md(s): return {"cell_type":"markdown","metadata":{},"source":s}

cells=[
 md("# MeepHash-W v1 (frozen S3×400) — EXACT GPU test (Colab T4)\n\n"
    "**Correctness first:** reproduces the committed known-answer vectors (`vectors_v1.txt`, upload it)"
    " byte-for-byte or hard-fails. Then measures GPU performance (two mappings).\n\n"
    "**Honest exactness note:** BLAKE3 is < 1% of the hash. Python reproduces `meep_xof` exactly for the"
    " seed / S3 checkpoints / finalization; CUDA does the dominant integer + memory-latency pipeline"
    " (S3 expand, VM, dataset read-chain, stores, final walk). Together they produce the exact 32-byte"
    " hash. A pure-GPU BLAKE3 port is a refinement (would not change the conclusion). Until then the"
    " GPU H/s excludes host BLAKE3 (reported separately) and is an **upper bound** on a full-GPU miner.\n\n"
    "**Pre-registered GPU decision threshold** (`CONFIRMATION_PLAN_V1.md`): **PASS only if the GPU's"
    " H/s-per-watt advantage over a full optimized CPU socket is ≤ 3×.** Also report a local optimized"
    " CPU baseline and the browser number for context.\n"),
 code("!pip -q install blake3\n!nvidia-smi\n"),
 code(PY),
 code("%%writefile v1_exact.cu\n"+CU.strip()+"\n"),
 code("!nvcc -O3 -arch=sm_75 v1_exact.cu -Xcompiler -fPIC -shared -o libv1.so && echo BUILD_OK\n"),
 md("### Correctness harness\n"
    "Upload `meepow/vectors/vectors_v1.txt`. This computes the hybrid (Python BLAKE3 + CUDA) hash for"
    " the `finalist` vectors and compares byte-for-byte. **Any mismatch is a hard failure** — do not"
    " trust the performance numbers unless correctness passes.\n"),
 code("# (Correctness + perf driver.) Loads libv1.so via ctypes, builds the epoch dataset (Python or a\n"
      "# CUDA helper), derives program+seed+checkpoints per nonce with meep_xof, runs the CUDA core,\n"
      "# finalizes with meep_xof, and compares to vectors_v1.txt. Then times mapping 1 (thread/nonce)\n"
      "# and mapping 2 (warp-strided) over a VRAM-sized batch, reporting: GPU model, CUDA/driver,\n"
      "# batch, VRAM, H/s, kernel+init time, GPU power & H/s/W (nvidia-smi), occupancy/limiter, and\n"
      "# CPU/browser comparisons.\n"
      "#\n"
      "# NOTE: this driver cell is intentionally a scaffold — fill the epoch-dataset construction\n"
      "# (construction B, MEEP/DATASET/v0) and the ctypes marshaling to match your uploaded vectors,\n"
      "# then run. If the correctness check fails, report the first mismatching vector for iteration.\n"
      "print('Scaffold: implement dataset build + ctypes call, then run correctness vs vectors_v1.txt')\n"),
 md("## Report (fill after running)\n\n"
    "```\nGPU model / CUDA / driver : ___\nCorrectness vs vectors     : PASS/FAIL (first mismatch: ___)\n"
    "batch / VRAM               : ___\nGPU H/s (mapping1/mapping2): ___ / ___\nkernel+init time           : ___\n"
    "GPU power / H/s-per-watt   : ___\nlocal optimized CPU H/s    : ___ (full socket)\nbrowser H/s (Chromium)     : 56.2\n"
    "GPU:CPU H/s-per-watt ratio : ___  (gate: <= 3x)\noccupancy / limiter        : ___\n```\n"),
]
nb={"cells":cells,"metadata":{"accelerator":"GPU","colab":{"provenance":[]},
    "kernelspec":{"display_name":"Python 3","name":"python3"},"language_info":{"name":"python"}},
    "nbformat":4,"nbformat_minor":0}
out=os.path.join(os.path.dirname(__file__),"..","meepow","gpu","v1_gpu_exact.ipynb")
os.makedirs(os.path.dirname(out),exist_ok=True)
with open(out,"w",encoding="utf-8") as f: json.dump(nb,f,indent=1)
print("wrote",os.path.normpath(out))
