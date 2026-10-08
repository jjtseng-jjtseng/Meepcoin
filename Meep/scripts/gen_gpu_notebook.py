#!/usr/bin/env python3
# Generates meepow/gpu/v1_gpu_prototype.ipynb — a self-contained Colab (T4) notebook that measures
# the GPU:CPU efficiency of MeepHash-W v1's performance-relevant structure (BENCHMARK_PLAN_V1 #9).
#
# It is a PERFORMANCE prototype, not a byte-exact hash: it faithfully reproduces the dominant costs
# (8 MiB/nonce dependent scratchpad fill + a 102,400-step data-dependent serial dataset read-chain
# with data-dependent scratch access), which determine GPU vs CPU efficiency. BLAKE3 (<1% of the
# real hash) is replaced by a cheap splitmix seed. Both GPU (CUDA) and CPU (OpenMP) run the SAME
# structure on the SAME machine so the ratio is apples-to-apples.
import json, os

CU = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <cuda_runtime.h>

#define DATASET_WORDS (4194304ULL)   // 32 MiB
#define SCRATCH_WORDS (1048576ULL)   // 8 MiB per nonce
#define ROUNDS 400
#define STEPS  256
#define S3_STRIDE 64

__host__ __device__ static inline uint64_t rotl64(uint64_t x, unsigned r){ return (x<<r)|(x>>((64-r)&63)); }
__host__ __device__ static inline uint64_t splitmix(uint64_t z){ z+=0x9E3779B97F4A7C15ULL; z=(z^(z>>30))*0xBF58476D1CE4E5B9ULL; z=(z^(z>>27))*0x94D049BB133111EBULL; return z^(z>>31); }
__host__ __device__ static inline uint64_t mixV1(uint64_t a,uint64_t b,uint64_t w){ uint64_t x=a+b; x^=rotl64(x,29); x*= (b|1ULL); x^=w; x=rotl64(x,17); return x+a; }

// One nonce: S3-style dependent scratch fill + VM loop with data-dependent scratch + dataset read-chain.
__host__ __device__ static inline uint64_t v1_nonce(const uint64_t* dataset, uint64_t* SP, uint64_t nonce){
    uint64_t s = splitmix(nonce+1);
    // sparse checkpoints (cheap, ~1/64) then dependent expansion
    for (uint64_t k=0;k<SCRATCH_WORDS/S3_STRIDE;++k) SP[k*S3_STRIDE]=splitmix(s+ k*0x100000001B3ULL);
    for (uint64_t w=0;w<SCRATCH_WORDS;++w){ if(w%S3_STRIDE==0) continue; SP[w]=mixV1(SP[w-1], SP[(w/S3_STRIDE)*S3_STRIDE], w); }
    uint64_t r[8], acc[4];
    for(int i=0;i<8;++i) r[i]=splitmix(s+i*0x9E37ULL);
    for(int i=0;i<4;++i) acc[i]=splitmix(s+100+i);
    const uint64_t smask=SCRATCH_WORDS-1, dmask=DATASET_WORDS-1;
    for(int i=0;i<ROUNDS*STEPS;++i){
        // a few integer ops (VM-ish)
        r[i&7] = r[i&7]*(r[(i+1)&7]|1ULL) + acc[0];
        acc[1] = rotl64(acc[1]^r[i&7], 23);
        // data-dependent scratch access (load + store)
        uint64_t off=(acc[1]^r[i&7])&smask; uint64_t v=SP[off]; acc[0]^=v; SP[off]=rotl64(v+acc[0],17);
        // mandatory serial dataset read-chain
        uint64_t da=(acc[2]^r[i&7])&dmask; uint64_t dv=dataset[da]; acc[3]^=dv; acc[2]=rotl64(acc[2]+dv,23);
    }
    return acc[0]^acc[1]^acc[2]^acc[3]^r[0]^r[7];
}

__global__ void v1_kernel(const uint64_t* dataset, uint64_t* pool, uint64_t base_nonce, int n, uint64_t* out){
    int tid=blockIdx.x*blockDim.x+threadIdx.x; if(tid>=n) return;
    uint64_t* SP = pool + (size_t)tid*SCRATCH_WORDS;
    out[tid] = v1_nonce(dataset, SP, base_nonce+tid);
}

int main(int argc, char** argv){
    int waves = argc>1?atoi(argv[1]):3;
    // dataset
    std::vector<uint64_t> hds(DATASET_WORDS);
    for(uint64_t i=0;i<DATASET_WORDS;++i) hds[i]=splitmix(i+12345);
    uint64_t* dds; cudaMalloc(&dds, DATASET_WORDS*8); cudaMemcpy(dds,hds.data(),DATASET_WORDS*8,cudaMemcpyHostToDevice);
    // choose batch by free memory (each nonce needs an 8 MiB scratchpad in global memory)
    size_t freeb=0, totb=0; cudaMemGetInfo(&freeb,&totb);
    size_t per=SCRATCH_WORDS*8; size_t budget=(size_t)(freeb*0.80);
    int batch=(int)(budget/per); if(batch>20000) batch=20000; if(batch<64) batch=64;
    uint64_t* pool; if(cudaMalloc(&pool,(size_t)batch*per)!=cudaSuccess){ printf("alloc fail batch=%d\n",batch); return 1; }
    uint64_t* dout; cudaMalloc(&dout, (size_t)batch*8);
    int tpb=64, blocks=(batch+tpb-1)/tpb;
    // warm
    v1_kernel<<<blocks,tpb>>>(dds,pool,0,batch,dout); cudaDeviceSynchronize();
    auto t0=std::chrono::steady_clock::now();
    for(int w=0;w<waves;++w){ v1_kernel<<<blocks,tpb>>>(dds,pool,(uint64_t)w*batch,batch,dout); }
    cudaDeviceSynchronize();
    double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    double hps=(double)batch*waves/sec;
    printf("GPU batch=%d waves=%d time=%.3fs  GPU_HPS=%.1f  (scratch pool %.2f GiB)\n",
           batch,waves,sec,hps,(double)batch*per/(1024.0*1024*1024));
    cudaFree(pool); cudaFree(dout); cudaFree(dds);
    return 0;
}
'''

CPUC = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <chrono>
#ifdef _OPENMP
#include <omp.h>
#endif
#define DATASET_WORDS (4194304ULL)
#define SCRATCH_WORDS (1048576ULL)
#define ROUNDS 400
#define STEPS  256
#define S3_STRIDE 64
static inline uint64_t rotl64(uint64_t x,unsigned r){return (x<<r)|(x>>((64-r)&63));}
static inline uint64_t splitmix(uint64_t z){z+=0x9E3779B97F4A7C15ULL;z=(z^(z>>30))*0xBF58476D1CE4E5B9ULL;z=(z^(z>>27))*0x94D049BB133111EBULL;return z^(z>>31);}
static inline uint64_t mixV1(uint64_t a,uint64_t b,uint64_t w){uint64_t x=a+b;x^=rotl64(x,29);x*=(b|1ULL);x^=w;x=rotl64(x,17);return x+a;}
static uint64_t v1_nonce(const uint64_t* dataset, uint64_t* SP, uint64_t nonce){
    uint64_t s=splitmix(nonce+1);
    for(uint64_t k=0;k<SCRATCH_WORDS/S3_STRIDE;++k) SP[k*S3_STRIDE]=splitmix(s+k*0x100000001B3ULL);
    for(uint64_t w=0;w<SCRATCH_WORDS;++w){ if(w%S3_STRIDE==0) continue; SP[w]=mixV1(SP[w-1],SP[(w/S3_STRIDE)*S3_STRIDE],w);}
    uint64_t r[8],acc[4]; for(int i=0;i<8;++i)r[i]=splitmix(s+i*0x9E37ULL); for(int i=0;i<4;++i)acc[i]=splitmix(s+100+i);
    const uint64_t smask=SCRATCH_WORDS-1,dmask=DATASET_WORDS-1;
    for(int i=0;i<ROUNDS*STEPS;++i){
        r[i&7]=r[i&7]*(r[(i+1)&7]|1ULL)+acc[0]; acc[1]=rotl64(acc[1]^r[i&7],23);
        uint64_t off=(acc[1]^r[i&7])&smask; uint64_t v=SP[off]; acc[0]^=v; SP[off]=rotl64(v+acc[0],17);
        uint64_t da=(acc[2]^r[i&7])&dmask; uint64_t dv=dataset[da]; acc[3]^=dv; acc[2]=rotl64(acc[2]+dv,23);
    }
    return acc[0]^acc[1]^acc[2]^acc[3]^r[0]^r[7];
}
int main(int argc,char**argv){
    int total=argc>1?atoi(argv[1]):0;
    std::vector<uint64_t> ds(DATASET_WORDS); for(uint64_t i=0;i<DATASET_WORDS;++i) ds[i]=splitmix(i+12345);
    int T=1;
#ifdef _OPENMP
    T=omp_get_max_threads();
#endif
    if(total==0) total=T*4;
    std::vector<uint64_t> res(total);
    auto t0=std::chrono::steady_clock::now();
#ifdef _OPENMP
    #pragma omp parallel
#endif
    {
        std::vector<uint64_t> SP(SCRATCH_WORDS);
#ifdef _OPENMP
        #pragma omp for schedule(dynamic)
#endif
        for(int n=0;n<total;++n) res[n]=v1_nonce(ds.data(),SP.data(),(uint64_t)n);
    }
    double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    uint64_t sink=0; for(auto x:res) sink^=x;
    printf("CPU threads=%d nonces=%d time=%.3fs  CPU_HPS=%.1f  (sink=%llu)\n",T,total,sec,total/sec,(unsigned long long)sink);
    return 0;
}
'''

def code(src): return {"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":src}
def md(src): return {"cell_type":"markdown","metadata":{},"source":src}

cells = [
 md("# MeepHash-W v1 — GPU adversarial prototype (T4)\n\n"
    "Measures the **GPU:CPU efficiency ratio** of MeepHash-W v1's performance-relevant structure "
    "(8 MiB/nonce dependent scratchpad fill + a 102,400-step data-dependent serial dataset "
    "read-chain with data-dependent scratch access). **Performance prototype, not a byte-exact "
    "hash** — BLAKE3 (<1% of the real hash) is replaced by a cheap seed; the dominant memory-"
    "latency structure is faithful. Same code structure runs on GPU (CUDA) and CPU (OpenMP), same "
    "machine, so the ratio is apples-to-apples.\n\n"
    "**Interpretation:** v1 is designed to be memory-latency-bound. A **low GPU:CPU ratio** "
    "(≈ or below the number of CPU cores, i.e. GPU not dramatically ahead per unit) supports the "
    "goal; a **high ratio** means GPUs still win and the design needs rework. No resistance is "
    "claimed without this number.\n"),
 code("!nvidia-smi\n"),
 code("%%writefile v1_gpu.cu\n"+CU.strip()+"\n"),
 code("%%writefile v1_cpu.cpp\n"+CPUC.strip()+"\n"),
 code("!nvcc -O3 -arch=sm_75 v1_gpu.cu -o v1_gpu && echo GPU_BUILD_OK\n"
      "!g++ -O3 -fopenmp v1_cpu.cpp -o v1_cpu && echo CPU_BUILD_OK\n"),
 code("import subprocess, re\n"
      "gpu = subprocess.run(['./v1_gpu','5'], capture_output=True, text=True).stdout\n"
      "cpu = subprocess.run(['./v1_cpu'], capture_output=True, text=True).stdout\n"
      "print(gpu); print(cpu)\n"
      "g=float(re.search(r'GPU_HPS=([0-9.]+)',gpu).group(1))\n"
      "c=float(re.search(r'CPU_HPS=([0-9.]+)',cpu).group(1))\n"
      "t=int(re.search(r'threads=([0-9]+)',cpu).group(1))\n"
      "print(f'\\nGPU H/s = {g:.1f}')\n"
      "print(f'CPU H/s = {c:.1f}  ({t} threads)')\n"
      "print(f'GPU:CPU efficiency ratio = {g/c:.2f}x  (per-socket)')\n"
      "print(f'GPU vs one CPU core       = {g/(c/t):.2f}x')\n"),
 md("## Result & interpretation\n\n"
    "Record `GPU H/s`, `CPU H/s`, and the ratio above into `docs/GPU_FEASIBILITY_V1.md`.\n\n"
    "- The T4 shares one 16 GB pool; each nonce needs an 8 MiB scratchpad, so only ~1–2k nonces "
    "run concurrently (occupancy cap). The per-nonce dataset read-chain is a serial pointer-chase "
    "that GPUs cannot shortcut within a nonce.\n"
    "- A ratio near or below the CPU core count means the memory-latency design blunts the GPU's "
    "throughput advantage (good). A large ratio means rework is needed. **Measure, don't claim.**\n"),
]

nb = {"cells":cells,"metadata":{"accelerator":"GPU","colab":{"provenance":[]},
      "kernelspec":{"display_name":"Python 3","name":"python3"},
      "language_info":{"name":"python"}},"nbformat":4,"nbformat_minor":0}

out = os.path.join(os.path.dirname(__file__), "..", "meepow", "gpu", "v1_gpu_prototype.ipynb")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1)
print("wrote", os.path.normpath(out))
