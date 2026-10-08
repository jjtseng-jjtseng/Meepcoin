#!/usr/bin/env python3
# Generates meepow/gpu/v2_gpu_exact_t4.ipynb — the EXACT MeepHash-W v2 CUDA test for Colab (T4).
#
# v2 of this notebook (corrected per review):
#   * correctness first (unchanged): must reproduce committed vectors_v2.txt byte-for-byte
#   * batch sweep BEYOND 1536 until allocation fails or throughput plateaus
#   * threads-per-block sweep (32/64/128/256)
#   * long steady-state timing: warmup + >=30 s continuous + >=5 trials, p50 and range
#   * ACTIVE power only: energy-counter delta preferred, else dense sampling gated to the
#     hashing window, discarding startup/shutdown samples
#   * real occupancy via cudaOccupancyMaxActiveBlocksPerMultiprocessor + clocks/temp/util
#   * Colab CPU cell converted to %%bash (was a Python SyntaxError)
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = open(os.path.join(HERE, "..", "meepow", "gpu", "v2_cuda_core.cuh"), encoding="utf-8").read()
VECS = open(os.path.join(HERE, "..", "meepow", "vectors", "vectors_v2.txt"), encoding="utf-8").read()

CU_MAIN = r'''
#include "v2_cuda_core.cuh"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <cuda_runtime.h>

#define CK(x) do { cudaError_t e=(x); if(e!=cudaSuccess){ printf("CUDA_ERR %s @%d\n", cudaGetErrorString(e), __LINE__); exit(1);} } while(0)

// Mapping A: one thread per nonce, CONTIGUOUS per-thread scratchpad (sp_stride = 1).
__global__ void k_contig(const MeepKeys* K, const uint64_t* ds, const MInstr* prog,
                         const uint8_t* tmpl, uint32_t tlen, uint32_t base_nonce, int n,
                         uint64_t* pool, uint8_t* outs) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t fb[512];
    meep_v2_hash_one(K, ds, prog, tmpl, tlen, base_nonce + i,
                     pool + (uint64_t)i * SCRATCH_WORDS, 1, fb, outs + (uint64_t)i * 32);
}

// Mapping B: one thread per nonce, INTERLEAVED scratchpad (sp_stride = n) so concurrent threads'
// word accesses are adjacent -> coalesced global memory transactions.
__global__ void k_interleaved(const MeepKeys* K, const uint64_t* ds, const MInstr* prog,
                              const uint8_t* tmpl, uint32_t tlen, uint32_t base_nonce, int n,
                              uint64_t* pool, uint8_t* outs) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t fb[512];
    meep_v2_hash_one(K, ds, prog, tmpl, tlen, base_nonce + i,
                     pool + i, (uint64_t)n, fb, outs + (uint64_t)i * 32);
}

// modes: verify | sweep | steady   (occupancy lives in v2_occ.cu, a separate TU)
int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "sweep";
    int batch   = argc > 2 ? atoi(argv[2]) : 1536;
    int mapping = argc > 3 ? atoi(argv[3]) : 1;     // 0 contiguous, 1 interleaved
    int tpb     = argc > 4 ? atoi(argv[4]) : 32;
    double secs = argc > 5 ? atof(argv[5]) : 30.0;

    MeepKeys hK; meep_init_keys(&hK);
    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i*7+1); sh[i] = (uint8_t)(i*3+9); }
    uint8_t tmpl[8] = {1,2,3,4,5,6,7,8};

    // dataset + program built on the HOST once (as a real miner would per epoch/job), then uploaded
    std::vector<uint64_t> D(DATASET_WORDS);
    meep_v2_build_dataset(&hK, ek, D.data());
    std::vector<MInstr> prog(PROG_LEN);
    { std::vector<uint8_t> pb(PROG_LEN*8); uint8_t fb[256];
      meep_derive_program(&hK, ek, sh, 4096, prog.data(), pb.data(), fb); }

    MeepKeys* dK; uint64_t* dD; MInstr* dP; uint8_t* dT; uint8_t* dOut; uint64_t* dPool;
    CK(cudaMalloc(&dK,sizeof(MeepKeys)));   CK(cudaMemcpy(dK,&hK,sizeof(MeepKeys),cudaMemcpyHostToDevice));
    CK(cudaMalloc(&dD,DATASET_WORDS*8));    CK(cudaMemcpy(dD,D.data(),DATASET_WORDS*8,cudaMemcpyHostToDevice));
    CK(cudaMalloc(&dP,PROG_LEN*sizeof(MInstr))); CK(cudaMemcpy(dP,prog.data(),PROG_LEN*sizeof(MInstr),cudaMemcpyHostToDevice));
    CK(cudaMalloc(&dT,8));                  CK(cudaMemcpy(dT,tmpl,8,cudaMemcpyHostToDevice));
    CK(cudaMalloc(&dOut,(size_t)batch*32));

    size_t poolBytes = (size_t)batch * SCRATCH_WORDS * 8;
    size_t freeB=0, totB=0; cudaMemGetInfo(&freeB,&totB);
    if (cudaMalloc(&dPool, poolBytes) != cudaSuccess) {
        printf("ALLOC_FAIL batch=%d needed_GiB=%.2f free_GiB=%.2f\n",
               batch, poolBytes/1073741824.0, freeB/1073741824.0);
        return 2;
    }
    int blocks = (batch + tpb - 1) / tpb;
    auto launch = [&](uint32_t base) {
        if (mapping == 0) k_contig<<<blocks,tpb>>>(dK,dD,dP,dT,8,base,batch,dPool,dOut);
        else              k_interleaved<<<blocks,tpb>>>(dK,dD,dP,dT,8,base,batch,dPool,dOut);
    };

    if (!strcmp(mode, "verify")) {
        launch(0); CK(cudaDeviceSynchronize());
        std::vector<uint8_t> h((size_t)batch*32);
        CK(cudaMemcpy(h.data(),dOut,(size_t)batch*32,cudaMemcpyDeviceToHost));
        for (int i = 0; i < batch; ++i) {
            printf("gpu %d ", i);
            for (int b = 0; b < 32; ++b) printf("%02x", h[(size_t)i*32+b]);
            printf("\n");
        }
        return 0;
    }

    // warmup (excluded from all timing and from the power window)
    launch(0); CK(cudaDeviceSynchronize());
    size_t usedB=0; { size_t f,t; cudaMemGetInfo(&f,&t); usedB = t - f; }

    if (!strcmp(mode, "sweep")) {                 // short throughput probe for the sweeps
        auto t0 = std::chrono::steady_clock::now();
        int waves = 3;
        for (int w = 0; w < waves; ++w) launch((uint32_t)w*batch);
        CK(cudaDeviceSynchronize());
        double s = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
        printf("SWEEP mapping=%d batch=%d tpb=%d hps=%.2f vram_gib=%.2f\n",
               mapping, batch, tpb, (double)batch*waves/s, usedB/1073741824.0);
        return 0;
    }

    // steady: continuous hashing for `secs`; prints a machine-readable window for the power poller
    printf("STEADY_BEGIN\n"); fflush(stdout);
    auto t0 = std::chrono::steady_clock::now();
    unsigned long long done = 0; uint32_t base = 0;
    while (std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count() < secs) {
        launch(base); base += batch;
        CK(cudaDeviceSynchronize());
        done += batch;
    }
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    printf("STEADY_END\n");
    printf("STEADY mapping=%d batch=%d tpb=%d secs=%.2f hashes=%llu hps=%.2f vram_gib=%.2f\n",
           mapping, batch, tpb, s, done, done/s, usedB/1073741824.0);
    return 0;
}
'''

CU_OCC = r'''
// Standalone occupancy report. Kept in its OWN translation unit so that if any CUDA occupancy API
// detail differs by toolkit version, the main benchmark still builds and runs.
#include "v2_cuda_core.cuh"
#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

__global__ void k_contig(const MeepKeys* K, const uint64_t* ds, const MInstr* prog,
                         const uint8_t* tmpl, uint32_t tlen, uint32_t base_nonce, int n,
                         uint64_t* pool, uint8_t* outs) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t fb[512];
    meep_v2_hash_one(K, ds, prog, tmpl, tlen, base_nonce + i,
                     pool + (uint64_t)i * SCRATCH_WORDS, 1, fb, outs + (uint64_t)i * 32);
}
__global__ void k_interleaved(const MeepKeys* K, const uint64_t* ds, const MInstr* prog,
                              const uint8_t* tmpl, uint32_t tlen, uint32_t base_nonce, int n,
                              uint64_t* pool, uint8_t* outs) {
    int i = blockIdx.x * blockDim.x + threadIdx.x; if (i >= n) return;
    uint8_t fb[512];
    meep_v2_hash_one(K, ds, prog, tmpl, tlen, base_nonce + i,
                     pool + i, (uint64_t)n, fb, outs + (uint64_t)i * 32);
}

int main(int argc, char** argv) {
    int tpb = argc > 1 ? atoi(argv[1]) : 32;
    cudaDeviceProp p;
    if (cudaGetDeviceProperties(&p, 0) != cudaSuccess) { printf("no device\n"); return 1; }
    int warpsMax = p.maxThreadsPerMultiProcessor / p.warpSize;
    printf("device=%s SMs=%d maxThreadsPerSM=%d warpSize=%d regsPerSM=%d\n",
           p.name, p.multiProcessorCount, p.maxThreadsPerMultiProcessor, p.warpSize,
           p.regsPerMultiprocessor);
    const void* ks[2] = {(const void*)k_contig, (const void*)k_interleaved};
    const char* nm[2] = {"contiguous", "interleaved"};
    for (int i = 0; i < 2; ++i) {
        int nb = 0;
        cudaFuncAttributes a;
        cudaError_t e1 = cudaOccupancyMaxActiveBlocksPerMultiprocessor(&nb, ks[i], tpb, 0);
        cudaError_t e2 = cudaFuncGetAttributes(&a, ks[i]);
        if (e1 != cudaSuccess || e2 != cudaSuccess) { printf("%s: query failed\n", nm[i]); continue; }
        int activeWarps = nb * tpb / p.warpSize;
        printf("%-12s tpb=%d blocks/SM=%d activeWarps/SM=%d theoWarps/SM=%d occupancy=%.3f "
               "regs/thread=%d localMem/thread=%zu shared/block=%zu\n",
               nm[i], tpb, nb, activeWarps, warpsMax, (double)activeWarps / warpsMax,
               a.numRegs, (size_t)a.localSizeBytes, (size_t)a.sharedSizeBytes);
    }
    return 0;
}
'''

POWER_PY = r'''
# Active-power measurement, gated to the hashing window only.
# Prefers the GPU total-energy counter (nvidia-smi total_energy_consumption, mJ) and takes a delta
# across the steady window; falls back to dense power.draw sampling with startup/shutdown discarded.
import subprocess, threading, time, re, statistics, json

def smi(q):
    try:
        return subprocess.run(['nvidia-smi', f'--query-gpu={q}', '--format=csv,noheader,nounits'],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ''

HAS_ENERGY = False
try:
    v = smi('total_energy_consumption')
    HAS_ENERGY = bool(v) and 'Supported' not in v and float(v.split('\n')[0]) >= 0
except Exception:
    HAS_ENERGY = False
print('energy counter available:', HAS_ENERGY)

def run_steady_with_power(batch, mapping, tpb, secs):
    samples, active = [], {'on': False}
    e0 = {'v': None}; e1 = {'v': None}
    def poll():
        while not active['on']:
            time.sleep(0.02)
        if HAS_ENERGY:
            try: e0['v'] = float(smi('total_energy_consumption').split('\n')[0])
            except Exception: pass
        while active['on']:
            row = smi('power.draw,utilization.gpu,clocks.sm,clocks.mem,temperature.gpu')
            if row:
                try:
                    p,u,cs,cm,t = [float(x) for x in row.split('\n')[0].split(',')]
                    samples.append((p,u,cs,cm,t))
                except Exception: pass
            time.sleep(0.1)
        if HAS_ENERGY:
            try: e1['v'] = float(smi('total_energy_consumption').split('\n')[0])
            except Exception: pass

    th = threading.Thread(target=poll); th.start()
    proc = subprocess.Popen(['./v2_gpu','steady',str(batch),str(mapping),str(tpb),str(secs)],
                            stdout=subprocess.PIPE, text=True, bufsize=1)
    out_lines = []
    for line in proc.stdout:
        out_lines.append(line)
        if 'STEADY_BEGIN' in line: active['on'] = True      # power window OPENS (post-warmup)
        if 'STEADY_END'   in line: active['on'] = False     # power window CLOSES
    proc.wait(); active['on'] = False; th.join()
    out = ''.join(out_lines)
    m = re.search(r'STEADY .*hps=([0-9.]+) vram_gib=([0-9.]+)', out)
    hps = float(m.group(1)) if m else 0.0
    vram = float(m.group(2)) if m else 0.0

    # discard first/last 10% of samples (ramp) -- the window is already gated, this is belt-and-braces
    s = samples[len(samples)//10 : len(samples) - len(samples)//10] or samples
    res = {'hps': hps, 'vram_gib': vram, 'n_samples': len(s)}
    if s:
        pw = [x[0] for x in s]
        res.update(avg_w=statistics.mean(pw), med_w=statistics.median(pw), peak_w=max(pw),
                   util=statistics.mean([x[1] for x in s]), sm_mhz=statistics.mean([x[2] for x in s]),
                   mem_mhz=statistics.mean([x[3] for x in s]), temp_c=statistics.mean([x[4] for x in s]))
    if HAS_ENERGY and e0['v'] is not None and e1['v'] is not None and secs > 0:
        res['energy_delta_j'] = (e1['v'] - e0['v']) / 1000.0
        res['energy_avg_w'] = res['energy_delta_j'] / secs
    return res
'''

def code(s): return {"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":s}
def md(s):   return {"cell_type":"markdown","metadata":{},"source":s}

cells = [
 md("# MeepHash-W **v2 (frozen)** - EXACT CUDA T4 benchmark (corrected)\n\n"
    "Correctness first: the *exact* frozen-v2 hash (full BLAKE3, framed `meep_xof`, v2 dataset, S3 "
    "scratch init, complete VM, read-chain, mix-back, final walk, finalization). Not a simplified model.\n\n"
    "**Corrections in this revision**\n"
    "* batch sweep continues **past 1536** until allocation fails or throughput plateaus\n"
    "* **threads-per-block sweep** (32/64/128/256)\n"
    "* **long steady-state** timing: warmup + >=30 s continuous + >=5 trials, p50 and range\n"
    "* **active power only** - energy-counter delta preferred; otherwise dense sampling gated to the "
    "hashing window with ramp samples discarded (the earlier 32.5 W / 119.1 H/s-per-W figure averaged "
    "~1 s of kernel with ~9 s of setup/idle **and** used batch 1024 instead of the best batch - it is void)\n"
    "* real **occupancy** via `cudaOccupancyMaxActiveBlocksPerMultiprocessor` (+ regs, local mem, clocks, temp)\n"
    "* Colab CPU cell converted to `%%bash` (previously a Python SyntaxError)\n\n"
    "**CPU denominator (measured locally, corrected):** sustained full-device 16-thread throughput is "
    "**387.9 H/s median** (range 374.5-396.2, n=5 x 30 s). The previously quoted 512.98 H/s was a "
    "0.25 s burst and is superseded. Browser: Chrome 57.8 H/s, Firefox 51.6 H/s (single worker).\n"),
 code("!nvidia-smi\n!nvcc --version | tail -2\n"),
 code("%%writefile v2_cuda_core.cuh\n" + CORE),
 code("%%writefile vectors_v2.txt\n" + VECS),
 code("%%writefile v2_gpu.cu\n" + CU_MAIN.strip() + "\n"),
 code("%%writefile v2_occ.cu\n" + CU_OCC.strip() + "\n"),
 code("!nvcc -O3 -arch=sm_75 -o v2_gpu v2_gpu.cu && echo BUILD_OK\n"
      "# occupancy reporter is a SEPARATE translation unit: if it fails to build, the benchmark\n"
      "# above still runs (only the occupancy numbers are lost).\n"
      "!nvcc -O3 -arch=sm_75 -o v2_occ v2_occ.cu && echo OCC_BUILD_OK || echo OCC_BUILD_FAILED_nonfatal\n"),
 md("## 1) Correctness - must be byte-identical to the committed vectors\n"
    "Both mappings, nonces 0..19, diffed against `vectors_v2.txt`. Performance below is only valid if this passes.\n"),
 code("import subprocess\n"
      "exp = {}\n"
      "for line in open('vectors_v2.txt'):\n"
      "    p = line.split()\n"
      "    if len(p)==4 and p[0]=='v2': exp[int(p[2])] = p[3]\n"
      "print('expected vectors:', len(exp))\n"
      "CORRECT = True\n"
      "for mapping,name in [(0,'contiguous'),(1,'interleaved')]:\n"
      "    out = subprocess.run(['./v2_gpu','verify','20',str(mapping),'32'],capture_output=True,text=True).stdout\n"
      "    got = {}\n"
      "    for line in out.splitlines():\n"
      "        p=line.split()\n"
      "        if len(p)==3 and p[0]=='gpu': got[int(p[1])]=p[2]\n"
      "    bad = [n for n in exp if got.get(n)!=exp[n]]\n"
      "    print(f'{name}: {len(exp)-len(bad)}/{len(exp)} match' + ('' if not bad else f'  MISMATCH {bad[:3]}'))\n"
      "    CORRECT = CORRECT and not bad\n"
      "print('\\nCORRECTNESS:', 'PASS' if CORRECT else 'FAIL - do NOT report performance')\n"),
 md("## 2) Batch sweep - push past 1536 until allocation fails or throughput plateaus\n"
    "Each nonce needs an 8 MiB scratchpad in global memory, so VRAM caps concurrency. Failures are reported honestly.\n"),
 code("import subprocess, re\n"
      "assert CORRECT, 'correctness failed; refusing to benchmark'\n"
      "batch_rows = []\n"
      "for b in [1024, 1280, 1536, 1600, 1664, 1728, 1792, 1856, 1920, 2048]:\n"
      "    o = subprocess.run(['./v2_gpu','sweep',str(b),'1','32'],capture_output=True,text=True).stdout\n"
      "    m = re.search(r'hps=([0-9.]+) vram_gib=([0-9.]+)', o)\n"
      "    if m:\n"
      "        batch_rows.append((b, float(m.group(1)), float(m.group(2))))\n"
      "        print(f'batch {b:5d}: {float(m.group(1)):9.2f} H/s   VRAM {float(m.group(2)):.2f} GiB')\n"
      "    else:\n"
      "        print(f'batch {b:5d}: {o.strip() or \"no result\"}')\n"
      "best_batch = max(batch_rows, key=lambda r: r[1])[0] if batch_rows else 1536\n"
      "print('\\nbest batch by throughput:', best_batch)\n"),
 md("## 3) Threads-per-block sweep at the best batch\n"),
 code("tpb_rows = []\n"
      "for t in [32, 64, 128, 256]:\n"
      "    o = subprocess.run(['./v2_gpu','sweep',str(best_batch),'1',str(t)],capture_output=True,text=True).stdout\n"
      "    m = re.search(r'hps=([0-9.]+)', o)\n"
      "    if m:\n"
      "        tpb_rows.append((t, float(m.group(1))))\n"
      "        print(f'tpb {t:4d}: {float(m.group(1)):9.2f} H/s')\n"
      "    else:\n"
      "        print(f'tpb {t:4d}: {o.strip() or \"no result\"}')\n"
      "best_tpb = max(tpb_rows, key=lambda r: r[1])[0] if tpb_rows else 32\n"
      "# also confirm interleaved still beats contiguous at the chosen config\n"
      "for mp,nm in [(0,'contiguous'),(1,'interleaved')]:\n"
      "    o = subprocess.run(['./v2_gpu','sweep',str(best_batch),str(mp),str(best_tpb)],capture_output=True,text=True).stdout\n"
      "    m = re.search(r'hps=([0-9.]+)', o)\n"
      "    if m: print(f'{nm}: {float(m.group(1)):9.2f} H/s')\n"
      "print('\\nbest tpb:', best_tpb)\n"),
 md("## 4) Long steady-state trials (>=5 x >=30 s) at the best configuration\n"),
 code("import statistics\n"
      "trials = []\n"
      "for i in range(5):\n"
      "    o = subprocess.run(['./v2_gpu','steady',str(best_batch),'1',str(best_tpb),'30'],capture_output=True,text=True).stdout\n"
      "    m = re.search(r'hps=([0-9.]+)', o)\n"
      "    if m:\n"
      "        trials.append(float(m.group(1))); print(f'trial {i+1}: {trials[-1]:.2f} H/s')\n"
      "trials.sort()\n"
      "if trials:\n"
      "    print(f'\\nGPU steady H/s  p50={statistics.median(trials):.2f}  min={trials[0]:.2f}  max={trials[-1]:.2f}  n={len(trials)}')\n"),
 md("## 5) Active GPU power (energy-counter delta preferred; sampling gated to the hashing window)\n"),
 code(POWER_PY.strip() + "\n"),
 code("res = run_steady_with_power(best_batch, 1, best_tpb, 45)\n"
      "import json; print(json.dumps(res, indent=1))\n"
      "W = res.get('energy_avg_w') or res.get('med_w')\n"
      "if W: print(f\"\\nACTIVE power {W:.1f} W  ->  GPU H/s per watt = {res['hps']/W:.3f}\")\n"
      "print('source:', 'energy counter delta' if 'energy_avg_w' in res else 'sampled power.draw (median, gated+trimmed)')\n"),
 md("## 6) Occupancy and limiters\n"),
 code("import os\n"
      "if os.path.exists('./v2_occ'):\n"
      "    for t in sorted({32, best_tpb}):\n"
      "        print(subprocess.run(['./v2_occ',str(t)],capture_output=True,text=True).stdout)\n"
      "else:\n"
      "    print('occupancy reporter unavailable (its build failed); ptxas stats below')\n"
      "!nvcc -O3 -arch=sm_75 --ptxas-options=-v -c v2_gpu.cu -o /dev/null 2>&1 | grep -E 'Function|registers|stack|spill|gmem|lmem' | head -20\n"),
 md("## 7) Colab CPU reference (SECONDARY only - does not replace the local CPU comparison)\n"),
 code("%%bash\n"
      "cat > cpu_ref.cpp <<'EOF'\n"
      "#define MEEP_HOST_ONLY\n"
      "#include \"v2_cuda_core.cuh\"\n"
      "#include <cstdio>\n#include <vector>\n#include <chrono>\n"
      "int main(){ MeepKeys K; meep_init_keys(&K); uint8_t ek[32],sh[32];\n"
      "  for(int i=0;i<32;++i){ek[i]=(uint8_t)(i*7+1);sh[i]=(uint8_t)(i*3+9);} uint8_t t[8]={1,2,3,4,5,6,7,8};\n"
      "  std::vector<uint64_t> D(DATASET_WORDS); meep_v2_build_dataset(&K,ek,D.data());\n"
      "  std::vector<MInstr> p(PROG_LEN); { std::vector<uint8_t> pb(PROG_LEN*8); uint8_t fb[256];\n"
      "    meep_derive_program(&K,ek,sh,4096,p.data(),pb.data(),fb); }\n"
      "  std::vector<uint64_t> SP(SCRATCH_WORDS); std::vector<uint8_t> fb(1024); uint8_t o[32];\n"
      "  meep_v2_hash_one(&K,D.data(),p.data(),t,8,0,SP.data(),1,fb.data(),o);\n"
      "  auto a=std::chrono::steady_clock::now(); int N=30;\n"
      "  for(int i=0;i<N;++i) meep_v2_hash_one(&K,D.data(),p.data(),t,8,i+1,SP.data(),1,fb.data(),o);\n"
      "  double s=std::chrono::duration<double>(std::chrono::steady_clock::now()-a).count();\n"
      "  printf(\"colab CPU 1-thread: %.2f H/s\\n\", N/s); return 0; }\n"
      "EOF\n"
      "g++ -O3 -std=c++17 cpu_ref.cpp -o cpu_ref && ./cpu_ref\n"),
 md("## 8) Final GPU report - paste these back\n\n"
    "```\nGPU model / CUDA / driver      : ___\nCorrectness (both mappings)    : PASS/FAIL\n"
    "Best batch / best tpb          : ___ / ___\nVRAM used                      : ___ GiB\n"
    "Steady H/s p50 (min-max, n=5)  : ___\nACTIVE power (source)          : ___ W (energy-counter | sampled)\n"
    "avg / median / peak W          : ___\nGPU util / SM MHz / mem MHz / T : ___\n"
    "GPU H/s per watt               : ___\nOccupancy (achieved/theoretical): ___\nRegisters / local mem per thread: ___\n"
    "Main limiter                   : scratchpad capacity | registers | latency | bandwidth\n"
    "Colab CPU 1-thread (secondary) : ___\n```\n\n"
    "**Efficiency gate.** GPU H/s-per-watt divided by CPU H/s-per-watt must be **<= 3x** "
    "(pre-registered, not to be changed after seeing results). The CPU denominator is measured "
    "locally on the Ryzen AI 7 PRO 350; if CPU power cannot be measured reliably the gate is "
    "**INCONCLUSIVE**, never PASS.\n"),
]

nb = {"cells": cells,
      "metadata": {"accelerator":"GPU","colab":{"provenance":[]},
                   "kernelspec":{"display_name":"Python 3","name":"python3"},
                   "language_info":{"name":"python"}},
      "nbformat":4,"nbformat_minor":0}
out = os.path.join(HERE, "..", "meepow", "gpu", "v2_gpu_exact_t4.ipynb")
with open(out, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1)
print("wrote", os.path.normpath(out))
