// Sustained full-device MeepHash-W v2 miner — holds steady-state load for a fixed wall-clock
// duration so external power instrumentation can sample a stable interval.
//
// Prints a machine-readable summary line; the power harness parses HPS= from it.
//
// Usage: meepow-v2-sustained [threads] [seconds]
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "dataset_v2.hpp"
#include "meepow_v2.hpp"

using namespace meepow;
using clk = std::chrono::steady_clock;

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int T = argc > 1 ? atoi(argv[1]) : (int)std::thread::hardware_concurrency();
    double SECS = argc > 2 ? atof(argv[2]) : 60.0;

    uint8_t ek[32], sh[32];
    for (int i = 0; i < 32; ++i) { ek[i] = (uint8_t)(i * 7 + 1); sh[i] = (uint8_t)(i * 3 + 9); }
    uint8_t tmpl[32] = {0};
    size_t D = V2_SEED_WORDS * 512;                 // 32 MiB
    std::vector<uint64_t> ds(D);
    auto tb = clk::now();
    v2_dataset_fill(ds.data(), D, ek, 4);
    double build_s = std::chrono::duration<double>(clk::now() - tb).count();
    printf("SETUP_DONE dataset_build_s=%.2f threads=%d seconds=%.0f\n", build_s, T, SECS);
    fflush(stdout);

    std::atomic<uint64_t> hashes{0};
    std::atomic<bool> go{false}, stop{false};
    std::vector<std::thread> th;
    for (int t = 0; t < T; ++t) th.emplace_back([&, t] {
        V1Ctx* c = v2_ctx_create(ds, ek, sh, 4096, tmpl, sizeof(tmpl));
        uint8_t h[32];
        uint32_t n = (uint32_t)(t * 1000000);
        while (!go.load(std::memory_order_relaxed)) std::this_thread::yield();
        while (!stop.load(std::memory_order_relaxed)) {
            v2_hash(c, n++, h, nullptr, nullptr);
            hashes.fetch_add(1, std::memory_order_relaxed);
        }
        v1_ctx_free(c);
    });

    // STEADY-STATE WINDOW: everything before this marker is setup/alloc and must be excluded by
    // the external power sampler.
    printf("STEADY_BEGIN epoch_ms=%lld\n",
           (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count());
    fflush(stdout);
    auto t0 = clk::now();
    go.store(true);
    std::this_thread::sleep_for(std::chrono::duration<double>(SECS));
    stop.store(true);
    double wall = std::chrono::duration<double>(clk::now() - t0).count();
    printf("STEADY_END epoch_ms=%lld\n",
           (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count());
    fflush(stdout);
    for (auto& x : th) x.join();

    uint64_t total = hashes.load();
    printf("RESULT threads=%d wall_s=%.3f hashes=%llu HPS=%.2f\n", T, wall,
           (unsigned long long)total, total / wall);
    return 0;
}
