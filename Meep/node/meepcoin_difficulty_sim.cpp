// meepcoin-difficulty-sim — exercise the REAL difficulty algorithm under controlled hashrate.
//
// This is a SIMULATION, clearly labelled as such. What makes it trustworthy is that it does not
// reimplement anything: it calls the actual consensus function
//
//     cryptonote::next_difficulty(timestamps, cumulative_difficulties, target_seconds)
//
// from src/cryptonote_basic/difficulty.cpp, with the same windowing Blockchain::get_difficulty_for
// _next_block() uses (the last DIFFICULTY_BLOCKS_COUNT = 735 entries, which next_difficulty then
// truncates to the oldest DIFFICULTY_WINDOW = 720, dropping the newest 15 -- that truncation IS the
// lag). So the difficulty numbers here are the daemon's own, not an approximation of them.
//
// What a simulation CANNOT show: real propagation, real reorgs, real validation cost, real miner
// behaviour. Those are covered by the live daemon tests. Anything here that depends on them is
// reported as out of scope rather than guessed at.
//
// Usage: meepcoin-difficulty-sim [scenario] [--csv <dir>]
//        meepcoin-difficulty-sim all --csv /tmp/diffsim
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/difficulty.h"

using cryptonote::difficulty_type;

static const size_t TARGET = DIFFICULTY_TARGET_V2;              // 60 s
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;     // 735

struct Block {
    uint64_t height;
    uint64_t timestamp;
    uint64_t interval;        // seconds since the previous block
    difficulty_type difficulty;
    double hashrate;          // H/s in effect while this block was being found
};

struct Chain {
    std::vector<uint64_t> timestamps;
    std::vector<difficulty_type> cumulative;
    std::vector<Block> blocks;
    uint64_t now = 1785283200;      // the MeepCoin genesis timestamp
    std::mt19937_64 rng;

    explicit Chain(uint64_t seed) : rng(seed) {}

    // Exactly the window Blockchain::get_difficulty_for_next_block() passes in.
    difficulty_type next_diff() const {
        size_t n = timestamps.size();
        size_t take = std::min(n, BLOCKS_COUNT);
        std::vector<uint64_t> ts(timestamps.end() - take, timestamps.end());
        std::vector<difficulty_type> cd(cumulative.end() - take, cumulative.end());
        return cryptonote::next_difficulty(ts, cd, TARGET);
    }

    // Mine one block at hashrate H (H/s). Solve time is exponential with mean difficulty/H.
    // skew_fn optionally perturbs the recorded timestamp (miner clock games, propagation delay).
    void mine(double H, const std::function<int64_t(uint64_t, std::mt19937_64 &)> &skew_fn = nullptr) {
        difficulty_type d = next_diff();
        if (d == 0) d = 1;
        double dd = d.convert_to<double>();
        double mean = (H > 0.0) ? (dd / H) : 1e18;
        std::exponential_distribution<double> exp_dist(1.0 / std::max(mean, 1e-9));
        double solve = exp_dist(rng);
        if (solve < 1.0) solve = 1.0;
        if (solve > 1e12) solve = 1e12;

        uint64_t prev = now;
        now += (uint64_t)solve;
        uint64_t recorded = now;
        if (skew_fn) {
            int64_t s = skew_fn(now, rng);
            // The daemon enforces CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT ahead of the median; clamp to
            // that so the simulation cannot explore states a real node would reject outright.
            int64_t maxfwd = (int64_t)CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
            if (s > maxfwd) s = maxfwd;
            int64_t cand = (int64_t)now + s;
            if (cand < (int64_t)prev + 1) cand = (int64_t)prev + 1;  // keep it monotone-ish
            recorded = (uint64_t)cand;
        }

        timestamps.push_back(recorded);
        cumulative.push_back(cumulative.empty() ? d : cumulative.back() + d);
        blocks.push_back(Block{(uint64_t)blocks.size(), recorded, (uint64_t)solve, d, H});
    }

    // Seed the chain so the difficulty window is already full and steady at hashrate H. Without
    // this every scenario would spend its first 735 blocks in warm-up and measure nothing.
    void warm_up(double H, size_t n) {
        // Bootstrap: next_difficulty returns 1 until there are 2 entries.
        for (size_t i = 0; i < n; ++i) mine(H);
    }
};

// ------------------------------------------------------------------ metrics
struct Stats {
    double mean_interval = 0, median_interval = 0, p90_interval = 0;
    double mean_diff = 0, max_diff = 0, min_diff = 0;
    double overshoot_pct = 0, undershoot_pct = 0;
    long recovery_blocks = -1;
    double recovery_seconds = -1;
    uint64_t longest_gap = 0;
};

static double dtod(const difficulty_type &d) { return d.convert_to<double>(); }

static Stats analyse(const std::vector<Block> &b, size_t from, double steady_diff) {
    Stats s;
    if (from >= b.size()) return s;
    std::vector<double> iv;
    double sum = 0, dsum = 0;
    s.min_diff = 1e300;
    for (size_t i = from; i < b.size(); ++i) {
        iv.push_back((double)b[i].interval);
        sum += (double)b[i].interval;
        double d = dtod(b[i].difficulty);
        dsum += d;
        s.max_diff = std::max(s.max_diff, d);
        s.min_diff = std::min(s.min_diff, d);
        s.longest_gap = std::max(s.longest_gap, b[i].interval);
    }
    size_t n = iv.size();
    s.mean_interval = sum / (double)n;
    s.mean_diff = dsum / (double)n;
    std::vector<double> sorted = iv;
    std::sort(sorted.begin(), sorted.end());
    s.median_interval = sorted[n / 2];
    s.p90_interval = sorted[(size_t)(0.9 * (double)(n - 1))];
    if (steady_diff > 0) {
        s.overshoot_pct = 100.0 * (s.max_diff - steady_diff) / steady_diff;
        s.undershoot_pct = 100.0 * (steady_diff - s.min_diff) / steady_diff;
    }
    return s;
}

// Blocks until a rolling 30-block mean interval returns to within tol of target, and the wall time.
static void recovery(const std::vector<Block> &b, size_t event_at, double tol, Stats &s) {
    const size_t W = 30;
    if (b.size() < event_at + W) return;
    uint64_t t0 = b[event_at].timestamp;
    for (size_t i = event_at + W; i < b.size(); ++i) {
        double sum = 0;
        for (size_t j = i - W; j < i; ++j) sum += (double)b[j].interval;
        double m = sum / (double)W;
        if (std::fabs(m - (double)TARGET) / (double)TARGET <= tol) {
            s.recovery_blocks = (long)(i - event_at);
            s.recovery_seconds = (double)b[i].timestamp - (double)t0;
            return;
        }
    }
}

static void dump_csv(const std::string &dir, const std::string &name,
                     const std::vector<Block> &b) {
    if (dir.empty()) return;
    std::string p = dir + "/" + name + ".csv";
    FILE *f = fopen(p.c_str(), "w");
    if (!f) return;
    fprintf(f, "height,timestamp,interval_s,difficulty,hashrate_hs\n");
    for (const auto &x : b)
        fprintf(f, "%llu,%llu,%llu,%s,%.3f\n",
                (unsigned long long)x.height, (unsigned long long)x.timestamp,
                (unsigned long long)x.interval,
                cryptonote::hex(x.difficulty).c_str(), x.hashrate);
    fclose(f);
}

// `equilibrium` is the difficulty the chain SHOULD settle at after the event, i.e. new_hashrate *
// target. Measuring overshoot against the PRE-event difficulty instead would report a legitimate
// 10x rise as "+900% overshoot", which is not overshoot at all -- it is the adjustment working.
static void report(const char *name, const char *desc, const std::vector<Block> &b,
                   size_t measure_from, double equilibrium, long event_at, const std::string &csvdir) {
    Stats s = analyse(b, measure_from, equilibrium);
    if (event_at >= 0) recovery(b, (size_t)event_at, 0.20, s);

    printf("\n--- %s\n", name);
    printf("    %s\n", desc);
    printf("    blocks %zu (measured from %zu)\n", b.size(), measure_from);
    printf("    interval   mean %8.1f s   median %8.1f s   p90 %8.1f s   target %zu s\n",
           s.mean_interval, s.median_interval, s.p90_interval, TARGET);
    printf("    bias vs target: %+.1f%%  (median < mean is expected: solve times are exponential)\n",
           100.0 * (s.mean_interval - (double)TARGET) / (double)TARGET);
    printf("    difficulty mean %12.0f   min %12.0f   max %12.0f\n",
           s.mean_diff, s.min_diff, s.max_diff);
    if (equilibrium > 0) {
        // Steady-state difficulty over the LAST 300 blocks, which is where the chain has settled.
        double tail = 0; size_t cnt = 0;
        for (size_t i = (b.size() > 300 ? b.size() - 300 : 0); i < b.size(); ++i) {
            tail += dtod(b[i].difficulty); ++cnt;
        }
        double settled = cnt ? tail / (double)cnt : 0;
        printf("    post-event equilibrium %.0f | settled (last 300 blk) %.0f -> %+.1f%% off\n",
               equilibrium, settled, 100.0 * (settled - equilibrium) / equilibrium);
        printf("    peak overshoot above equilibrium %+7.1f%%   deepest dip below %+7.1f%%\n",
               s.overshoot_pct, s.undershoot_pct);
    }
    printf("    longest single block gap %llu s (%.1f x target)\n",
           (unsigned long long)s.longest_gap, (double)s.longest_gap / (double)TARGET);
    if (event_at >= 0) {
        if (s.recovery_blocks >= 0)
            printf("    RECOVERY to within 20%% of target: %ld blocks, %.0f s (%.1f h)\n",
                   s.recovery_blocks, s.recovery_seconds, s.recovery_seconds / 3600.0);
        else
            printf("    RECOVERY: NOT reached within the simulated span\n");
    }
    dump_csv(csvdir, name, b);
}

// ------------------------------------------------------------------ scenarios
int main(int argc, char **argv) {
    std::string which = (argc > 1) ? argv[1] : "all";
    std::string csvdir;
    for (int i = 1; i < argc - 1; ++i)
        if (std::strcmp(argv[i], "--csv") == 0) csvdir = argv[i + 1];

    const double H0 = 400.0;     // ~400 H/s: one machine's measured sustained MeepHash-W v2 rate
    const size_t WARM = 900;     // > 735 so the window is full before measuring
    const double STEADY = H0 * (double)TARGET;   // difficulty a stable H0 should settle at

    printf("MeepCoin automatic-difficulty SIMULATION\n");
    printf("========================================\n");
    printf("SIMULATION -- calls the real cryptonote::next_difficulty(); no reimplementation.\n");
    printf("Does NOT model propagation, reorgs or validation cost; those are live-daemon tests.\n\n");
    printf("target %zu s | DIFFICULTY_WINDOW %d | LAG %d | CUT %d | BLOCKS_COUNT %d\n",
           TARGET, DIFFICULTY_WINDOW, DIFFICULTY_LAG, DIFFICULTY_CUT, DIFFICULTY_BLOCKS_COUNT);
    printf("baseline hashrate %.0f H/s -> expected steady difficulty %.0f\n", H0, STEADY);

    auto run = [&](const char *name) { return which == "all" || which == name; };

    // 1 -----------------------------------------------------------------
    if (run("stable-one-miner")) {
        Chain c(1);
        c.warm_up(H0, WARM);
        for (size_t i = 0; i < 1500; ++i) c.mine(H0);
        report("stable-one-miner", "one miner, constant 400 H/s, 1500 blocks after warm-up",
               c.blocks, WARM, STEADY, -1, csvdir);
    }

    // 2 -----------------------------------------------------------------
    if (run("stable-many-miners")) {
        // For difficulty only the aggregate matters; 8 miners at 50 H/s == 400 H/s aggregate. What
        // differs in reality is orphan rate and timestamp spread, which a single-chain simulation
        // cannot represent -- flagged rather than implied.
        Chain c(2);
        c.warm_up(H0, WARM);
        for (size_t i = 0; i < 1500; ++i) c.mine(H0);
        report("stable-many-miners",
               "8 miners x 50 H/s = 400 H/s aggregate (difficulty sees only the aggregate)",
               c.blocks, WARM, STEADY, -1, csvdir);
    }

    // 3 -----------------------------------------------------------------
    if (run("loss-90pct")) {
        Chain c(3);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        for (size_t i = 0; i < 2500; ++i) c.mine(H0 * 0.10);
        report("loss-90pct", "sudden 90% hashrate loss: 400 -> 40 H/s",
               c.blocks, ev, H0 * 0.10 * (double)TARGET, (long)ev, csvdir);
    }

    // 4 -----------------------------------------------------------------
    if (run("gain-10x")) {
        Chain c(4);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        for (size_t i = 0; i < 2500; ++i) c.mine(H0 * 10.0);
        report("gain-10x", "sudden 10x hashrate increase: 400 -> 4000 H/s",
               c.blocks, ev, H0 * 10.0 * (double)TARGET, (long)ev, csvdir);
    }

    // 5 -----------------------------------------------------------------
    if (run("gradual-growth")) {
        Chain c(5);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        double H = H0;
        for (size_t i = 0; i < 3000; ++i) { H *= 1.001; c.mine(H); }   // +0.1%/block ~ 20x over 3000
        report("gradual-growth", "+0.1% hashrate per block for 3000 blocks (400 -> ~8000 H/s)",
               c.blocks, ev, H * (double)TARGET, -1, csvdir);
    }

    // 6 -----------------------------------------------------------------
    if (run("bursty-browsers")) {
        Chain c(6);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        // Square wave: a crowd of browser miners triples the hashrate for 100 blocks, then leaves.
        for (size_t cyc = 0; cyc < 15; ++cyc) {
            for (size_t i = 0; i < 100; ++i) c.mine(H0 * 3.0);
            for (size_t i = 0; i < 100; ++i) c.mine(H0);
        }
        report("bursty-browsers", "15 cycles of 100 blocks at 3x then 100 blocks at 1x",
               c.blocks, ev, H0 * 2.0 * (double)TARGET, -1, csvdir);
    }

    // 7 -----------------------------------------------------------------
    if (run("stall-and-restart")) {
        Chain c(7);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        // Every miner leaves for 24 h of wall time, then 10% of the original returns. Nothing is
        // mined during the stall, so the ONLY way difficulty falls is the timestamp of the first
        // block after it -- difficulty is driven by block timestamps, never by wall clock.
        c.now += 24 * 3600;
        for (size_t i = 0; i < 2500; ++i) c.mine(H0 * 0.10);
        report("stall-and-restart",
               "all miners leave for 24 h, then 10% of the hashrate returns",
               c.blocks, ev, H0 * 0.10 * (double)TARGET, (long)ev, csvdir);
        // The decisive question for self-recovery: how long was the first post-stall block?
        if (c.blocks.size() > ev)
            printf("    first block after the stall took %llu s (%.1f x target) at difficulty %s\n",
                   (unsigned long long)c.blocks[ev].interval,
                   (double)c.blocks[ev].interval / (double)TARGET,
                   cryptonote::hex(c.blocks[ev].difficulty).c_str());
    }

    // 8 -----------------------------------------------------------------
    if (run("timestamp-manipulation")) {
        Chain c(8);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        // A miner controlling every block pushes each timestamp as far forward as the future-time
        // limit allows, trying to drive difficulty down. Clamped to the consensus limit.
        auto skew = [](uint64_t, std::mt19937_64 &) -> int64_t {
            return (int64_t)CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
        };
        for (size_t i = 0; i < 2000; ++i) c.mine(H0, skew);
        // Name the exact strategy. This tests ONE attack: a CONSTANT forward offset applied to
        // every block. It says nothing about alternating manipulation, selective timestamps placed
        // near the cut boundaries, or several colluding manipulators -- none of which are tested.
        report("timestamp-manipulation-CONSTANT-OFFSET",
               "single miner, CONSTANT +2 h offset on every block (one strategy of several)",
               c.blocks, ev, STEADY, -1, csvdir);
    }

    // 9 -----------------------------------------------------------------
    if (run("oscillating")) {
        Chain c(9);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        for (size_t i = 0; i < 3000; ++i) {
            double phase = 2.0 * 3.14159265358979 * (double)i / 400.0;   // 400-block period
            double H = H0 * (2.0 + 1.5 * std::sin(phase));               // 0.5x .. 3.5x
            c.mine(H);
        }
        report("oscillating", "sinusoidal hashrate, 400-block period, 0.5x to 3.5x of baseline",
               c.blocks, ev, H0 * 2.0 * (double)TARGET, -1, csvdir);
    }

    // 10 ----------------------------------------------------------------
    if (run("delayed-propagation")) {
        Chain c(10);
        c.warm_up(H0, WARM);
        size_t ev = c.blocks.size();
        // Timestamps arrive jittered by up to +/- 5 minutes relative to the true solve time, which
        // is what delayed propagation and clock spread look like to the difficulty algorithm.
        auto jitter = [](uint64_t, std::mt19937_64 &r) -> int64_t {
            std::uniform_int_distribution<int64_t> u(-300, 300);
            return u(r);
        };
        for (size_t i = 0; i < 2000; ++i) c.mine(H0, jitter);
        // SIMULATED timestamp jitter only. No network, no peers, no propagation: this perturbs the
        // recorded timestamps and nothing else. It is not a propagation test.
        report("timestamp-jitter-SIMULATED", "timestamps jittered +/- 300 s -- SIMULATION of clock "
               "spread, NOT a propagation test (no network is involved)",
               c.blocks, ev, STEADY, -1, csvdir);
    }

    printf("\n========================================\n");
    printf("SIMULATION COMPLETE. These are algorithm-level results; reorgs, propagation and\n");
    printf("validation cost are covered separately by the live daemon tests.\n");
    return 0;
}
