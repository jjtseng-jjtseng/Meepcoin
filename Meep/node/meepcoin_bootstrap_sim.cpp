// meepcoin-bootstrap-sim — isolate the causes of the launch difficulty spike.
//
// SIMULATION. Like meepcoin-difficulty-sim it calls the REAL cryptonote::next_difficulty(); nothing
// is reimplemented. But it fixes a modelling defect that made the earlier simulator unable to see
// this problem at all:
//
//   the earlier sim clamped every solve time to >= 1 second before adding it to the clock, so two
//   blocks could never share a timestamp. Same-second blocks are precisely what drives the launch
//   spike, so that clamp hid the entire phenomenon. Here time is accumulated as a double and the
//   RECORDED timestamp is floor(t) -- which is what a real miner writes, an integer second. At
//   difficulty 1 with any real hashrate, many blocks land in the same second.
//
// Validation target: the live chain produced difficulty 1,1,1,10,110,1210,13310,79860 at heights
// 0..7. A faithful model must reproduce that shape.
//
// Usage: meepcoin-bootstrap-sim [experiment] [--csv <dir>]
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/difficulty.h"

using cryptonote::difficulty_type;

static const size_t TARGET = DIFFICULTY_TARGET_V2;            // 60
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;   // 735
static const uint64_t GENESIS_TS = 1785283200;                // MEEPCOIN_GENESIS_TIMESTAMP

// ---------------------------------------------------------------- bootstrap policy
struct Policy {
    std::string name;
    // Difficulty forced for heights 1..fixed_n (0 = disabled).
    uint64_t fixed_n = 0;
    uint64_t fixed_diff = 1;
    // Refuse to adjust until at least min_samples blocks exist; hold hold_diff until then.
    uint64_t min_samples = 0;
    uint64_t hold_diff = 1;
    // Clamp each step to at most up_x higher / down_x lower than the previous difficulty.
    double up_x = 0;      // 0 = disabled
    double down_x = 0;    // 0 = disabled
};

struct Block {
    uint64_t height, timestamp;
    double solve_s;
    difficulty_type difficulty;
};

struct Chain {
    std::vector<uint64_t> ts;
    std::vector<difficulty_type> cd;
    std::vector<Block> blocks;
    double t = 0;                 // continuous clock, seconds
    std::mt19937_64 rng;
    Policy pol;

    Chain(uint64_t seed, const Policy &p, uint64_t genesis_ts, double launch_offset)
        : rng(seed), pol(p) {
        // The genesis block itself, at its own timestamp.
        ts.push_back(genesis_ts);
        cd.push_back(1);
        blocks.push_back(Block{0, genesis_ts, 0, 1});
        // Mining starts launch_offset seconds after the genesis timestamp.
        t = (double)genesis_ts + launch_offset;
    }

    difficulty_type raw_next() const {
        size_t n = ts.size();
        size_t take = std::min(n, BLOCKS_COUNT);
        // get_difficulty_for_next_block skips the genesis entry.
        size_t from = (n > take) ? n - take : 0;
        std::vector<uint64_t> a;
        std::vector<difficulty_type> b;
        for (size_t i = from; i < n; ++i) {
            if (i == 0) continue;
            a.push_back(ts[i]);
            b.push_back(cd[i]);
        }
        if (a.size() < 2) return 1;
        return cryptonote::next_difficulty(a, b, TARGET);
    }

    difficulty_type policy_next() const {
        uint64_t h = blocks.size();          // height of the block about to be mined
        if (pol.fixed_n && h <= pol.fixed_n) return pol.fixed_diff;
        if (pol.min_samples && h <= pol.min_samples) return pol.hold_diff;
        difficulty_type d = raw_next();
        if (d == 0) d = 1;
        if ((pol.up_x > 0 || pol.down_x > 0) && !blocks.empty()) {
            double prev = blocks.back().difficulty.convert_to<double>();
            double dd = d.convert_to<double>();
            if (pol.up_x > 0 && dd > prev * pol.up_x) dd = prev * pol.up_x;
            if (pol.down_x > 0 && dd < prev / pol.down_x) dd = prev / pol.down_x;
            if (dd < 1) dd = 1;
            d = (uint64_t)dd;
        }
        return d;
    }

    void mine(double H) {
        difficulty_type d = policy_next();
        if (d == 0) d = 1;
        double mean = d.convert_to<double>() / std::max(H, 1e-9);
        std::exponential_distribution<double> ed(1.0 / std::max(mean, 1e-12));
        double solve = ed(rng);
        // NO clamp to >= 1 s. Sub-second solves are the entire point of this study.
        t += solve;
        uint64_t rec = (uint64_t)t;      // a miner records whole seconds
        ts.push_back(rec);
        cd.push_back(cd.back() + d);
        blocks.push_back(Block{(uint64_t)blocks.size(), rec, solve, d});
    }
};

// ---------------------------------------------------------------- metrics
struct Result {
    double max_diff = 0, min_after_peak = 0;
    long peak_height = -1;
    long blocks_to_target = -1;    // first height where a 20-block mean interval is within 25%
    double secs_to_target = -1;
    double mean_interval_100 = 0;
    double worst_gap = 0;
};

static Result analyse(const std::vector<Block> &b, double H) {
    Result r;
    r.min_after_peak = 1e300;
    double sum = 0; size_t cnt = 0;
    for (size_t i = 1; i < b.size(); ++i) {
        double d = b[i].difficulty.convert_to<double>();
        if (d > r.max_diff) { r.max_diff = d; r.peak_height = (long)i; }
        if (i <= 100) { sum += b[i].solve_s; ++cnt; }
        r.worst_gap = std::max(r.worst_gap, b[i].solve_s);
    }
    for (size_t i = (size_t)std::max(0L, r.peak_height); i < b.size(); ++i)
        r.min_after_peak = std::min(r.min_after_peak, b[i].difficulty.convert_to<double>());
    r.mean_interval_100 = cnt ? sum / (double)cnt : 0;

    const size_t W = 20;
    for (size_t i = W; i < b.size(); ++i) {
        double s = 0;
        for (size_t j = i - W; j < i; ++j) s += b[j].solve_s;
        double m = s / (double)W;
        if (std::fabs(m - (double)TARGET) / (double)TARGET <= 0.25) {
            r.blocks_to_target = (long)i;
            r.secs_to_target = (double)b[i].timestamp - (double)b[0].timestamp;
            break;
        }
    }
    return r;
}

static void print_head(const std::vector<Block> &b, size_t n) {
    printf("      h  timestamp   solve_s     difficulty\n");
    for (size_t i = 0; i < std::min(n, b.size()); ++i)
        printf("    %3zu %11llu %9.3f %14s\n", i, (unsigned long long)b[i].timestamp,
               b[i].solve_s, cryptonote::hex(b[i].difficulty).c_str());
}

static void dump(const std::string &dir, const std::string &name, const std::vector<Block> &b) {
    if (dir.empty()) return;
    FILE *f = fopen((dir + "/" + name + ".csv").c_str(), "w");
    if (!f) return;
    fprintf(f, "height,timestamp,solve_s,difficulty\n");
    for (const auto &x : b)
        fprintf(f, "%llu,%llu,%.4f,%s\n", (unsigned long long)x.height,
                (unsigned long long)x.timestamp, x.solve_s,
                cryptonote::hex(x.difficulty).c_str());
    fclose(f);
}

static Result run_case(const char *label, const Policy &pol, uint64_t genesis_ts,
                       double launch_offset, double H, size_t nblocks, uint64_t seed,
                       const std::string &csvdir, bool show_head) {
    Chain c(seed, pol, genesis_ts, launch_offset);
    for (size_t i = 0; i < nblocks; ++i) c.mine(H);
    Result r = analyse(c.blocks, H);
    printf("  %-46s peak %12.0f @h%-4ld  min-after %10.0f  "
           "mean-iv(100) %7.1fs  to-target %s\n",
           label, r.max_diff, r.peak_height, r.min_after_peak, r.mean_interval_100,
           r.blocks_to_target < 0 ? "never" :
             (std::to_string(r.blocks_to_target) + " blk").c_str());
    if (show_head) print_head(c.blocks, 12);
    dump(csvdir, label, c.blocks);
    return r;
}

int main(int argc, char **argv) {
    std::string which = (argc > 1 && argv[1][0] != '-') ? argv[1] : "all";
    std::string csvdir;
    for (int i = 1; i < argc - 1; ++i)
        if (!std::strcmp(argv[i], "--csv")) csvdir = argv[i + 1];
    auto run = [&](const char *n) { return which == "all" || which == n; };

    const double H = 424.0;            // measured live miner hashrate, 12 threads
    const size_t N = 400;

    printf("MeepCoin difficulty-BOOTSTRAP simulation\n");
    printf("========================================\n");
    printf("SIMULATION. Calls the real cryptonote::next_difficulty(). Timestamps are floor()ed to\n");
    printf("whole seconds and solve times are NOT clamped, so same-second blocks occur naturally.\n");
    printf("target %zu s | window %d | lag %d | cut %d | reference hashrate %.0f H/s\n\n",
           TARGET, DIFFICULTY_WINDOW, DIFFICULTY_LAG, DIFFICULTY_CUT, H);

    Policy cur{"current"};

    // 0 ---------------------------------------------------------------- fidelity vs the live chain
    if (run("validate")) {
        printf("--- 0. MODEL VALIDATION against the observed live chain\n");
        printf("    live chain produced: 1, 1, 1, 10, 110, 1210, 13310, 79860 at heights 0..7\n");
        printf("    live launch offset was 132909 s after the genesis timestamp\n");
        run_case("validate-live-shape", cur, GENESIS_TS, 132909.0, H, 40, 12345, csvdir, true);
        printf("\n");
    }

    // 1 ---------------------------------------------------------------- genesis timestamp far back
    if (run("genesis-offset")) {
        printf("--- 1/2. Genesis timestamp: far before launch vs equal to launch\n");
        run_case("gts-offset-132909s (as shipped)", cur, GENESIS_TS, 132909.0, H, N, 1, csvdir, false);
        run_case("gts-offset-30d",                  cur, GENESIS_TS, 30*86400.0, H, N, 1, csvdir, false);
        run_case("gts-offset-0s (launch == genesis)",cur, GENESIS_TS, 0.0,       H, N, 1, csvdir, false);
        printf("    NOTE: the offset changes the FIRST interval only. It does not remove the spike,\n");
        printf("          because the spike is caused by same-second blocks, not by the offset.\n\n");
    }

    // 3/4 -------------------------------------------------------------- same-second vs +1 s
    if (run("timestamps")) {
        printf("--- 3/4. Same-second early blocks vs one-second-apart early blocks\n");
        // Same-second is the natural outcome at low difficulty; force the contrast by running the
        // identical policy at a hashrate low enough that solves exceed a second from the start.
        run_case("same-second (H=424, D starts at 1)", cur, GENESIS_TS, 0.0, H,   N, 2, csvdir, false);
        run_case("1s-apart   (H=0.5, D starts at 1)",  cur, GENESIS_TS, 0.0, 0.5, N, 2, csvdir, false);
        printf("    The only difference is how many blocks share a timestamp. That is the cause.\n\n");
    }

    // 5 ---------------------------------------------------------------- starting difficulty
    if (run("start-diff")) {
        printf("--- 5. Different starting difficulties (first block forced, then normal rules)\n");
        for (uint64_t d : {1ULL, 1000ULL, 25440ULL, 254400ULL}) {
            Policy p{"start"};
            p.fixed_n = 1; p.fixed_diff = d;
            char lbl[96];
            snprintf(lbl, sizeof(lbl), "start-diff-%llu", (unsigned long long)d);
            run_case(lbl, p, GENESIS_TS, 0.0, H, N, 3, csvdir, false);
        }
        printf("    25440 = 424 H/s x 60 s, i.e. a correct estimate for this miner.\n\n");
    }

    // 6 ---------------------------------------------------------------- fixed difficulty for N
    if (run("fixed-n")) {
        printf("--- 6. Hold a fixed difficulty for the first N blocks, then hand over\n");
        for (uint64_t n : {0ULL, 10ULL, 30ULL, 100ULL, 720ULL}) {
            Policy p{"fixed"};
            p.fixed_n = n; p.fixed_diff = 25440;
            char lbl[96];
            snprintf(lbl, sizeof(lbl), "fixed-25440-for-%llu-blocks", (unsigned long long)n);
            run_case(lbl, p, GENESIS_TS, 0.0, H, N, 4, csvdir, false);
        }
        printf("\n");
    }

    // 7 ---------------------------------------------------------------- bootstrap window rules
    if (run("bootstrap-window")) {
        printf("--- 7. Alternative rules before the window is populated\n");
        for (uint64_t m : {0ULL, 10ULL, 60ULL, 120ULL}) {
            Policy p{"minsamples"};
            p.min_samples = m; p.hold_diff = 25440;
            char lbl[96];
            snprintf(lbl, sizeof(lbl), "hold-until-%llu-samples", (unsigned long long)m);
            run_case(lbl, p, GENESIS_TS, 0.0, H, N, 5, csvdir, false);
        }
        // Bounded per-block movement, which is a bootstrap fix AND a steady-state damper.
        for (double ux : {2.0, 4.0, 8.0}) {
            Policy p{"clamp"};
            p.up_x = ux; p.down_x = ux;
            char lbl[96];
            snprintf(lbl, sizeof(lbl), "clamp-per-block-%.0fx-both-ways", ux);
            run_case(lbl, p, GENESIS_TS, 0.0, H, N, 5, csvdir, false);
        }
        printf("\n");
    }

    // 8 ---------------------------------------------------------------- hashrate estimate wrong
    if (run("estimate-error")) {
        printf("--- 8. Sensitivity: seeded difficulty right, and wrong by 10x each way\n");
        struct { const char *lbl; uint64_t d; double h; } cases[] = {
            {"seed-correct        (D=25440,  H=424)",   25440,  424.0},
            {"seed-10x-too-HIGH   (D=254400, H=424)",   254400, 424.0},
            {"seed-10x-too-LOW    (D=2544,   H=424)",   2544,   424.0},
            {"seed-correct-but-H-10x-higher",           25440,  4240.0},
            {"seed-correct-but-H-10x-lower",            25440,  42.4},
        };
        for (auto &c : cases) {
            Policy p{"seed"};
            p.fixed_n = 30; p.fixed_diff = c.d;      // hold 30 blocks, then hand over
            run_case(c.lbl, p, GENESIS_TS, 0.0, c.h, N, 6, csvdir, false);
        }
        printf("    All five hold the seed for 30 blocks before the normal rules take over.\n\n");
    }

    printf("========================================\n");
    printf("Columns: peak = highest difficulty reached; min-after = lowest difficulty at or after\n");
    printf("the peak; mean-iv(100) = mean solve time over the first 100 blocks (target %zu s);\n", TARGET);
    printf("to-target = first height where a 20-block mean interval is within 25%% of target.\n");
    return 0;
}
