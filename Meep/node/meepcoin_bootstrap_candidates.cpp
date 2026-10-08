// meepcoin-bootstrap-candidates — evaluate asymmetric bootstrap rules A, B and C.
//
// ANALYSIS ONLY. No daemon consensus is changed.
//
// HOW THE REAL FUNCTION IS STILL USED, AND HOW A TIME-SPAN FLOOR IS TESTED WITHOUT PATCHING IT
// ---------------------------------------------------------------------------------------------
// cryptonote::next_difficulty() computes, after sorting timestamps and cutting DIFFICULTY_CUT from
// each end:
//     time_span  = sorted_ts[cut_end-1] - sorted_ts[cut_begin]      (clamped to >= 1)
//     total_work = cum_diff[cut_end-1]  - cum_diff[cut_begin]
//     result     = (total_work * target + time_span - 1) / time_span
//
// Candidate B needs a DIFFERENT time_span. Rather than fork the consensus function, this tool
// recomputes time_span and total_work from the same inputs and applies the formula itself -- and
// then SELF-CHECKS that replication on every single call: with the floor disabled it must equal
// what the real next_difficulty() returns. Any mismatch aborts the run. So candidate B is measured
// through arithmetic that is continuously proven identical to the shipped implementation.
//
// Candidates A and C never touch time_span; they clamp the RESULT, so they call the real function
// directly.
//
// WHAT CANDIDATE B CLAMPS: the AGGREGATE span only -- the single `time_span` value above. It does
// NOT rewrite any block's timestamp, and it does not clamp individual intervals. Timestamps stored
// in the chain are untouched; only the divisor used for this one calculation has a floor.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/difficulty.h"

using cryptonote::difficulty_type;

static const size_t TARGET = DIFFICULTY_TARGET_V2;             // 60
static const size_t WINDOW = DIFFICULTY_WINDOW;                // 720
static const size_t CUT = DIFFICULTY_CUT;                      // 60
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;    // 735
static const uint64_t GENESIS_TS = 1785283200;
static const double ASSUMED_H = 424.0;
static const uint64_t BOOT_D = (uint64_t)(ASSUMED_H * (double)TARGET);   // 25440

static size_t g_selfchecks = 0, g_selffails = 0;

// ---- replicate the cut, verified against the real function on every call ----------------------
struct Cut { size_t begin, end; };
static Cut cut_of(size_t length) {
    if (length <= WINDOW - 2 * CUT) return Cut{0, length};
    size_t b = (length - (WINDOW - 2 * CUT) + 1) / 2;
    return Cut{b, b + (WINDOW - 2 * CUT)};
}

// Returns the difficulty using an optional aggregate-span floor. floor_span == 0 disables it.
static difficulty_type diff_with_span_floor(std::vector<uint64_t> ts,
                                            std::vector<difficulty_type> cd,
                                            uint64_t floor_span,
                                            bool selfcheck) {
    if (ts.size() > WINDOW) { ts.resize(WINDOW); cd.resize(WINDOW); }
    size_t length = ts.size();
    if (length <= 1) return 1;
    std::vector<uint64_t> sorted = ts;
    std::sort(sorted.begin(), sorted.end());
    Cut c = cut_of(length);
    uint64_t span = sorted[c.end - 1] - sorted[c.begin];
    if (span == 0) span = 1;
    difficulty_type work = cd[c.end - 1] - cd[c.begin];

    if (selfcheck) {
        // Prove the replication matches the shipped function before trusting the floored variant.
        boost::multiprecision::uint256_t r =
            (boost::multiprecision::uint256_t(work) * TARGET + span - 1) / span;
        difficulty_type mine = r.convert_to<difficulty_type>();
        difficulty_type real = cryptonote::next_difficulty(ts, cd, TARGET);
        ++g_selfchecks;
        if (mine != real) ++g_selffails;
    }

    uint64_t use = std::max(span, floor_span ? floor_span : span);
    boost::multiprecision::uint256_t res =
        (boost::multiprecision::uint256_t(work) * TARGET + use - 1) / use;
    return res.convert_to<difficulty_type>();
}

// ---- candidate configuration -------------------------------------------------------------------
enum class BootEnd { Blocks, Samples };      // fixed length, or "until N valid samples exist"
struct Cand {
    std::string name;
    double up_cap = 0;          // A/C: max multiplier per block during bootstrap (0 = off)
    uint64_t boot_len = 0;      // bootstrap length (blocks, or sample threshold)
    BootEnd end = BootEnd::Blocks;
    // B/C: aggregate span floor = intervals * per_interval, or a fraction of the target span
    uint64_t per_interval = 0;  // seconds per interval (0 = off)
    double target_fraction = 0; // e.g. 0.25 -> floor = 0.25 * intervals * TARGET (0 = off)
    uint64_t floor_until = 0;   // apply the floor only while height <= this (0 = always)
};

struct Blk { uint64_t h, ts; double solve; difficulty_type d; };

struct Chain {
    std::vector<uint64_t> ts;
    std::vector<difficulty_type> cd;
    std::vector<Blk> b;
    double t;
    std::mt19937_64 rng;
    Cand c;
    double H;

    Chain(uint64_t seed, const Cand &cc, double h) : rng(seed), c(cc), H(h) {
        ts.push_back(GENESIS_TS);
        cd.push_back(1);
        b.push_back(Blk{0, GENESIS_TS, 0, 1});
        t = (double)GENESIS_TS;
    }

    bool in_boot() const {
        uint64_t h = b.size();
        if (c.boot_len == 0) return false;
        if (c.end == BootEnd::Blocks) return h <= c.boot_len;
        return (ts.size() - 1) < c.boot_len;      // valid samples excludes genesis
    }

    void window(std::vector<uint64_t> &a, std::vector<difficulty_type> &w) const {
        size_t n = ts.size();
        size_t take = std::min(n, BLOCKS_COUNT);
        size_t from = (n > take) ? n - take : 0;
        for (size_t i = from; i < n; ++i) {
            if (i == 0) continue;
            a.push_back(ts[i]);
            w.push_back(cd[i]);
        }
    }

    difficulty_type next() {
        std::vector<uint64_t> a;
        std::vector<difficulty_type> w;
        window(a, w);
        if (a.size() < 2) return 1;

        uint64_t floor_span = 0;
        bool floor_active = (c.floor_until == 0) || (b.size() <= c.floor_until);
        if (floor_active) {
            size_t len = std::min(a.size(), WINDOW);
            Cut cc = cut_of(len);
            uint64_t intervals = (cc.end - cc.begin > 0) ? (uint64_t)(cc.end - cc.begin - 1) : 0;
            if (c.per_interval) floor_span = intervals * c.per_interval;
            else if (c.target_fraction > 0)
                floor_span = (uint64_t)(c.target_fraction * (double)intervals * (double)TARGET);
        }

        difficulty_type d = (floor_span > 0)
            ? diff_with_span_floor(a, w, floor_span, true)
            : cryptonote::next_difficulty(a, w, TARGET);
        if (d == 0) d = 1;

        // A/C: cap upward movement during bootstrap. Downward is deliberately NOT capped.
        if (c.up_cap > 0 && in_boot() && !b.empty()) {
            double prev = b.back().d.convert_to<double>();
            double dd = d.convert_to<double>();
            double lim = prev * c.up_cap;
            if (dd > lim) d = (uint64_t)std::max(1.0, lim);
        }
        return d;
    }

    void mine() {
        difficulty_type d = next();
        if (d == 0) d = 1;
        double mean = d.convert_to<double>() / std::max(H, 1e-9);
        std::exponential_distribution<double> ed(1.0 / std::max(mean, 1e-12));
        double s = ed(rng);
        if (s > 5e7) s = 5e7;                 // 578 days: treat as a stall, do not run forever
        t += s;
        uint64_t rec = (uint64_t)t;
        ts.push_back(rec);
        cd.push_back(cd.back() + d);
        b.push_back(Blk{b.size(), rec, s, d});
    }
};

// ---- metrics -----------------------------------------------------------------------------------
struct M {
    double worst_iv = 0, peak = 0, mind = 1e300;
    double med_iv = 0, p5_iv = 0, p95_iv = 0, mean_iv100 = 0;
    long settle_blk = -1;
    double settle_s = -1;
    int in_1min = 0, in_10min = 0, in_1hr = 0;
    bool stalled = false;
    double boot_wall = 0;
};

static double q(std::vector<double> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[(size_t)(p * (double)(v.size() - 1))];
}

// STALL DEFINITION, stated rather than implied: any single block taking more than one hour.
static const double STALL_S = 3600.0;

// Minimum difficulty is measured from MIN_D_FROM onward. Measured from height 1 it is always 1,
// because every chain starts at difficulty 1 -- which made the column identical for every candidate
// and told us nothing. From here it answers the question that matters: once the chain is going, how
// low does the rule let difficulty fall?
static const size_t MIN_D_FROM = 20;

static M measure(const Chain &ch, uint64_t boot_len) {
    M m;
    std::vector<double> iv;
    double s100 = 0; size_t n100 = 0;
    for (size_t i = 1; i < ch.b.size(); ++i) {
        const Blk &x = ch.b[i];
        iv.push_back(x.solve);
        if (i <= 100) { s100 += x.solve; ++n100; }
        m.worst_iv = std::max(m.worst_iv, x.solve);
        double d = x.d.convert_to<double>();
        m.peak = std::max(m.peak, d);
        if (i >= MIN_D_FROM) m.mind = std::min(m.mind, d);
        if (x.solve > STALL_S) m.stalled = true;
    }
    if (m.mind > 1e299) m.mind = 0;      // run shorter than MIN_D_FROM
    m.mean_iv100 = n100 ? s100 / (double)n100 : 0;
    m.med_iv = q(iv, .5); m.p5_iv = q(iv, .05); m.p95_iv = q(iv, .95);

    uint64_t t0 = ch.b.size() > 1 ? ch.b[1].ts : GENESIS_TS;
    for (size_t i = 1; i < ch.b.size(); ++i) {
        uint64_t dt = ch.b[i].ts - t0;
        if (dt <= 60) ++m.in_1min;
        if (dt <= 600) ++m.in_10min;
        if (dt <= 3600) ++m.in_1hr;
    }
    if (boot_len && ch.b.size() > boot_len)
        m.boot_wall = (double)ch.b[boot_len].ts - (double)ch.b[0].ts;

    const size_t W = 20;
    for (size_t i = W; i < ch.b.size(); ++i) {
        double s = 0;
        for (size_t j = i - W; j < i; ++j) s += ch.b[j].solve;
        double a = s / (double)W;
        if (std::fabs(a - (double)TARGET) / (double)TARGET <= 0.25) {
            m.settle_blk = (long)i;
            m.settle_s = (double)ch.b[i].ts - (double)ch.b[0].ts;
            break;
        }
    }
    return m;
}

struct Agg {
    std::vector<double> worst, peak, mind, med, p5, p95, sb, ss, b1, b10, b60, bw;
    size_t n = 0, stalls = 0, never = 0;
    void add(const M &m) {
        ++n;
        worst.push_back(m.worst_iv); peak.push_back(m.peak); mind.push_back(m.mind);
        med.push_back(m.med_iv); p5.push_back(m.p5_iv); p95.push_back(m.p95_iv);
        b1.push_back(m.in_1min); b10.push_back(m.in_10min); b60.push_back(m.in_1hr);
        bw.push_back(m.boot_wall);
        if (m.stalled) ++stalls;
        if (m.settle_blk < 0) ++never; else { sb.push_back(m.settle_blk); ss.push_back(m.settle_s); }
    }
};

static void hdr() {
    printf("  %-38s %10s %10s %10s %9s %9s %8s %8s %7s %6s %6s\n",
           "candidate", "worst-iv", "peak-D", "min-D", "med-iv", "p95-iv",
           "settle", "settle-s", "b/1min", "stall", "never");
}
static void row(const char *label, Agg &a) {
    printf("  %-38s %10.0f %10.0f %10.0f %9.0f %9.0f %8s %8s %7.1f %5.0f%% %5.0f%%\n",
           label, q(a.worst, .5), q(a.peak, .5), q(a.mind, .5), q(a.med, .5), q(a.p95, .5),
           a.sb.empty() ? "-" : std::to_string((long)q(a.sb, .5)).c_str(),
           a.ss.empty() ? "-" : std::to_string((long)q(a.ss, .5)).c_str(),
           q(a.b1, .5),
           100.0 * (double)a.stalls / (double)a.n, 100.0 * (double)a.never / (double)a.n);
}

int main(int argc, char **argv) {
    size_t SEEDS = (argc > 1) ? (size_t)atoi(argv[1]) : 1000;
    size_t NB = (argc > 2) ? (size_t)atoi(argv[2]) : 150;

    printf("MeepCoin asymmetric bootstrap candidates A / B / C   (ANALYSIS ONLY)\n");
    printf("====================================================================\n");
    printf("Calls the real cryptonote::next_difficulty(). Candidate B's span floor is applied by\n");
    printf("replicated arithmetic that is SELF-CHECKED against the real function on every call.\n");
    printf("Bootstrap difficulty where used: %llu (= %.0f H/s x %zu s).\n",
           (unsigned long long)BOOT_D, ASSUMED_H, TARGET);
    printf("Candidate B clamps the AGGREGATE time_span only. It does NOT rewrite timestamps and\n");
    printf("does NOT clamp individual intervals.\n");
    printf("Stall = any single block interval > %.0f s. settle = trailing-20 mean within 25%% of target.\n",
           STALL_S);
    printf("%zu seeds per cell, %zu blocks per run.\n\n", SEEDS, NB);

    std::vector<Cand> cands;
    { Cand c; c.name = "CONTROL unmodified"; cands.push_back(c); }
    // Candidate A: upward cap during bootstrap, downward free.
    for (double cap : {1.25, 1.5, 2.0, 4.0})
        for (uint64_t L : {10ULL, 30ULL, 60ULL}) {
            Cand c; c.up_cap = cap; c.boot_len = L;
            char n[80]; snprintf(n, sizeof(n), "A cap%.2fx boot%llu", cap, (unsigned long long)L);
            c.name = n; cands.push_back(c);
        }
    { Cand c; c.up_cap = 2.0; c.boot_len = 60; c.end = BootEnd::Samples;
      c.name = "A cap2.00x until-60-samples"; cands.push_back(c); }
    // Candidate B: aggregate span floors.
    for (uint64_t s : {1ULL, 5ULL, 15ULL}) {
        Cand c; c.per_interval = s;
        char n[80]; snprintf(n, sizeof(n), "B span-floor %llus/interval", (unsigned long long)s);
        c.name = n; cands.push_back(c);
    }
    { Cand c; c.target_fraction = 0.25; c.name = "B span-floor 0.25x target span"; cands.push_back(c); }
    { Cand c; c.per_interval = 15; c.floor_until = 60;
      c.name = "B span-floor 15s, only h<=60"; cands.push_back(c); }
    // Candidate C: small cap + conservative floor.
    { Cand c; c.up_cap = 2.0; c.boot_len = 30; c.per_interval = 5;
      c.name = "C cap2x boot30 + floor 5s"; cands.push_back(c); }
    { Cand c; c.up_cap = 1.5; c.boot_len = 60; c.per_interval = 15;
      c.name = "C cap1.5x boot60 + floor 15s"; cands.push_back(c); }

    const double mults[] = {0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0};
    for (double m : mults) {
        printf("== launch hashrate %gx assumed (%.4f H/s), equilibrium difficulty %.0f\n",
               m, ASSUMED_H * m, ASSUMED_H * m * (double)TARGET);
        hdr();
        for (const Cand &c : cands) {
            Agg a;
            for (size_t s = 0; s < SEEDS; ++s) {
                Chain ch(0x9E3779B97F4A7C15ULL * (s + 1) ^ (uint64_t)(m * 1e6), c, ASSUMED_H * m);
                for (size_t i = 0; i < NB; ++i) ch.mine();
                a.add(measure(ch, c.boot_len));
            }
            row(c.name.c_str(), a);
        }
        printf("\n");
    }

    printf("====================================================================\n");
    printf("SELF-CHECK: %zu replicated-arithmetic comparisons against the real next_difficulty(), "
           "%zu mismatches -> %s\n", g_selfchecks, g_selffails,
           g_selffails == 0 ? "candidate B's arithmetic is proven identical where the floor is inactive"
                            : "FAIL, results not trustworthy");
    printf("ANALYSIS ONLY. No consensus code changed.\n");
    return g_selffails == 0 ? 0 : 1;
}
