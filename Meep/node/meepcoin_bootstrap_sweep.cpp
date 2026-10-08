// meepcoin-bootstrap-sweep — evidence for (or against) a fixed-difficulty bootstrap rule.
//
// ANALYSIS ONLY. Nothing here is implemented in the daemon. Calls the REAL
// cryptonote::next_difficulty(); nothing is reimplemented.
//
// Answers, in order, the twelve evidence items:
//   1  the exact bootstrap difficulty used, printed with every result
//   2  how it was selected                     -> BOOTSTRAP_D = ASSUMED_H * TARGET, stated below
//   3  "to-target" defined                     -> see TO_TARGET_DEF
//   4  >= 100 deterministic seeds per candidate
//   5  launch hashrates at 0.01x .. 100x of assumed
//   6  distributions: median, p5, p95, worst interval, peak/min difficulty, blocks+time to settle
//   7  bootstrap lengths N = 0, 10, 20, 30, 60, 100
//   8  the exact boundary at N-1, N, N+1, N+2
//   9  competing branches and reorg across the boundary
//  10  constant / alternating / selective-future / cut-boundary timestamp strategies,
//      during bootstrap and immediately after handoff
//  11  a miner with 100x the expected hashrate racing through the bootstrap section
//  12  byte-for-byte identity with the existing calculation after the handoff height
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

static const size_t TARGET = DIFFICULTY_TARGET_V2;              // 60 s
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;     // 735
static const uint64_t GENESIS_TS = 1785283200;
static const int64_t FTL = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;  // 7200 s
static const size_t TS_CHECK_WINDOW = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;  // 60

// ---- item 2: how the bootstrap difficulty was selected -----------------------------------------
// ASSUMED_H is a guess at aggregate launch hashrate. On this machine one miner sustained ~424 H/s
// with 12 threads, so 424 H/s is used as "1x" throughout. The bootstrap difficulty is then
//     BOOTSTRAP_D = ASSUMED_H * TARGET
// i.e. the difficulty at which a miner of exactly ASSUMED_H would average one block per target
// period. There is nothing clever about it: it is the equilibrium difficulty for the assumed
// hashrate. Its whole justification is that being wrong is survivable, which items 5/6 measure.
static const double ASSUMED_H = 424.0;
static const uint64_t BOOTSTRAP_D = (uint64_t)(ASSUMED_H * (double)TARGET);   // 25440

// ---- item 3: "to-target" defined ---------------------------------------------------------------
// The first height h at which the mean SOLVE TIME of blocks (h-20, h] lies within +/-25% of the
// 60 s target, i.e. within [45 s, 75 s]. Reported as "never" if no such height exists in the run.
static const size_t SETTLE_WINDOW = 20;
static const double SETTLE_TOL = 0.25;
static const char *TO_TARGET_DEF =
    "first height whose trailing 20-block mean solve time is within +/-25% of 60 s (45-75 s)";

// ---- timestamp strategies ----------------------------------------------------------------------
enum class TsAttack { None, Constant, Alternating, SelectiveFuture, CutBoundary };
static const char *ts_name(TsAttack a) {
    switch (a) {
        case TsAttack::None: return "honest";
        case TsAttack::Constant: return "constant +FTL";
        case TsAttack::Alternating: return "alternating +FTL/min";
        case TsAttack::SelectiveFuture: return "selective future (1 in 10)";
        case TsAttack::CutBoundary: return "cut-boundary (extremes)";
    }
    return "?";
}

enum class AttackWhen { Never, Bootstrap, AfterHandoff, Always };

struct Cfg {
    uint64_t N = 0;                 // bootstrap length; 0 = no bootstrap rule
    uint64_t boot_d = BOOTSTRAP_D;
    double H = ASSUMED_H;
    TsAttack attack = TsAttack::None;
    AttackWhen when = AttackWhen::Never;
};

struct Blk {
    uint64_t height, ts;
    double solve;
    difficulty_type d;
};

struct Chain {
    std::vector<uint64_t> ts;
    std::vector<difficulty_type> cd;
    std::vector<Blk> b;
    double t;
    std::mt19937_64 rng;
    Cfg cfg;

    Chain(uint64_t seed, const Cfg &c) : rng(seed), cfg(c) {
        ts.push_back(GENESIS_TS);
        cd.push_back(1);
        b.push_back(Blk{0, GENESIS_TS, 0, 1});
        t = (double)GENESIS_TS;
    }

    // Exactly the window Blockchain::get_difficulty_for_next_block() passes in (genesis skipped).
    difficulty_type raw_next() const {
        size_t n = ts.size();
        size_t take = std::min(n, BLOCKS_COUNT);
        size_t from = (n > take) ? n - take : 0;
        std::vector<uint64_t> a;
        std::vector<difficulty_type> c;
        for (size_t i = from; i < n; ++i) {
            if (i == 0) continue;
            a.push_back(ts[i]);
            c.push_back(cd[i]);
        }
        if (a.size() < 2) return 1;
        return cryptonote::next_difficulty(a, c, TARGET);
    }

    difficulty_type policy_next() const {
        uint64_t h = b.size();
        if (cfg.N && h <= cfg.N) return cfg.boot_d;
        return raw_next();
    }

    bool attacking(uint64_t h) const {
        bool in_boot = (cfg.N && h <= cfg.N);
        switch (cfg.when) {
            case AttackWhen::Never: return false;
            case AttackWhen::Bootstrap: return in_boot;
            case AttackWhen::AfterHandoff: return !in_boot;
            case AttackWhen::Always: return true;
        }
        return false;
    }

    // Lowest timestamp consensus would accept: the median of the last TS_CHECK_WINDOW timestamps.
    uint64_t min_acceptable_ts() const {
        size_t n = ts.size();
        size_t take = std::min(n, TS_CHECK_WINDOW);
        std::vector<uint64_t> w(ts.end() - take, ts.end());
        std::sort(w.begin(), w.end());
        return w[w.size() / 2];
    }

    void mine() {
        uint64_t h = b.size();
        difficulty_type d = policy_next();
        if (d == 0) d = 1;
        double mean = d.convert_to<double>() / std::max(cfg.H, 1e-9);
        std::exponential_distribution<double> ed(1.0 / std::max(mean, 1e-12));
        double solve = ed(rng);
        t += solve;
        uint64_t honest = (uint64_t)t;          // whole seconds, as a miner records
        uint64_t rec = honest;

        if (attacking(h)) {
            uint64_t lo = min_acceptable_ts();
            switch (cfg.attack) {
                case TsAttack::Constant:
                    rec = honest + (uint64_t)FTL;
                    break;
                case TsAttack::Alternating:
                    rec = (h % 2 == 0) ? honest + (uint64_t)FTL : std::max(lo, honest > 1 ? honest - 1 : honest);
                    break;
                case TsAttack::SelectiveFuture:
                    rec = (h % 10 == 0) ? honest + (uint64_t)FTL : honest;
                    break;
                case TsAttack::CutBoundary:
                    // Try to occupy the sorted extremes so the manipulated values land in the cut
                    // region: alternate between the highest and lowest values consensus accepts.
                    rec = (h % 2 == 0) ? honest + (uint64_t)FTL : lo;
                    break;
                default: break;
            }
            if (rec < lo) rec = lo;
        }

        ts.push_back(rec);
        cd.push_back(cd.back() + d);
        b.push_back(Blk{h, rec, solve, d});
    }
};

// ---- metrics -----------------------------------------------------------------------------------
struct Run {
    double peak = 0, mind = 1e300, worst_iv = 0, median_iv = 0;
    long settle_blocks = -1;
    double settle_secs = -1;
};

static Run measure(const std::vector<Blk> &b) {
    Run r;
    std::vector<double> iv;
    for (size_t i = 1; i < b.size(); ++i) {
        double d = b[i].d.convert_to<double>();
        r.peak = std::max(r.peak, d);
        r.mind = std::min(r.mind, d);
        r.worst_iv = std::max(r.worst_iv, b[i].solve);
        iv.push_back(b[i].solve);
    }
    if (!iv.empty()) {
        std::vector<double> s = iv;
        std::sort(s.begin(), s.end());
        r.median_iv = s[s.size() / 2];
    }
    for (size_t i = SETTLE_WINDOW; i < b.size(); ++i) {
        double sum = 0;
        for (size_t j = i - SETTLE_WINDOW; j < i; ++j) sum += b[j].solve;
        double m = sum / (double)SETTLE_WINDOW;
        if (std::fabs(m - (double)TARGET) / (double)TARGET <= SETTLE_TOL) {
            r.settle_blocks = (long)i;
            r.settle_secs = (double)b[i].ts - (double)b[0].ts;
            break;
        }
    }
    return r;
}

static double pct(std::vector<double> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t i = (size_t)(p * (double)(v.size() - 1));
    return v[i];
}

struct Agg {
    std::vector<double> peak, mind, worst_iv, settle_b, settle_s;
    size_t never = 0, n = 0;
    void add(const Run &r) {
        ++n;
        peak.push_back(r.peak);
        mind.push_back(r.mind);
        worst_iv.push_back(r.worst_iv);
        if (r.settle_blocks < 0) ++never;
        else { settle_b.push_back((double)r.settle_blocks); settle_s.push_back(r.settle_secs); }
    }
};

static void print_agg(const char *label, Agg &a) {
    printf("  %-34s peak p50 %10.0f [p5 %9.0f p95 %10.0f] | min p50 %9.0f | "
           "worst-iv p50 %7.0fs p95 %8.0fs | settle p50 %6s blk %8s | never %zu/%zu\n",
           label,
           pct(a.peak, .5), pct(a.peak, .05), pct(a.peak, .95),
           pct(a.mind, .5),
           pct(a.worst_iv, .5), pct(a.worst_iv, .95),
           a.settle_b.empty() ? "-" : std::to_string((long)pct(a.settle_b, .5)).c_str(),
           a.settle_s.empty() ? "-" : (std::to_string((long)pct(a.settle_s, .5)) + "s").c_str(),
           a.never, a.n);
}

int main(int argc, char **argv) {
    std::string only = (argc > 1) ? argv[1] : "all";
    auto run = [&](const char *n) { return only == "all" || only == n; };

    const size_t SEEDS = 100;
    const size_t NBLOCKS = 200;

    printf("MeepCoin bootstrap-candidate SWEEP  (ANALYSIS ONLY -- nothing implemented)\n");
    printf("=========================================================================\n");
    printf("Calls the real cryptonote::next_difficulty(). target %zu s | window %d | lag %d | cut %d\n",
           TARGET, DIFFICULTY_WINDOW, DIFFICULTY_LAG, DIFFICULTY_CUT);
    printf("\nITEM 1/2 -- bootstrap difficulty used in EVERY experiment below: %llu\n",
           (unsigned long long)BOOTSTRAP_D);
    printf("   selected as ASSUMED_H * TARGET = %.0f H/s * %zu s. ASSUMED_H is the sustained rate\n",
           ASSUMED_H, TARGET);
    printf("   one 12-thread miner measured on this machine. It is the equilibrium difficulty for\n");
    printf("   that assumed hashrate -- nothing more. Item 5/6 measure the cost of it being wrong.\n");
    printf("ITEM 3 -- \"to-target\"/settle = %s\n", TO_TARGET_DEF);
    printf("ITEM 4 -- %zu deterministic seeds per cell, %zu blocks each\n\n", SEEDS, NBLOCKS);

    // ---------------------------------------------------------------- items 4,5,6,7
    if (run("sweep")) {
        printf("=== ITEMS 4-7: N x launch-hashrate sweep, %zu seeds per cell ===\n", SEEDS);
        const double mults[] = {0.01, 0.1, 1.0, 10.0, 100.0};
        const uint64_t Ns[] = {0, 10, 20, 30, 60, 100};
        for (double m : mults) {
            printf("\n-- launch hashrate %gx assumed  (%.2f H/s), equilibrium difficulty %.0f\n",
                   m, ASSUMED_H * m, ASSUMED_H * m * (double)TARGET);
            for (uint64_t N : Ns) {
                Agg a;
                for (size_t s = 0; s < SEEDS; ++s) {
                    Cfg c;
                    c.N = N; c.H = ASSUMED_H * m;
                    Chain ch(1000000 * (uint64_t)(m * 100) + 1000 * N + s, c);
                    for (size_t i = 0; i < NBLOCKS; ++i) ch.mine();
                    a.add(measure(ch.b));
                }
                char lbl[64];
                snprintf(lbl, sizeof(lbl), "N=%llu", (unsigned long long)N);
                print_agg(lbl, a);
            }
        }
        printf("\n");
    }

    // ---------------------------------------------------------------- item 8
    if (run("boundary")) {
        printf("=== ITEM 8: the exact handoff boundary, N=30, %zu seeds ===\n", SEEDS);
        printf("  height:        N-1=29        N=30        N+1=31       N+2=32   (median difficulty)\n");
        std::vector<double> h29, h30, h31, h32;
        for (size_t s = 0; s < SEEDS; ++s) {
            Cfg c; c.N = 30; c.H = ASSUMED_H;
            Chain ch(7000 + s, c);
            for (size_t i = 0; i < 40; ++i) ch.mine();
            h29.push_back(ch.b[29].d.convert_to<double>());
            h30.push_back(ch.b[30].d.convert_to<double>());
            h31.push_back(ch.b[31].d.convert_to<double>());
            h32.push_back(ch.b[32].d.convert_to<double>());
        }
        printf("            %12.0f %12.0f %12.0f %12.0f\n",
               pct(h29, .5), pct(h30, .5), pct(h31, .5), pct(h32, .5));
        printf("  p95:      %12.0f %12.0f %12.0f %12.0f\n",
               pct(h29, .95), pct(h30, .95), pct(h31, .95), pct(h32, .95));
        printf("  Heights <= N carry the fixed value; the first computed difficulty is at N+1.\n\n");
    }

    // ---------------------------------------------------------------- item 12
    if (run("identity")) {
        printf("=== ITEM 12: after handoff, byte-for-byte identical to the existing calculation ===\n");
        size_t checked = 0, mismatch = 0;
        for (size_t s = 0; s < 200; ++s) {
            Cfg c; c.N = 30; c.H = ASSUMED_H * ((s % 5) ? 1.0 : 10.0);
            Chain ch(31337 + s, c);
            for (size_t i = 0; i < 120; ++i) {
                uint64_t h = ch.b.size();
                if (h > c.N) {
                    // For the SAME history, the policy result must equal the untouched algorithm.
                    difficulty_type p = ch.policy_next();
                    difficulty_type r = ch.raw_next();
                    ++checked;
                    if (p != r) ++mismatch;
                }
                ch.mine();
            }
        }
        printf("  compared %zu post-handoff difficulties across 200 histories: %zu mismatches\n",
               checked, mismatch);
        printf("  ITEM 12: %s\n\n", mismatch == 0 ? "PASS -- identical after the handoff height"
                                                  : "FAIL -- the rule leaks past the handoff");
    }

    // ---------------------------------------------------------------- item 9
    if (run("reorg")) {
        printf("=== ITEM 9: competing branches and reorg across the bootstrap boundary ===\n");
        printf("  Two branches fork at height 25 (inside bootstrap, N=30) and run to height 40.\n");
        size_t same_boot = 0, trials = 100, adv = 0;
        for (size_t s = 0; s < trials; ++s) {
            Cfg c; c.N = 30; c.H = ASSUMED_H;
            Chain base(90000 + s, c);
            for (size_t i = 0; i < 25; ++i) base.mine();
            Chain A = base, B = base;
            A.rng.seed(500000 + s);
            B.rng.seed(900000 + s);
            B.cfg.H = ASSUMED_H * 4.0;                 // B has 4x the hashrate
            for (size_t i = 0; i < 15; ++i) { A.mine(); B.mine(); }
            // The bootstrap difficulty depends on HEIGHT alone, so both branches must see the same
            // value at the same height inside the bootstrap -- no branch can gain from the rule.
            bool eq = true;
            for (uint64_t h = 26; h <= 30; ++h)
                if (A.b[h].d != B.b[h].d) eq = false;
            if (eq) ++same_boot;
            // Cumulative work decides the winner, as usual.
            if (B.cd.back() > A.cd.back()) ++adv;
        }
        printf("  identical bootstrap difficulty on both branches at every height 26..30: %zu/%zu\n",
               same_boot, trials);
        printf("  higher-hashrate branch won on cumulative work: %zu/%zu\n", adv, trials);
        printf("  ITEM 9: %s\n\n", same_boot == trials
               ? "the rule is height-indexed, so it grants no branch an advantage"
               : "WARNING -- branches saw different bootstrap difficulty at the same height");
    }

    // ---------------------------------------------------------------- item 10
    if (run("timestamps")) {
        printf("=== ITEM 10: timestamp strategies, during bootstrap and after handoff (N=30) ===\n");
        printf("  Baseline honest median difficulty at h=200 is the comparison point.\n");
        const TsAttack atks[] = {TsAttack::None, TsAttack::Constant, TsAttack::Alternating,
                                 TsAttack::SelectiveFuture, TsAttack::CutBoundary};
        const AttackWhen whens[] = {AttackWhen::Bootstrap, AttackWhen::AfterHandoff, AttackWhen::Always};
        const char *wn[] = {"during bootstrap", "after handoff", "always"};
        double honest_med = 0;
        {
            Agg a; std::vector<double> fin;
            for (size_t s = 0; s < SEEDS; ++s) {
                Cfg c; c.N = 30; c.H = ASSUMED_H;
                Chain ch(4242 + s, c);
                for (size_t i = 0; i < NBLOCKS; ++i) ch.mine();
                fin.push_back(ch.b.back().d.convert_to<double>());
            }
            honest_med = pct(fin, .5);
            printf("  honest baseline final difficulty (median of %zu seeds): %.0f\n\n", SEEDS, honest_med);
        }
        for (size_t wi = 0; wi < 3; ++wi) {
            printf("  -- %s\n", wn[wi]);
            for (TsAttack at : atks) {
                if (at == TsAttack::None) continue;
                std::vector<double> fin, mn;
                for (size_t s = 0; s < SEEDS; ++s) {
                    Cfg c; c.N = 30; c.H = ASSUMED_H; c.attack = at; c.when = whens[wi];
                    Chain ch(4242 + s, c);
                    for (size_t i = 0; i < NBLOCKS; ++i) ch.mine();
                    fin.push_back(ch.b.back().d.convert_to<double>());
                    double lo = 1e300;
                    for (size_t i = 31; i < ch.b.size(); ++i)
                        lo = std::min(lo, ch.b[i].d.convert_to<double>());
                    mn.push_back(lo);
                }
                double f = pct(fin, .5), l = pct(mn, .5);
                printf("     %-26s final p50 %10.0f (%+6.1f%% vs honest) | lowest-after-handoff p50 %9.0f (%+6.1f%%)\n",
                       ts_name(at), f, 100.0 * (f - honest_med) / honest_med,
                       l, 100.0 * (l - honest_med) / honest_med);
            }
        }
        printf("\n");
    }

    // ---------------------------------------------------------------- item 11
    if (run("race")) {
        printf("=== ITEM 11: a miner with 100x the expected hashrate racing the bootstrap ===\n");
        Agg a;
        std::vector<double> boot_secs;
        for (size_t s = 0; s < SEEDS; ++s) {
            Cfg c; c.N = 30; c.H = ASSUMED_H * 100.0;
            Chain ch(555000 + s, c);
            for (size_t i = 0; i < NBLOCKS; ++i) ch.mine();
            a.add(measure(ch.b));
            boot_secs.push_back((double)ch.b[30].ts - (double)ch.b[0].ts);
        }
        print_agg("N=30, H=100x", a);
        printf("  wall-clock to clear the 30-block bootstrap: p50 %.0fs  p5 %.0fs  p95 %.0fs\n",
               pct(boot_secs, .5), pct(boot_secs, .05), pct(boot_secs, .95));
        printf("  At 100x, the bootstrap section is mined in well under its intended %zu s x 30.\n",
               TARGET);
        printf("  Those %llu blocks are won at a KNOWN fixed difficulty -- the main cost of the rule.\n\n",
               30ULL);
    }

    printf("=========================================================================\n");
    printf("ANALYSIS ONLY. No consensus code has been changed.\n");
    return 0;
}
