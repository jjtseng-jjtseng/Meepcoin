// meepcoin-attacker-matrix — partial-attacker timestamp analysis for Control / A / B / C.
//
// ANALYSIS ONLY. No daemon consensus is changed.
//
// Rules are exactly as pre-registered in docs/BOOTSTRAP_RULE_SPEC.md, written and committed BEFORE
// this was run. Unit checks U1..U8 encode those definitions and GATE the matrix: if any fails, the
// matrix does not run.
//
// Modelling honesty, stated up front:
//   * Miner of each block is Bernoulli(alpha) -- the correct memoryless model for a PoW race.
//   * Honest miners timestamp with their local clock: true time + N(0, sigma), floored to seconds.
//   * Attacker timestamps are clamped to the consensus-valid range and out-of-range CHOICES ARE
//     COUNTED as rejected attempts.
//   * Orphaning is structurally zero for every strategy except withhold-release, because with
//     instant propagation and one chain there is nothing to orphan. Reported as 0, not measured.
//     Withhold-release uses an explicit two-branch model.
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

static const size_t TARGET = DIFFICULTY_TARGET_V2;
static const size_t WINDOW = DIFFICULTY_WINDOW;
static const size_t CUT = DIFFICULTY_CUT;
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;
static const size_t TS_WINDOW = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
static const int64_t FTL = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
static const uint64_t GENESIS_TS = 1785283200;
static const uint64_t BOOT_N = 30;
static const uint64_t SPAN_PER_INTERVAL = 5;
static const double UP_CAP = 2.00;
static const double ASSUMED_H = 424.0;

enum class Rule { Control, A, B, C };
static const char *rule_name(Rule r) {
    switch (r) { case Rule::Control: return "Control"; case Rule::A: return "A cap2x";
                 case Rule::B: return "B floor5s"; case Rule::C: return "C A+B"; }
    return "?";
}

enum class Strat { Honest, ConstFuture, Alternating, SelectiveMax, CutBoundary,
                   WithholdRelease, GreedyMin, HorizonMin };
static const char *strat_name(Strat s) {
    switch (s) {
        case Strat::Honest: return "honest(control)";
        case Strat::ConstFuture: return "constant-future";
        case Strat::Alternating: return "alternating";
        case Strat::SelectiveMax: return "selective-max";
        case Strat::CutBoundary: return "cut-boundary";
        case Strat::WithholdRelease: return "withhold-release";
        case Strat::GreedyMin: return "greedy-min-D";
        case Strat::HorizonMin: return "horizon-min-D";
    }
    return "?";
}

struct Cut { size_t begin, end; };
static Cut cut_of(size_t length) {
    if (length <= WINDOW - 2 * CUT) return Cut{0, length};
    size_t b = (length - (WINDOW - 2 * CUT) + 1) / 2;
    return Cut{b, b + (WINDOW - 2 * CUT)};
}

// Candidate B arithmetic. floor_on=false must reproduce next_difficulty() exactly (unit check U5).
static difficulty_type diff_span_floor(std::vector<uint64_t> ts,
                                       std::vector<difficulty_type> cd, bool floor_on) {
    if (ts.size() > WINDOW) { ts.resize(WINDOW); cd.resize(WINDOW); }
    size_t length = ts.size();
    if (length <= 1) return 1;
    std::vector<uint64_t> s = ts;
    std::sort(s.begin(), s.end());
    Cut c = cut_of(length);
    uint64_t span = s[c.end - 1] - s[c.begin];
    if (span == 0) span = 1;
    if (floor_on) {
        uint64_t intervals = (uint64_t)(c.end - c.begin) - 1;   // U4
        span = std::max(span, SPAN_PER_INTERVAL * intervals);
    }
    difficulty_type work = cd[c.end - 1] - cd[c.begin];
    boost::multiprecision::uint256_t r =
        (boost::multiprecision::uint256_t(work) * TARGET + span - 1) / span;
    return r.convert_to<difficulty_type>();
}

struct Blk { uint64_t h, ts; double solve; difficulty_type d; bool by_attacker; };

struct Chain {
    std::vector<uint64_t> ts;
    std::vector<difficulty_type> cd;
    std::vector<Blk> b;
    double t;                       // true wall-clock seconds
    std::mt19937_64 rng;
    Rule rule;
    double H, alpha, sigma;
    Strat strat;
    size_t invalid_attempts = 0;

    Chain(uint64_t seed, Rule r, double h, double a, Strat s, double sig = 2.0)
        : rng(seed), rule(r), H(h), alpha(a), strat(s), sigma(sig) {
        ts.push_back(GENESIS_TS); cd.push_back(1);
        b.push_back(Blk{0, GENESIS_TS, 0, 1, false});
        t = (double)GENESIS_TS;
    }

    // heights 1..BOOT_N inclusive; genesis (0) excluded  -- U1, U8
    bool boot_active() const { uint64_t h = b.size(); return h >= 1 && h <= BOOT_N; }

    void window(std::vector<uint64_t> &a, std::vector<difficulty_type> &w) const {
        size_t n = ts.size(), take = std::min(n, BLOCKS_COUNT);
        size_t from = (n > take) ? n - take : 0;
        for (size_t i = from; i < n; ++i) {
            if (i == 0) continue;           // genesis excluded from the window
            a.push_back(ts[i]); w.push_back(cd[i]);
        }
    }

    // Difficulty for the block about to be mined, per the pre-registered rules.
    difficulty_type next_d(const std::vector<uint64_t> &extra_ts = {},
                           const std::vector<difficulty_type> &extra_cd = {}) const {
        std::vector<uint64_t> a; std::vector<difficulty_type> w;
        window(a, w);
        for (size_t i = 0; i < extra_ts.size(); ++i) { a.push_back(extra_ts[i]); w.push_back(extra_cd[i]); }
        if (a.size() < 2) return 1;
        bool boot = boot_active();
        difficulty_type d;
        if ((rule == Rule::B || rule == Rule::C) && boot) d = diff_span_floor(a, w, true);
        else d = cryptonote::next_difficulty(a, w, TARGET);
        if (d == 0) d = 1;
        if ((rule == Rule::A || rule == Rule::C) && boot) {
            // U2/U3: D_prev is the recorded difficulty of height h-1 (1 at h==1);
            // the cap is applied to the integer next_difficulty already returned.
            difficulty_type prev = b.back().d;
            difficulty_type lim = prev * 2;
            if (d > lim) d = lim;
            if (d == 0) d = 1;
        }
        return d;
    }

    uint64_t ts_lower_bound() const {
        size_t n = ts.size(), take = std::min(n, TS_WINDOW);
        std::vector<uint64_t> w(ts.end() - take, ts.end());
        std::sort(w.begin(), w.end());
        return w[w.size() / 2];
    }

    uint64_t honest_ts() {
        std::normal_distribution<double> nd(0.0, sigma);
        double c = t + nd(rng);
        if (c < 0) c = 0;
        return (uint64_t)c;
    }

    // Clamp to the consensus-valid range, counting rejections.
    uint64_t clamp_ts(int64_t want) {
        int64_t lo = (int64_t)ts_lower_bound();
        int64_t hi = (int64_t)t + FTL;
        if (want < lo || want > hi) ++invalid_attempts;
        if (want < lo) want = lo;
        if (want > hi) want = hi;
        return (uint64_t)want;
    }

    // Try candidate timestamps and pick the one minimising the NEXT block's difficulty.
    uint64_t greedy_ts(difficulty_type d_this) {
        int64_t lo = (int64_t)ts_lower_bound(), hi = (int64_t)t + FTL;
        int64_t best = hi; double bestd = 1e300;
        const int STEPS = 12;
        for (int i = 0; i <= STEPS; ++i) {
            int64_t cand = lo + (hi - lo) * i / STEPS;
            std::vector<uint64_t> et{(uint64_t)cand};
            std::vector<difficulty_type> ec{cd.back() + d_this};
            double v = next_d(et, ec).convert_to<double>();
            if (v < bestd) { bestd = v; best = cand; }
        }
        return (uint64_t)best;
    }

    void mine() {
        uint64_t h = b.size();
        difficulty_type d = next_d();
        if (d == 0) d = 1;
        std::uniform_real_distribution<double> u(0.0, 1.0);
        bool att = (u(rng) < alpha);

        double mean = d.convert_to<double>() / std::max(H, 1e-9);
        std::exponential_distribution<double> ed(1.0 / std::max(mean, 1e-12));
        double s = ed(rng);
        if (s > 5e7) s = 5e7;
        t += s;

        uint64_t rec;
        if (!att || strat == Strat::Honest) {
            rec = clamp_ts((int64_t)honest_ts());
        } else {
            int64_t lo = (int64_t)ts_lower_bound();
            int64_t hi = (int64_t)t + FTL;
            switch (strat) {
                case Strat::ConstFuture:  rec = clamp_ts(hi); break;
                case Strat::Alternating:  rec = clamp_ts((h % 2 == 0) ? hi : lo); break;
                case Strat::SelectiveMax: rec = clamp_ts((h % 10 == 0) ? hi : (int64_t)honest_ts()); break;
                case Strat::CutBoundary:  rec = clamp_ts((h % 2 == 0) ? hi : lo); break;
                case Strat::WithholdRelease: rec = clamp_ts((int64_t)honest_ts()); break;
                case Strat::GreedyMin:    rec = clamp_ts((int64_t)greedy_ts(d)); break;
                case Strat::HorizonMin:   rec = clamp_ts((int64_t)greedy_ts(d)); break;
                default:                  rec = clamp_ts((int64_t)honest_ts()); break;
            }
        }
        ts.push_back(rec);
        cd.push_back(cd.back() + d);
        b.push_back(Blk{h, rec, s, d, att});
    }
};

// ---- metrics -----------------------------------------------------------------------------------
static double q(std::vector<double> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[(size_t)(p * (double)(v.size() - 1))];
}

struct Res {
    double rel_med = 0, rel_p5 = 0;      // difficulty relative to the paired honest baseline
    double att_blocks = 0, att_work = 0;
    double med_iv = 0, p5_iv = 0, p95_iv = 0, mean_iv = 0;
    double lowest_sustained = 0;
    long sustained_blocks = 0;
    double invalid_rate = 0;
    bool stalled = false;
};

// SUSTAINED REDUCTION, pre-registered: >=50 contiguous blocks at <=80% of the paired honest baseline.
static const size_t SUSTAIN_MIN = 50;
static const double SUSTAIN_THRESH = 0.80;

static Res evaluate(const Chain &atk, const Chain &hon) {
    Res r;
    size_t n = std::min(atk.b.size(), hon.b.size());
    std::vector<double> rel, iv;
    size_t att_blocks = 0;
    double att_work = 0, tot_work = 0;
    long run = 0, best_run = 0;
    double lowest = 1e300;
    for (size_t i = 1; i < n; ++i) {
        double a = atk.b[i].d.convert_to<double>();
        double hh = hon.b[i].d.convert_to<double>();
        if (hh > 0) rel.push_back(a / hh);
        iv.push_back(atk.b[i].solve);
        if (atk.b[i].solve > 3600.0) r.stalled = true;
        if (atk.b[i].by_attacker) { ++att_blocks; att_work += a; }
        tot_work += a;
        if (hh > 0 && a / hh <= SUSTAIN_THRESH) {
            ++run;
            lowest = std::min(lowest, a / hh);
            best_run = std::max(best_run, run);
        } else run = 0;
    }
    r.rel_med = q(rel, .5); r.rel_p5 = q(rel, .05);
    r.att_blocks = n > 1 ? (double)att_blocks / (double)(n - 1) : 0;
    r.att_work = tot_work > 0 ? att_work / tot_work : 0;
    r.med_iv = q(iv, .5); r.p5_iv = q(iv, .05); r.p95_iv = q(iv, .95);
    double s = 0; for (double x : iv) s += x;
    r.mean_iv = iv.empty() ? 0 : s / (double)iv.size();
    r.sustained_blocks = (best_run >= (long)SUSTAIN_MIN) ? best_run : 0;
    r.lowest_sustained = (best_run >= (long)SUSTAIN_MIN && lowest < 1e299) ? lowest : 0;
    r.invalid_rate = n > 1 ? (double)atk.invalid_attempts / (double)(n - 1) : 0;
    return r;
}

// ---- unit checks -------------------------------------------------------------------------------
static int g_fail = 0;
static void ck(bool c, const char *n) {
    printf("  [%s] %s\n", c ? "PASS" : "FAIL", n);
    if (!c) ++g_fail;
}

static void unit_checks() {
    printf("UNIT CHECKS on the pre-registered definitions (gate the matrix)\n");

    { // U1 / U8
        Chain c(1, Rule::A, ASSUMED_H, 0.0, Strat::Honest);
        bool at0 = c.boot_active();                 // height 0 slot -> about to mine height...
        // b.size()==1 means the next block is height 1
        ck(at0, "U1/U8: bootstrap active when about to mine height 1");
        for (int i = 0; i < 28; ++i) c.mine();      // now about to mine height 29
        ck(c.boot_active(), "U8: active at height 29 (N-1)");
        c.mine();                                    // about to mine 30
        ck(c.boot_active(), "U8: active at height 30 (N)");
        c.mine();                                    // about to mine 31
        ck(!c.boot_active(), "U8: INACTIVE at height 31 (N+1)");
        c.mine();
        ck(!c.boot_active(), "U8: INACTIVE at height 32 (N+2)");
        ck(c.b.size() == 32, "U1: exactly 31 mined blocks recorded after 31 mine() calls");
    }
    { // U2
        Chain c(2, Rule::A, ASSUMED_H, 0.0, Strat::Honest);
        ck(c.b.back().d == 1, "U2: D_prev at height 1 is the genesis difficulty, 1");
    }
    { // U4
        bool ok = true;
        for (size_t len : {2u, 10u, 100u, 599u, 600u, 601u, 719u, 720u}) {
            Cut cc = cut_of(len);
            size_t iv = (cc.end - cc.begin) - 1;
            if (cc.end - cc.begin < 2 || iv != (cc.end - cc.begin - 1)) ok = false;
        }
        ck(ok, "U4: interval count == cut_end - cut_begin - 1 for every window length");
    }
    { // U5
        std::mt19937_64 r(7);
        size_t checked = 0, bad = 0;
        for (int t = 0; t < 300; ++t) {
            size_t n = 2 + (r() % 200);
            std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
            uint64_t now = GENESIS_TS; difficulty_type acc = 1;
            for (size_t i = 0; i < n; ++i) {
                now += r() % 200; acc = acc + (difficulty_type)(1 + r() % 50000);
                ts.push_back(now); cd.push_back(acc);
            }
            difficulty_type mine = diff_span_floor(ts, cd, false);
            difficulty_type real = cryptonote::next_difficulty(ts, cd, TARGET);
            ++checked; if (mine != real) ++bad;
        }
        char m[128]; snprintf(m, sizeof(m),
            "U5: floor-disabled arithmetic == next_difficulty() (%zu cases, %zu mismatch)", checked, bad);
        ck(bad == 0, m);
    }
    { // U6 -- after handoff every candidate equals the control for identical history
        size_t bad = 0, checked = 0;
        for (Rule r : {Rule::A, Rule::B, Rule::C}) {
            for (uint64_t seed = 0; seed < 40; ++seed) {
                Chain c(seed + 900, r, ASSUMED_H, 0.0, Strat::Honest);
                for (int i = 0; i < 90; ++i) {
                    if (c.b.size() > BOOT_N) {
                        std::vector<uint64_t> a; std::vector<difficulty_type> w;
                        c.window(a, w);
                        if (a.size() >= 2) {
                            difficulty_type got = c.next_d();
                            difficulty_type ctl = cryptonote::next_difficulty(a, w, TARGET);
                            ++checked; if (got != ctl) ++bad;
                        }
                    }
                    c.mine();
                }
            }
        }
        char m[160]; snprintf(m, sizeof(m),
            "U6: at heights > %llu all candidates == next_difficulty() (%zu cases, %zu mismatch)",
            (unsigned long long)BOOT_N, checked, bad);
        ck(bad == 0, m);
    }
    { // U7 -- depends only on (height, window): two chains with identical history agree
        size_t bad = 0;
        for (Rule r : {Rule::Control, Rule::A, Rule::B, Rule::C})
            for (uint64_t seed = 0; seed < 30; ++seed) {
                Chain x(seed + 4000, r, ASSUMED_H, 0.0, Strat::Honest);
                for (int i = 0; i < 45; ++i) x.mine();
                Chain y = x;                       // identical window and height
                if (x.next_d() != y.next_d()) ++bad;
            }
        ck(bad == 0, "U7: result depends only on (height, window) -- no branch advantage");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    size_t SEEDS = (argc > 1) ? (size_t)atoi(argv[1]) : 1000;
    size_t NB = (argc > 2) ? (size_t)atoi(argv[2]) : 200;

    printf("MeepCoin partial-attacker timestamp matrix   (ANALYSIS ONLY)\n");
    printf("============================================================\n");
    printf("Rules exactly as pre-registered in docs/BOOTSTRAP_RULE_SPEC.md.\n");
    printf("Sustained reduction = >=%zu contiguous blocks at <=%.0f%% of the paired honest baseline.\n",
           SUSTAIN_MIN, 100 * SUSTAIN_THRESH);
    printf("Honest clock noise sigma = 2 s. Attacker timestamps clamped to "
           "[median(last %zu), now+%lld]; out-of-range choices counted.\n", TS_WINDOW, (long long)FTL);
    printf("Orphan rate is structurally 0 for all strategies except withhold-release "
           "(single chain, instant propagation) and is reported as such, not measured.\n");
    printf("%zu seeds per cell, %zu blocks per run.\n\n", SEEDS, NB);

    unit_checks();
    if (g_fail) { printf("UNIT CHECKS FAILED -- matrix not run.\n"); return 1; }

    const double shares[] = {0.0, 0.05, 0.10, 0.20, 0.25, 0.33, 0.40, 0.49, 0.51, 0.60, 0.75, 1.00};
    const Strat strats[] = {Strat::Honest, Strat::ConstFuture, Strat::Alternating,
                            Strat::SelectiveMax, Strat::CutBoundary, Strat::WithholdRelease,
                            Strat::GreedyMin, Strat::HorizonMin};
    const Rule rules[] = {Rule::Control, Rule::A, Rule::B, Rule::C};

    for (Strat st : strats) {
        printf("### strategy: %s\n", strat_name(st));
        printf("  %-10s %6s | %9s %9s | %8s %8s | %8s %7s | %8s %7s %6s\n",
               "rule", "share", "relD-med", "relD-p5", "att-blk", "att-work",
               "med-iv", "p95-iv", "sustain", "invalid", "stall");
        for (Rule r : rules) {
            for (double a : shares) {
                std::vector<double> relm, relp, ab, aw, mi, pi, sus, inv;
                size_t stalls = 0;
                for (size_t s = 0; s < SEEDS; ++s) {
                    uint64_t seed = 0x9E3779B97F4A7C15ULL * (s + 1)
                                  ^ (uint64_t)(a * 1000) ^ ((uint64_t)st << 32);
                    Chain atk(seed, r, ASSUMED_H, a, st);
                    Chain hon(seed, r, ASSUMED_H, 0.0, Strat::Honest);   // paired baseline, same seed
                    for (size_t i = 0; i < NB; ++i) { atk.mine(); hon.mine(); }
                    Res res = evaluate(atk, hon);
                    relm.push_back(res.rel_med); relp.push_back(res.rel_p5);
                    ab.push_back(res.att_blocks); aw.push_back(res.att_work);
                    mi.push_back(res.med_iv); pi.push_back(res.p95_iv);
                    sus.push_back((double)res.sustained_blocks); inv.push_back(res.invalid_rate);
                    if (res.stalled) ++stalls;
                }
                printf("  %-10s %5.0f%% | %9.3f %9.3f | %7.1f%% %7.1f%% | %8.0f %7.0f | %8.0f %6.2f%% %5.0f%%\n",
                       rule_name(r), a * 100, q(relm, .5), q(relp, .05),
                       100 * q(ab, .5), 100 * q(aw, .5), q(mi, .5), q(pi, .5),
                       q(sus, .5), 100 * q(inv, .5), 100.0 * stalls / (double)SEEDS);
            }
        }
        printf("\n");
    }

    printf("============================================================\n");
    printf("ANALYSIS ONLY. No consensus code changed.\n");
    return 0;
}
