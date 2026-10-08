#!/usr/bin/env python3
"""Add a controlled genesis-age parameter, the genesis-age sweep, the rules-x-genesis matrix, and
the per-height mechanical trace to node/meepcoin_netsim.cpp. ANALYSIS ONLY."""
import io, os, sys

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meepcoin_netsim.cpp")
s = io.open(P, encoding="utf-8").read()
if "GENESIS AGE" in s:
    print("= already applied"); sys.exit(0)

# ---------------------------------------------------------------- launch offset
# The genesis block keeps its timestamp; the chain simply starts mining `launch_offset` seconds
# later. That is exactly what "genesis is N seconds stale at launch" means, and it isolates genesis
# age from every other variable: same code, same rules, same hashrate, same RNG seed, same duration.
s = s.replace("    double T = (double)GENESIS_TS;",
              "    double T = (double)GENESIS_TS;   // advanced by launch_offset in the constructor\n"
              "    double launch_offset = 0;        // GENESIS AGE: seconds between genesis ts and\n"
              "                                     // the first mining attempt", 1)
OLD = """    Sim(uint64_t seed, Rule r, Strat s, Profile p, double H, double alpha, int nhonest,
        ClockCfg c = ClockCfg())
        : rng(seed), rule(r), strat(s), prof(p), clk(c) {"""
NEW = """    Sim(uint64_t seed, Rule r, Strat s, Profile p, double H, double alpha, int nhonest,
        ClockCfg c = ClockCfg(), double launch_off = 0.0)
        : rng(seed), rule(r), strat(s), prof(p), clk(c) {
        launch_offset = launch_off;
        T += launch_off;"""
assert OLD in s
s = s.replace(OLD, NEW, 1)
# node clock sync reference must follow the launch time, not the genesis timestamp
s = s.replace("            n.sync_T = (double)GENESIS_TS;",
              "            n.sync_T = (double)GENESIS_TS + launch_off;", 1)
s = s.replace("            n.next_corr_T = (clk.uses_corr() && !perfect) ? (double)GENESIS_TS + gap : 1e300;",
              "            n.next_corr_T = (clk.uses_corr() && !perfect)\n"
              "                          ? (double)GENESIS_TS + launch_off + gap : 1e300;", 1)

# ---------------------------------------------------------------- thread launch offset through
s = s.replace("""static DiffStats one_diff(uint64_t seed, TsRule ts, Rule rule, Strat st, double alpha,
                          double H, size_t nblocks, int nhonest, ClockCfg c) {
    g_ts_rule = ts;
    Sim s(seed, rule, st, PROFILES[P_LOCAL], H, alpha, nhonest, c);""",
"""static DiffStats one_diff(uint64_t seed, TsRule ts, Rule rule, Strat st, double alpha,
                          double H, size_t nblocks, int nhonest, ClockCfg c,
                          double launch_off = 0.0) {
    g_ts_rule = ts;
    Sim s(seed, rule, st, PROFILES[P_LOCAL], H, alpha, nhonest, c, launch_off);""", 1)
s = s.replace("""static DiffAgg diff_sweep(TsRule ts, Rule rule, Strat st, double alpha, double Hmul,
                          size_t nseeds, size_t nblocks, int nhonest, ClockCfg c) {""",
"""static DiffAgg diff_sweep(TsRule ts, Rule rule, Strat st, double alpha, double Hmul,
                          size_t nseeds, size_t nblocks, int nhonest, ClockCfg c,
                          double launch_off = 0.0) {""", 1)
s = s.replace("""            parts[t].add(one_diff(1300000 + i, ts, rule, st, alpha, 424.0 * Hmul, nblocks,
                                  nhonest, c));""",
"""            parts[t].add(one_diff(1300000 + i, ts, rule, st, alpha, 424.0 * Hmul, nblocks,
                                  nhonest, c, launch_off));""", 1)

# ---------------------------------------------------------------- the sweep + matrix + trace
MODE = r'''
// ================================================================================================
// GENESIS AGE -- controlled sweep, rules x genesis matrix, and the mechanical launch-spike trace
// ================================================================================================
struct AgeCase { const char *name; double secs; };
static const AgeCase AGES[] = {
    {"launch time (fresh)",  0.0},
    {"10 minutes",           600.0},
    {"2 hours",              7200.0},
    {"12 hours",             43200.0},
    {"1 day",                86400.0},
    {"5.3 days (existing)",  458000.0},
};
static const size_t NAGES = sizeof(AGES) / sizeof(AGES[0]);

static void genesis_sweep(size_t NSEED) {
    printf("GENESIS-AGE SWEEP\n\n");
    printf("  %zu deterministic seeds per cell, 800 blocks, localhost profile, 4 honest miners for\n",
           NSEED);
    printf("  the honest rows and 3 honest + 1 attacker for the attack rows.\n");
    printf("  ONLY the genesis age differs between rows of a block: identical code, rules, hashrate,\n");
    printf("  RNG seeds and duration. The genesis block keeps its timestamp; mining simply starts\n");
    printf("  `age` seconds later, which is what a stale genesis means.\n\n");
    ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;

    printf("=== A. HONEST LAUNCH, 1x hashrate ===\n\n");
    for (TsRule tr : {TsRule::Upstream, TsRule::T1T2}) {
        dhdr();
        for (size_t i = 0; i < NAGES; ++i) {
            char lbl[128]; snprintf(lbl, sizeof(lbl), "%s | genesis %s", ts_rule_name(tr), AGES[i].name);
            drow(lbl, diff_sweep(tr, Rule::Control, Strat::Honest, 0.0, 1.0, NSEED, 800, 4, C,
                                 AGES[i].secs));
        }
        printf("\n");
    }

    printf("=== B. ADAPTIVE ATTACKER (lowest-legal / maximum-future alternating) ===\n\n");
    for (double alpha : {0.33, 1.00}) {
        for (TsRule tr : {TsRule::Upstream, TsRule::T1T2}) {
            dhdr();
            for (size_t i = 0; i < NAGES; ++i) {
                char lbl[128];
                snprintf(lbl, sizeof(lbl), "%s %.0f%% | genesis %s", ts_rule_name(tr), 100 * alpha,
                         AGES[i].name);
                drow(lbl, diff_sweep(tr, Rule::Control, Strat::Alternating, alpha, 1.0, NSEED, 800,
                                     3, C, AGES[i].secs));
            }
            printf("\n");
        }
    }

    printf("=== C. THE 2x2 MATRIX: rules x genesis age, nothing else varying ===\n\n");
    struct MRow { const char *tag; TsRule tr; double age; };
    MRow rows[] = {
        {"current rules  + stale genesis", TsRule::Upstream, 458000.0},
        {"current rules  + fresh genesis", TsRule::Upstream, 0.0},
        {"T1+T2(+T4)     + stale genesis", TsRule::T1T2,     458000.0},
        {"T1+T2(+T4)     + fresh genesis", TsRule::T1T2,     0.0},
    };
    printf("  -- honest launch, 1x --\n");
    dhdr();
    for (auto &r : rows)
        drow(r.tag, diff_sweep(r.tr, Rule::Control, Strat::Honest, 0.0, 1.0, NSEED, 800, 4, C, r.age));
    printf("\n  -- 33%% adaptive attacker --\n");
    dhdr();
    for (auto &r : rows)
        drow(r.tag, diff_sweep(r.tr, Rule::Control, Strat::Alternating, 0.33, 1.0, NSEED, 800, 3, C,
                               r.age));
    printf("\n  -- 100%% adaptive attacker (upper bound) --\n");
    dhdr();
    for (auto &r : rows)
        drow(r.tag, diff_sweep(r.tr, Rule::Control, Strat::Alternating, 1.00, 1.0, NSEED, 800, 3, C,
                               r.age));
    printf("\n");
}

// ---- mechanical per-height trace of the honest launch spike -------------------------------------
static void spike_trace(TsRule tr, double age, uint64_t seed, const char *label) {
    g_ts_rule = tr;
    ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;
    Sim s(seed, Rule::Control, Strat::Honest, PROFILES[P_LOCAL], 424.0, 0.0, 4, C, age);
    s.run(120, false);
    int wt = s.winning_tip();
    std::vector<int> path = s.w.path_to(wt);
    printf("  --- %s (seed %llu, genesis age %.0f s) ---\n", label, (unsigned long long)seed, age);
    printf("  %5s %12s %9s %6s %6s %7s %7s %11s %13s %12s %12s\n",
           "h", "timestamp", "interval", "n_win", "n_eq", "cut_b", "cut_e", "span_cut",
           "cumwork_rng", "raw_next", "accepted");
    for (size_t i = 1; i < path.size() && i <= 20; ++i) {
        const Block &b = s.w.blocks[path[i]];
        std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
        s.w.chain_back(b.parent, BLOCKS_COUNT, ts, cd);
        if (ts.size() > WINDOW) { ts.resize(WINDOW); cd.resize(WINDOW); }
        size_t n = ts.size();
        size_t cb = 0, ce = n; uint64_t span = 0; double work = 0, raw = 0;
        size_t n_eq = 0;
        if (n >= 2) {
            std::vector<uint64_t> sorted = ts; std::sort(sorted.begin(), sorted.end());
            Cut c = cut_of(n); cb = c.begin; ce = c.end;
            span = sorted[ce - 1] - sorted[cb];
            work = (cd[ce - 1] - cd[cb]).convert_to<double>();
            raw = cryptonote::next_difficulty(ts, cd, TARGET).convert_to<double>();
            for (size_t k = 1; k < sorted.size(); ++k) if (sorted[k] == sorted[k - 1]) ++n_eq;
        }
        double iv = (i >= 2) ? (b.found_T - s.w.blocks[path[i - 1]].found_T) : 0.0;
        printf("  %5llu %12llu %9.3f %6zu %6zu %7zu %7zu %11llu %13.0f %12.0f %12.0f\n",
               (unsigned long long)b.height, (unsigned long long)b.ts, iv, n, n_eq, cb, ce,
               (unsigned long long)span, work, raw, b.d.convert_to<double>());
    }
    double peak = 0;
    for (size_t i = 1; i < path.size(); ++i)
        peak = std::max(peak, s.w.blocks[path[i]].d.convert_to<double>());
    printf("  peak difficulty over 120 blocks: %.0f\n\n", peak);
}

static void spikeexplain() {
    printf("MECHANICAL EXPLANATION OF THE HONEST LAUNCH SPIKE\n\n");
    printf("  n_win  = window size fed to next_difficulty after the lag truncation\n");
    printf("  n_eq   = adjacent EQUAL timestamps in the sorted window (same-second blocks)\n");
    printf("  span_cut = sorted[cut_end-1] - sorted[cut_begin], the divisor the formula uses\n\n");
    // worst and median seeds are chosen by peak difficulty over a small scan, so the two traces
    // are genuinely the extremes of the same distribution rather than arbitrary picks
    for (TsRule tr : {TsRule::Upstream, TsRule::T1T2}) {
        for (double age : {0.0, 458000.0}) {
            g_ts_rule = tr;
            ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;
            std::vector<std::pair<double, uint64_t>> peaks;
            for (uint64_t sd = 0; sd < 60; ++sd) {
                Sim s(4000000 + sd, Rule::Control, Strat::Honest, PROFILES[P_LOCAL], 424.0, 0.0, 4,
                      C, age);
                s.run(120, false);
                double pk = 0;
                for (int b : s.w.path_to(s.winning_tip()))
                    pk = std::max(pk, s.w.blocks[b].d.convert_to<double>());
                peaks.push_back({pk, 4000000 + sd});
            }
            std::sort(peaks.begin(), peaks.end());
            char lw[96], lm[96];
            snprintf(lw, sizeof(lw), "%s, genesis %s, WORST of 60 seeds",
                     ts_rule_name(tr), age == 0 ? "fresh" : "5.3 days stale");
            snprintf(lm, sizeof(lm), "%s, genesis %s, MEDIAN of 60 seeds",
                     ts_rule_name(tr), age == 0 ? "fresh" : "5.3 days stale");
            spike_trace(tr, age, peaks.back().second, lw);
            spike_trace(tr, age, peaks[peaks.size() / 2].second, lm);
        }
    }
    g_ts_rule = TsRule::Upstream;
}
'''
s = s.replace("// ================================================================================================\nint main(int argc, char **argv) {",
              MODE + "\n// ================================================================================================\nint main(int argc, char **argv) {", 1)
s = s.replace('    if (mode == "spancompare") { spancompare(nseed); return 0; }',
              '    if (mode == "spancompare") { spancompare(nseed); return 0; }\n'
              '    if (mode == "genesisage") { genesis_sweep(nseed); return 0; }\n'
              '    if (mode == "spikeexplain") { spikeexplain(); return 0; }', 1)
io.open(P, "w", encoding="utf-8", newline="\n").write(s)
print("added genesis-age sweep, rules x genesis matrix, and the spike trace")
