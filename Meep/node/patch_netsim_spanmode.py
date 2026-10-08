#!/usr/bin/env python3
"""Add the `spancompare` mode and two extra attacker strategies to netsim. ANALYSIS ONLY."""
import io, os, sys

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meepcoin_netsim.cpp")
s = io.open(P, encoding="utf-8").read()
if "spancompare" in s:
    print("= already applied"); sys.exit(0)

s = s.replace("enum class Strat { Honest, ConstFuture, Alternating, SelectiveMax, CutBoundary };",
              "enum class Strat { Honest, ConstFuture, Alternating, SelectiveMax, CutBoundary,\n"
              "                   LowestOnly, MaxOnly };", 1)
s = s.replace('        case Strat::CutBoundary: return "cut-boundary";',
              '        case Strat::CutBoundary: return "cut-boundary";\n'
              '        case Strat::LowestOnly: return "lowest-only";\n'
              '        case Strat::MaxOnly: return "max-future-only";', 1)
s = s.replace('''        case Strat::CutBoundary:
            if (v.height % 2 == 0) { want = hi; *decision = "cut-high"; }
            else                   { want = lo; *decision = "cut-low"; }
            break;''',
'''        case Strat::CutBoundary:
            if (v.height % 2 == 0) { want = hi; *decision = "cut-high"; }
            else                   { want = lo; *decision = "cut-low"; }
            break;
        case Strat::LowestOnly:
            want = lo; *decision = "lowest-only"; break;
        case Strat::MaxOnly:
            want = hi; *decision = "max-only"; break;''', 1)

MODE = r'''
// ================================================================================================
// TASK 5 -- span-limiting candidate comparison
// ================================================================================================
struct Combo2 { const char *name; TsRule ts; Rule rule; double s1; uint64_t s2; uint64_t until; };

static void run_combo(const Combo2 &cb, Strat st, double alpha, double hmul, size_t nseed,
                      int nhonest, ClockCfg C, const char *tag) {
    S1_MULT = cb.s1; S2_DIV = cb.s2; SPAN_ACTIVE_UNTIL = cb.until;
    char lbl[160];
    snprintf(lbl, sizeof(lbl), "%s | %s", cb.name, tag);
    drow(lbl, diff_sweep(cb.ts, cb.rule, st, alpha, hmul, nseed, 800, nhonest, C));
}

static void spancompare(size_t NSEED) {
    printf("TASK 5 -- SPAN-LIMITING CANDIDATE COMPARISON\n\n");
    printf("  %zu deterministic seeds per cell, 800 blocks, localhost profile.\n", NSEED);
    printf("  PINNED SHARE, fixed before running: blocks on the final winning chain (genesis\n");
    printf("  excluded) whose own difficulty is <= %.0f. pin_run is the longest consecutive streak.\n",
           PIN_THRESHOLD);
    printf("  NOTE ON T4: the simulator applies the future-time limit on EVERY receipt, so it has no\n");
    printf("  separate main/alternative path and T1+T2+T4 is indistinguishable from T1+T2 here. T4 is\n");
    printf("  a daemon-level consistency fix and is evaluated live, not in this table.\n\n");
    ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;

    Combo2 combos[] = {
        {"current rules",              TsRule::Upstream, Rule::Control, 3, 2, 30},
        {"T1+T2 (= +T4 here)",         TsRule::T1T2,     Rule::Control, 3, 2, 30},
        {"T1+T2 + B",                  TsRule::T1T2,     Rule::B,       3, 2, 30},
        {"T1+T2 + A  [neg control]",   TsRule::T1T2,     Rule::A,       3, 2, 30},
        {"T1+T2 + S1 x2  h1-30",       TsRule::T1T2,     Rule::S1,      2, 2, 30},
        {"T1+T2 + S1 x3  h1-30",       TsRule::T1T2,     Rule::S1,      3, 2, 30},
        {"T1+T2 + S1 x10 h1-30",       TsRule::T1T2,     Rule::S1,     10, 2, 30},
        {"T1+T2 + S1 x3  ALWAYS",      TsRule::T1T2,     Rule::S1,      3, 2, 1000000},
        {"T1+T2 + S1 x10 ALWAYS",      TsRule::T1T2,     Rule::S1,     10, 2, 1000000},
        {"T1+T2 + S2 /2  h1-30",       TsRule::T1T2,     Rule::S2,      3, 2, 30},
        {"T1+T2 + S2 /2  ALWAYS",      TsRule::T1T2,     Rule::S2,      3, 2, 1000000},
        {"T1+T2 + S4 (chain-relative)",TsRule::T1T2_S4,  Rule::Control, 3, 2, 30},
        {"T1+T2 + S4 + S1 x3 ALWAYS",  TsRule::T1T2_S4,  Rule::S1,      3, 2, 1000000},
        {"T1+T2 + S4 + B",             TsRule::T1T2_S4,  Rule::B,       3, 2, 30},
    };

    printf("=== A. HONEST LAUNCH, 4 honest miners ===\n\n");
    for (double m : {0.001, 0.01, 1.0, 100.0, 1000.0}) {
        dhdr();
        char tag[40]; snprintf(tag, sizeof(tag), "honest %gx", m);
        for (auto &cb : combos) run_combo(cb, Strat::Honest, 0.0, m, NSEED, 4, C, tag);
        printf("\n");
    }

    printf("=== B. ADAPTIVE ATTACKER (alternating lowest / maximum legal) ===\n\n");
    struct AS { const char *tag; double alpha; } shares[] = {
        {"33% adaptive", 0.33}, {"51% adaptive", 0.51}, {"100% adaptive", 1.00} };
    for (auto &sh : shares) {
        dhdr();
        for (auto &cb : combos) run_combo(cb, Strat::Alternating, sh.alpha, 1.0, NSEED, 3, C, sh.tag);
        printf("\n");
    }

    printf("=== C. OTHER LEGAL-EXTREME STRATEGIES, 100%% attacker, 1x ===\n\n");
    struct SS { const char *tag; Strat st; } strats[] = {
        {"lowest-only", Strat::LowestOnly}, {"max-future-only", Strat::MaxOnly},
        {"cut-boundary", Strat::CutBoundary} };
    for (auto &ss : strats) {
        dhdr();
        for (auto &cb : combos) run_combo(cb, ss.st, 1.0, 1.0, NSEED, 3, C, ss.tag);
        printf("\n");
    }

    printf("=== D. CLOCK DISPERSION AND COMPETING BRANCHES (honest, 1x, 4 miners) ===\n\n");
    for (double so : {0.0, 10.0, 30.0}) {
        ClockCfg C2; C2.sigma_offset = so; C2.sigma_noise = 2.0;
        dhdr();
        char tag[48]; snprintf(tag, sizeof(tag), "honest, sigma_offset %.0f s", so);
        for (auto &cb : combos) run_combo(cb, Strat::Honest, 0.0, 1.0, NSEED, 4, C2, tag);
        printf("\n");
    }

    S1_MULT = 3.0; S2_DIV = 2; SPAN_ACTIVE_UNTIL = 30;
    g_ts_rule = TsRule::Upstream;
}
'''
s = s.replace("// ================================================================================================\nint main(int argc, char **argv) {",
              MODE + "\n// ================================================================================================\nint main(int argc, char **argv) {", 1)
s = s.replace('    if (mode == "diffcompare") { diffcompare(nseed); return 0; }',
              '    if (mode == "diffcompare") { diffcompare(nseed); return 0; }\n'
              '    if (mode == "spancompare") { spancompare(nseed); return 0; }', 1)
io.open(P, "w", encoding="utf-8", newline="\n").write(s)
print("added spancompare mode + LowestOnly/MaxOnly strategies")
