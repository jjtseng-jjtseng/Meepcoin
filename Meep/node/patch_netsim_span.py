#!/usr/bin/env python3
"""Add span-limiting difficulty candidates S1/S2 and the chain-relative timestamp bound S4 to
node/meepcoin_netsim.cpp. ANALYSIS ONLY -- the simulator, not consensus code."""
import io, os, sys

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meepcoin_netsim.cpp")
s = io.open(P, encoding="utf-8").read()
if "MEEPCOIN SPAN CANDIDATES" in s:
    print("= already applied"); sys.exit(0)

# ---------------------------------------------------------------- 1. rule enums and knobs
OLD = "enum class Rule { Control, A, B, C };"
NEW = r'''// ---- MEEPCOIN SPAN CANDIDATES ------------------------------------------------------------------
// Control  the unmodified rule
// A        2x upward cap, heights 1..BOOT_N                 (negative control only -- rejected)
// B        5 s per included interval aggregate span FLOOR
// C        B then A
// S1       aggregate span CEILING: span_eff = min(span_raw, S1_MULT * TARGET * intervals)
//          Difficulty is decreasing in the span, so a ceiling RAISES difficulty. This is the direct
//          answer to a pin caused by an inflated span.
// S2       bounded downward step: d_next >= d_prev / S2_DIV
enum class Rule { Control, A, B, C, S1, S2, S1S2 };
static const char *rule_short(Rule r) {
    switch (r) { case Rule::Control: return "control"; case Rule::A: return "A"; case Rule::B: return "B";
                 case Rule::C: return "A+B"; case Rule::S1: return "S1"; case Rule::S2: return "S2";
                 case Rule::S1S2: return "S1+S2"; }
    return "?";
}
static double  S1_MULT = 3.0;        // span ceiling multiplier
static uint64_t S2_DIV = 2;          // maximum downward step per block
static uint64_t SPAN_ACTIVE_UNTIL = 30;   // heights 1..this; set large to keep the rule active'''
assert OLD in s
s = s.replace(OLD, NEW, 1)

# ---------------------------------------------------------------- 2. timestamp rule: add S4
OLD = "enum class TsRule { Upstream, T1T2, T3b };"
NEW = r'''// S4 is a TIMESTAMP rule, not a difficulty rule: in addition to the local-clock future-time limit,
// a block's timestamp may not exceed the window median by more than S4_SLACK seconds. That bounds
// the aggregate span from above using only chain data, which is what a local-clock limit cannot do.
// It is only viable when the genesis timestamp is close to the real launch time -- with a stale
// genesis the median starts far in the past and honest blocks would be rejected. Measured, not
// assumed: see the genesis-age sweep.
enum class TsRule { Upstream, T1T2, T3b, T1T2_S4 };
static int64_t S4_SLACK = 7200;'''
assert OLD in s
s = s.replace(OLD, NEW, 1)
s = s.replace('''    switch (r) { case TsRule::Upstream: return "upstream";
                 case TsRule::T1T2: return "T1+T2";
                 case TsRule::T3b: return "T3b-monotonic"; }''',
'''    switch (r) { case TsRule::Upstream: return "upstream";
                 case TsRule::T1T2: return "T1+T2";
                 case TsRule::T3b: return "T3b-monotonic";
                 case TsRule::T1T2_S4: return "T1+T2+S4"; }''', 1)
s = s.replace("if (h < TS_WINDOW && g_ts_rule != TsRule::T1T2)",
              "if (h < TS_WINDOW && g_ts_rule != TsRule::T1T2 && g_ts_rule != TsRule::T1T2_S4)", 1)

# ---------------------------------------------------------------- 3. diff_impl gains span modes
OLD = '''static difficulty_type diff_impl(std::vector<uint64_t> ts, std::vector<difficulty_type> cd,
                                 bool span_floor) {'''
NEW = '''// span_mode: 0 none, 1 candidate B floor, 2 candidate S1 ceiling, 3 both
static difficulty_type diff_impl(std::vector<uint64_t> ts, std::vector<difficulty_type> cd,
                                 int span_mode) {'''
assert OLD in s
s = s.replace(OLD, NEW, 1)
OLD = '''    if (n <= 1) return 1;
    if (!span_floor) return cryptonote::next_difficulty(ts, cd, TARGET);
    std::vector<uint64_t> s = ts;
    std::sort(s.begin(), s.end());
    Cut c = cut_of(n);
    uint64_t span = s[c.end - 1] - s[c.begin];
    if (span == 0) span = 1;
    uint64_t iv = (uint64_t)(c.end - c.begin) - 1;
    span = std::max(span, SPAN_PER_INTERVAL * iv);'''
NEW = '''    if (n <= 1) return 1;
    if (span_mode == 0) return cryptonote::next_difficulty(ts, cd, TARGET);
    std::vector<uint64_t> s = ts;
    std::sort(s.begin(), s.end());
    Cut c = cut_of(n);
    uint64_t span = s[c.end - 1] - s[c.begin];
    if (span == 0) span = 1;
    uint64_t iv = (uint64_t)(c.end - c.begin) - 1;
    if (span_mode & 1) span = std::max(span, SPAN_PER_INTERVAL * iv);          // B: floor
    if (span_mode & 2) {                                                       // S1: ceiling
        uint64_t cap = (uint64_t)(S1_MULT * (double)TARGET * (double)std::max<uint64_t>(iv, 1));
        if (cap < 1) cap = 1;
        span = std::min(span, cap);
    }
    if (span == 0) span = 1;'''
assert OLD in s
s = s.replace(OLD, NEW, 1)

# ---------------------------------------------------------------- 4. diff_for honours new rules
OLD = '''        bool boot = boot_active(nh);
        difficulty_type d = 1;
        if (ts.size() >= 2) {
            d = diff_impl(ts, cd, (rule == Rule::B || rule == Rule::C) && boot);
            if (d == 0) d = 1;
            if ((rule == Rule::A || rule == Rule::C) && boot) {
                difficulty_type lim = w.blocks[tip].d * 2;
                if (d > lim) d = lim;
                if (d == 0) d = 1;
            }
        }'''
NEW = '''        bool boot = nh >= 1 && nh <= SPAN_ACTIVE_UNTIL;
        difficulty_type d = 1;
        if (ts.size() >= 2) {
            int mode = 0;
            if ((rule == Rule::B || rule == Rule::C || rule == Rule::S1S2) && boot) mode |= 1;
            if ((rule == Rule::S1 || rule == Rule::S1S2) && boot) mode |= 2;
            d = diff_impl(ts, cd, mode);
            if (d == 0) d = 1;
            if ((rule == Rule::A || rule == Rule::C) && boot) {
                difficulty_type lim = w.blocks[tip].d * 2;              // negative control only
                if (d > lim) d = lim;
                if (d == 0) d = 1;
            }
            if ((rule == Rule::S2 || rule == Rule::S1S2) && boot) {
                difficulty_type floor_d = w.blocks[tip].d / S2_DIV;     // bounded downward step
                if (floor_d == 0) floor_d = 1;
                if (d < floor_d) d = floor_d;
            }
        }'''
assert OLD in s
s = s.replace(OLD, NEW, 1)

# ---------------------------------------------------------------- 5. S4 upper bound in validate()
OLD = '''        if (mb.applies && b.ts < mb.value) return "timestamp below median lower bound";'''
NEW = '''        if (mb.applies && b.ts < mb.value) return "timestamp below median lower bound";
        // S4: chain-relative future bound. Uses only chain data, so every node agrees regardless of
        // its own clock -- unlike the FTL, which is local-clock relative.
        if (g_ts_rule == TsRule::T1T2_S4 && mb.applies &&
            (int64_t)b.ts > (int64_t)mb.value + S4_SLACK)
            return "timestamp above median + S4 slack";'''
assert OLD in s
s = s.replace(OLD, NEW, 1)

# the attacker must also respect S4 when choosing its maximum, otherwise it just gets rejected
OLD = '''    const int64_t hi = (int64_t)v.own_clock + v.ftl;         // highest value legal by its own clock'''
NEW = '''    int64_t hi = (int64_t)v.own_clock + v.ftl;               // highest value legal by its own clock
    if (v.s4_cap > 0 && hi > v.s4_cap) hi = v.s4_cap;        // and by the chain-relative bound'''
assert OLD in s
s = s.replace(OLD, NEW, 1)
s = s.replace('''    int64_t  ftl;            // public consensus constant
};''',
'''    int64_t  ftl;            // public consensus constant
    int64_t  s4_cap;         // chain-relative upper bound, or 0 when the rule is inactive
};''', 1)
s = s.replace('''        v.ftl = FTL;
        return v;''',
'''        v.ftl = FTL;
        v.s4_cap = (g_ts_rule == TsRule::T1T2_S4 && mb.applies)
                 ? (int64_t)mb.value + S4_SLACK : 0;
        return v;''', 1)

io.open(P, "w", encoding="utf-8", newline="\n").write(s)
print("applied span candidates S1/S2/S1S2 and timestamp candidate S4")
