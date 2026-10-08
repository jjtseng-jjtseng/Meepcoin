// meepcoin-netsim — discrete-event network model for timestamp-attack analysis, round 3.
//
// ANALYSIS ONLY. No consensus code is changed. No genesis, economics, frozen tag or public
// infrastructure is touched. LOCALHOST / PRIVATE DEVELOPMENT CHAIN, dev/test coins, no value.
//
// ROUND-3 CHANGES, and why each was needed:
//
//  1. CLOCK MODEL SPLIT INTO NAMED COMPONENTS WITH EXPLICIT DRAW LIFETIMES.
//     Round 2 had one "offset" (drawn once per node -- correct) and one "noise" that was redrawn
//     ON EVERY READ. A node that read its own clock twice inside a single block event got two
//     independent values, so a miner could REJECT ITS OWN BLOCK about half the time whenever it
//     placed a timestamp at the future-time boundary. That is not a property of any real node.
//     Noise is now drawn once per (node, clock-read event) and cached.
//
//  2. RNG STREAM ALIGNED ACROSS sigma. Round 2 skipped the offset draw entirely when sigma == 0,
//     so the sigma = 0 run used a DIFFERENT random stream from every sigma > 0 run. The reported
//     non-monotonicity was measured across misaligned streams on a single seed. Offsets are now
//     always drawn and then scaled, so sigma is the only thing that changes.
//
//  3. MEDIAN LOWER BOUND CORRECTED TO THE DAEMON'S ACTUAL RULE, three separate defects:
//       (a) Blockchain::check_block_timestamp returns TRUE, with no median computed at all, when
//           the chain holds fewer than BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW blocks. Round 2 applied
//           the bound from height 1.
//       (b) epee::misc_utils::median of an EVEN-sized vector is (v[n-1]+v[n])/2, not v[n].
//           The window is exactly 60 entries, so the even branch is the one that always runs.
//       (c) handle_alternative_block does NOT have the "fewer than 60 blocks" guard and its
//           window excludes genesis on a short chain, so main and alt chains differ.
//     Confirmed live -- see docs/LIVE_MEDIAN_BOUNDARY.md.
//
//  4. ATTACKER INFORMATION BOUNDARY MADE STRUCTURAL. Timestamp strategies are now free functions
//     over a LocalView struct holding only what the attacker can observe from its own chain tip
//     and its own clock. They cannot see the Sim, the RNG, other nodes, or the future, because
//     they are not passed them.
//
//  5. WINNING-CHAIN METRICS SEPARATED FROM PRODUCED-BLOCK METRICS. Round 2 divided wall clock by
//     the count of all produced blocks. If honest validators reject the attacker's blocks, those
//     blocks are on a branch honest nodes never follow, and that ratio measures a private branch
//     rather than the network's chain. Both are now reported, always.
//
//  6. DIFFICULTY MEMOISED PER TIP so the large seed sweeps are affordable.
//
// WHAT IS MODELLED, SEPARATELY:
//   global monotonic wall clock T; per-node persistent offset; per-node drift; per-read-event
//   noise; NTP-style correction events; PoW solve ~ Exponential(D/H); per-block processing;
//   template refresh; propagation; serial per-node queueing; receiver-side validation against the
//   RECEIVER's clock; competing branches resolved by cumulative work.
//
// REMAINING APPROXIMATIONS, stated rather than buried:
//   honest miners are a small number of aggregate nodes, not thousands; propagation is a
//   per-profile distribution, not a topology; mempool/tx relay/block weight are absent; the
//   attacker is a single node; only the localhost profile is measured, the other five are
//   assumptions.

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <numeric>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/difficulty.h"

using cryptonote::difficulty_type;

static const size_t TARGET = DIFFICULTY_TARGET_V2;
static const size_t WINDOW = DIFFICULTY_WINDOW;
static const size_t CUT = DIFFICULTY_CUT;
static const size_t BLOCKS_COUNT = DIFFICULTY_BLOCKS_COUNT;
static const size_t TS_WINDOW = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;   // 60
static const int64_t FTL = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;       // 7200
static const uint64_t GENESIS_TS = 1785283200;

// ---- network profiles ---------------------------------------------------------------------------
// Provenance is carried per profile and printed wherever a profile is used. Three of the eight are
// measured on this host (docs/LIVE_MEDIAN_BOUNDARY.md); the rest are ASSUMPTIONS and are never
// described otherwise.
//
//   MEASURED, quiet host  : accepted-block submit 20.25 / 21.90 / 24.71 ms (min/median/max, n=40)
//                           template refresh after an accepted parent 1.11 / 1.22 / 1.68 ms
//                           A-accepts -> visible at B, two daemons over P2P: 21.9 / 29.6 / 462.0 ms
//   MEASURED, CPU load    : submit 605.20 ms mean under 14 competing busy threads
//   MEASURED, disk load   : submit 59.79 ms mean under 2 fsync writers
//
// The end-to-end P2P figure is NOT wire propagation: it is A's processing + transfer + B's
// processing + the 1 ms poll. Its minimum, 21.9 ms, is within a millisecond of this model's
// prop(0.5 ms) + proc(25.3 ms) decomposition once the poll floor is allowed for, so the split is
// consistent with the measurement rather than contradicted by it. Wire propagation on loopback is
// below the resolution of the method and stays an assumption.
struct Profile {
    const char *name;
    double prop_mean, prop_sd, proc;
    const char *provenance;
};
static const Profile PROFILES[] = {
    {"ideal-zero-latency",   0.0,    0.0,    0.0,     "analytic control, not a claim"},
    {"localhost",            0.0005, 0.0002, 0.02533, "proc MEASURED; prop assumed sub-ms"},
    {"localhost-cpu-load",   0.0005, 0.0002, 0.60520, "proc MEASURED under CPU load"},
    {"localhost-disk-load",  0.0005, 0.0002, 0.05979, "proc MEASURED under disk load"},
    {"datacenter",           0.002,  0.001,  0.02533, "ASSUMPTION -- never measured"},
    {"regional",             0.040,  0.015,  0.02533, "ASSUMPTION -- never measured"},
    {"global",               0.150,  0.060,  0.02533, "ASSUMPTION -- never measured"},
    {"congested",            0.400,  0.250,  0.120,   "ASSUMPTION -- never measured"},
};
static const size_t NPROF = sizeof(PROFILES) / sizeof(PROFILES[0]);
static const size_t P_IDEAL = 0, P_LOCAL = 1, P_GLOBAL = 6;

// ---- candidate difficulty rules -----------------------------------------------------------------
// ---- MEEPCOIN SPAN CANDIDATES ------------------------------------------------------------------
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
static uint64_t SPAN_ACTIVE_UNTIL = 30;   // heights 1..this; set large to keep the rule active

// ---- timestamp-validation rule under test (task 5) ---------------------------------------------
// TsRule::Upstream  what the daemon does today: no median check at all below 60 blocks.
// TsRule::T1T2      one shared window [max(0,p-59) .. p], genesis included, applied at every
//                   height and on both the main and alternative paths.
// TsRule::T3b       upstream, plus strict monotonicity against the parent. Carried ONLY to
//                   demonstrate its honest-rejection cost, not as a proposal.
// S4 is a TIMESTAMP rule, not a difficulty rule: in addition to the local-clock future-time limit,
// a block's timestamp may not exceed the window median by more than S4_SLACK seconds. That bounds
// the aggregate span from above using only chain data, which is what a local-clock limit cannot do.
// It is only viable when the genesis timestamp is close to the real launch time -- with a stale
// genesis the median starts far in the past and honest blocks would be rejected. Measured, not
// assumed: see the genesis-age sweep.
enum class TsRule { Upstream, T1T2, T3b, T1T2_S4 };
static int64_t S4_SLACK = 7200;
static const char *ts_rule_name(TsRule r) {
    switch (r) { case TsRule::Upstream: return "upstream";
                 case TsRule::T1T2: return "T1+T2";
                 case TsRule::T3b: return "T3b-monotonic";
                 case TsRule::T1T2_S4: return "T1+T2+S4"; }
    return "?";
}
static TsRule g_ts_rule = TsRule::Upstream;
static const uint64_t BOOT_N = 30;
static const uint64_t SPAN_PER_INTERVAL = 5;

// ================================================================================================
// CLOCK MODEL
// ================================================================================================
//  quantity        distribution                      DRAW LIFETIME
//  --------------  --------------------------------  --------------------------------------------
//  offset0_i       N(0,1) * sigma_offset             ONCE per node at construction. NEVER
//                                                    resampled. The unit normal is always drawn
//                                                    so the RNG stream does not shift with sigma.
//  drift_i         N(0,1) * drift_ppm_sd, clamped    ONCE per node at construction.
//                  to +-drift_ppm_max
//  noise_i(e)      N(0,1) * sigma_noise              ONCE per (node, clock-read EVENT). One event
//                                                    is one block production, or one arrival being
//                                                    validated at one node. Two reads inside the
//                                                    same event return the SAME value. Different
//                                                    nodes and different events are independent.
//  corr_gap_i(k)   Exp(mean = corr_period)           ONCE per correction event.
//  corr_resid_i(k) N(0,1) * corr_resid_sd            ONCE per correction event; becomes the node's
//                                                    new persistent offset and resets drift accrual.
//
//  local_clock_i(T, e) = T + offset_eff_i + drift_i*1e-6*(T - sync_T_i) + noise_i(e)
// ================================================================================================
enum class ClockMode {
    SyncPerfect,        // every clock is exactly T. No offset, drift, noise or corrections.
    PersistentOnly,     // persistent per-node offset. No noise, no drift, no corrections.
    PersistentNoise,    // persistent offset + per-block-event noise.
    PersistentDrift,    // persistent offset + bounded linear drift. No noise.
    Corrections,        // persistent offset + drift + NTP-style correction events.
    AdversarialAttacker // honest = PersistentNoise; the attacker holds a perfect clock.
};
static const char *clock_name(ClockMode m) {
    switch (m) {
        case ClockMode::SyncPerfect:         return "sync-perfect";
        case ClockMode::PersistentOnly:      return "persistent-only";
        case ClockMode::PersistentNoise:     return "persistent+noise";
        case ClockMode::PersistentDrift:     return "persistent+drift";
        case ClockMode::Corrections:         return "corrections";
        case ClockMode::AdversarialAttacker: return "adversarial-attacker-clock";
    }
    return "?";
}
struct ClockCfg {
    ClockMode mode = ClockMode::PersistentNoise;
    double sigma_offset  = 1.5;     // s   persistent skew
    double sigma_noise   = 2.0;     // s   per-event jitter
    double drift_ppm_sd  = 0.0;     // ppm persistent rate error
    double drift_ppm_max = 200.0;   // ppm clamp: worse than any usable quartz oscillator
    double corr_period   = 1024.0;  // s   mean gap between correction events (ntpd poll ceiling)
    double corr_resid_sd = 0.05;    // s   residual offset just after a correction
    bool uses_offset() const { return mode != ClockMode::SyncPerfect; }
    bool uses_noise()  const { return mode == ClockMode::PersistentNoise ||
                                      mode == ClockMode::AdversarialAttacker; }
    bool uses_drift()  const { return mode == ClockMode::PersistentDrift ||
                                      mode == ClockMode::Corrections; }
    bool uses_corr()   const { return mode == ClockMode::Corrections; }
};

// ================================================================================================
// ATTACKER INFORMATION BOUNDARY
// ================================================================================================
// A strategy sees ONLY this. It is a free function, so it cannot reach the Sim, the RNG, other
// nodes' clocks, or any future random outcome -- it is not passed them and there is no global
// state to read. Everything here is derivable by a miner from its own chain tip and its own clock.
struct LocalView {
    double   own_clock;      // this node's own clock reading for this event
    bool     lb_applies;     // does the median rule bind at this height, per the daemon's rule
    uint64_t lb;             // median lower bound over this node's own last 60 blocks
    uint64_t height;         // height of the block about to be produced
    uint64_t parent_ts;      // this node's own tip timestamp
    int64_t  ftl;            // public consensus constant
    int64_t  s4_cap;         // chain-relative upper bound, or 0 when the rule is inactive
};
enum class Strat { Honest, ConstFuture, Alternating, SelectiveMax, CutBoundary,
                   LowestOnly, MaxOnly };
static const char *strat_name(Strat s) {
    switch (s) {
        case Strat::Honest: return "honest";
        case Strat::ConstFuture: return "constant-future";
        case Strat::Alternating: return "alternating";
        case Strat::SelectiveMax: return "selective-max";
        case Strat::CutBoundary: return "cut-boundary";
        case Strat::LowestOnly: return "lowest-only";
        case Strat::MaxOnly: return "max-future-only";
    }
    return "?";
}
// Returns the timestamp AND records which branch of the strategy fired, for the traces.
static uint64_t choose_ts(Strat s, const LocalView &v, const char **decision) {
    int64_t hi = (int64_t)v.own_clock + v.ftl;               // highest value legal by its own clock
    if (v.s4_cap > 0 && hi > v.s4_cap) hi = v.s4_cap;        // and by the chain-relative bound
    const int64_t lo = v.lb_applies ? (int64_t)v.lb : 0;
    int64_t want;
    switch (s) {
        case Strat::Honest:
            want = (int64_t)v.own_clock; *decision = "honest-clock"; break;
        case Strat::ConstFuture:
            want = hi; *decision = "max-future"; break;
        case Strat::Alternating:
            if (v.height % 2 == 0) { want = hi; *decision = "alt-high"; }
            else                   { want = lo; *decision = "alt-low"; }
            break;
        case Strat::SelectiveMax:
            if (v.height % 10 == 0) { want = hi; *decision = "sel-high"; }
            else { want = (int64_t)v.own_clock; *decision = "sel-clock"; }
            break;
        case Strat::CutBoundary:
            if (v.height % 2 == 0) { want = hi; *decision = "cut-high"; }
            else                   { want = lo; *decision = "cut-low"; }
            break;
        case Strat::LowestOnly:
            want = lo; *decision = "lowest-only"; break;
        case Strat::MaxOnly:
            want = hi; *decision = "max-only"; break;
        default: want = (int64_t)v.own_clock; *decision = "?"; break;
    }
    if (want < lo) { want = lo; *decision = "clamped-to-median"; }
    if (want < 0) want = 0;
    return (uint64_t)want;
}

// ---- difficulty ---------------------------------------------------------------------------------
struct Cut { size_t begin, end; };
static Cut cut_of(size_t n) {
    if (n <= WINDOW - 2 * CUT) return Cut{0, n};
    size_t b = (n - (WINDOW - 2 * CUT) + 1) / 2;
    return Cut{b, b + (WINDOW - 2 * CUT)};
}
// span_mode: 0 none, 1 candidate B floor, 2 candidate S1 ceiling, 3 both
static difficulty_type diff_impl(std::vector<uint64_t> ts, std::vector<difficulty_type> cd,
                                 int span_mode) {
    if (ts.size() > WINDOW) { ts.resize(WINDOW); cd.resize(WINDOW); }
    size_t n = ts.size();
    if (n <= 1) return 1;
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
    if (span == 0) span = 1;
    difficulty_type w = cd[c.end - 1] - cd[c.begin];
    boost::multiprecision::uint256_t r =
        (boost::multiprecision::uint256_t(w) * TARGET + span - 1) / span;
    return r.convert_to<difficulty_type>();
}

// ---- the median rule, matching Blockchain::check_block_timestamp exactly -------------------------
static uint64_t epee_median(std::vector<uint64_t> v) {
    if (v.empty()) return 0;
    if (v.size() == 1) return v[0];
    size_t n = v.size() / 2;
    std::sort(v.begin(), v.end());
    if (v.size() % 2) return v[n];
    return v[n - 1] / 2 + v[n] / 2 + ((v[n - 1] - 2 * (v[n - 1] / 2)) + (v[n] - 2 * (v[n] / 2))) / 2;
}
struct MedianBound { bool applies; uint64_t value; };

// ---- chain --------------------------------------------------------------------------------------
struct Block {
    int id = -1, parent = -1;
    uint64_t height = 0, ts = 0;
    difficulty_type d = 1, cumwork = 1;
    int producer = -1;
    bool manipulated = false;      // produced by the attacker while its strategy was active
    double found_T = 0;
};

struct World {
    std::vector<Block> blocks;
    World() {
        Block g; g.id = 0; g.parent = -1; g.height = 0; g.ts = GENESIS_TS;
        g.d = 1; g.cumwork = 1; g.producer = -1; g.found_T = (double)GENESIS_TS;
        blocks.push_back(g);
    }
    // DIFFICULTY window: genesis excluded, matching get_difficulty_for_next_block's offset of 1.
    void chain_back(int tip, size_t want, std::vector<uint64_t> &ts,
                    std::vector<difficulty_type> &cd) const {
        std::vector<const Block *> v;
        int cur = tip;
        while (cur >= 0 && v.size() < want) {
            const Block &b = blocks[cur];
            if (b.height == 0) break;
            v.push_back(&b);
            cur = b.parent;
        }
        for (auto it = v.rbegin(); it != v.rend(); ++it) {
            ts.push_back((*it)->ts); cd.push_back((*it)->cumwork);
        }
    }
    // TIMESTAMP window: heights h-60 .. h-1 where h = block count = parent height + 1, i.e. the
    // 60 blocks ending at the parent inclusive. Genesis is inside that set only when h == 60.
    MedianBound median_bound(int parent) const {
        uint64_t h = blocks[parent].height + 1;
        // T1+T2 removes this guard and takes the median over whatever history exists instead.
        if (h < TS_WINDOW && g_ts_rule != TsRule::T1T2 && g_ts_rule != TsRule::T1T2_S4)
            return MedianBound{false, 0};                    // daemon returns true, no median
        std::vector<uint64_t> ts;
        int cur = parent;
        while (cur >= 0 && ts.size() < TS_WINDOW) {
            ts.push_back(blocks[cur].ts);
            if (blocks[cur].height == 0) break;
            cur = blocks[cur].parent;
        }
        return MedianBound{true, epee_median(ts)};
    }
    bool is_ancestor(int anc, int of) const {
        int cur = of;
        while (cur >= 0) {
            if (cur == anc) return true;
            if (blocks[cur].height == 0) break;
            cur = blocks[cur].parent;
        }
        return false;
    }
    std::vector<int> path_to(int tip) const {
        std::vector<int> p;
        for (int cur = tip; cur >= 0; cur = blocks[cur].parent) {
            p.push_back(cur);
            if (blocks[cur].height == 0) break;
        }
        std::reverse(p.begin(), p.end());
        return p;
    }
};

struct Node {
    int id = 0;
    bool attacker = false;
    double hashrate = 0;
    // clock state -- see the lifetime table above
    double offset0 = 0, offset_eff = 0, drift_ppm = 0, sync_T = 0, next_corr_T = 1e300;
    uint64_t noise_event = (uint64_t)-1;
    double noise_cache = 0, noise_sd = 0;
    int tip = 0;
    double busy_until = 0;
    size_t orphaned = 0, produced = 0, reorgs = 0;
};

struct Arrival { double t; int block; int to; bool operator<(const Arrival &o) const { return t > o.t; } };
struct Reject { double T; int block; int by; const char *why; };

struct Trace {
    uint64_t height; double T; uint64_t ts; int producer; bool accepted;
    int branch, block_id;
    double d, solve, proc, prop, vclock;
    uint64_t median_lb, ftl_upper;    // the per-row legal bounds that round 2 failed to record
    bool lb_applies;
    const char *decision;
    const char *why;
};

// ================================================================================================
struct Sim {
    World w;
    std::vector<Node> nodes;
    std::priority_queue<Arrival> inflight;
    std::mt19937_64 rng;
    Rule rule; Strat strat; Profile prof; ClockCfg clk;
    double T = (double)GENESIS_TS;   // advanced by launch_offset in the constructor
    double launch_offset = 0;        // GENESIS AGE: seconds between genesis ts and
                                     // the first mining attempt
    std::vector<Reject> rejects;
    std::vector<Trace> trace;
    size_t accepted = 0, rejected = 0;
    double last_T = -1;
    uint64_t event_seq = 0;
    std::vector<std::vector<double>> accept_times;
    uint64_t attack_until_height = (uint64_t)-1;   // attacker is honest strictly above this height
    bool degenerate = false;                       // item 2: exact-equivalence mode
    std::unordered_map<int, uint64_t> diff_cache;  // memo: tip -> difficulty (fits in 64 bits here)
    // per-block acceptance census, for "was this block legal at the receiving validator"
    std::map<int, std::pair<int,int>> census;      // block -> (accepts, rejects) by peers

    Sim(uint64_t seed, Rule r, Strat s, Profile p, double H, double alpha, int nhonest,
        ClockCfg c = ClockCfg(), double launch_off = 0.0)
        : rng(seed), rule(r), strat(s), prof(p), clk(c) {
        launch_offset = launch_off;
        T += launch_off;
        std::normal_distribution<double> unit(0.0, 1.0);
        std::exponential_distribution<double> ecorr(1.0);
        auto mknode = [&](int id, bool att, double hr) {
            Node n; n.id = id; n.attacker = att; n.hashrate = hr;
            // ALWAYS draw, then scale. Keeps the RNG stream identical across sigma values so a
            // sigma sweep varies dispersion and nothing else.
            double u_off = unit(rng), u_drift = unit(rng);
            bool perfect = (clk.mode == ClockMode::SyncPerfect) ||
                           (att && clk.mode == ClockMode::AdversarialAttacker);
            n.offset0 = perfect ? 0.0 : (clk.uses_offset() ? u_off * clk.sigma_offset : 0.0);
            n.drift_ppm = perfect ? 0.0 : (clk.uses_drift()
                            ? std::max(-clk.drift_ppm_max,
                                std::min(clk.drift_ppm_max, u_drift * clk.drift_ppm_sd)) : 0.0);
            n.noise_sd = perfect ? 0.0 : (clk.uses_noise() ? clk.sigma_noise : 0.0);
            n.offset_eff = n.offset0;
            n.sync_T = (double)GENESIS_TS + launch_off;
            double gap = ecorr(rng) * clk.corr_period;
            n.next_corr_T = (clk.uses_corr() && !perfect)
                          ? (double)GENESIS_TS + launch_off + gap : 1e300;
            nodes.push_back(n);
        };
        mknode(0, true, H * alpha);
        for (int i = 0; i < nhonest; ++i) mknode(i + 1, false, H * (1.0 - alpha) / (double)nhonest);
        accept_times.resize(nodes.size());
    }

    // ---- the clock ------------------------------------------------------------------------------
    double clock_of(Node &n, uint64_t ev) {
        if (clk.uses_corr() && n.next_corr_T < 1e299) {
            std::normal_distribution<double> unit(0.0, 1.0);
            std::exponential_distribution<double> ecorr(1.0);
            while (T >= n.next_corr_T) {
                n.offset_eff = unit(rng) * clk.corr_resid_sd;   // NTP steps the clock to ~truth
                n.sync_T = n.next_corr_T;
                n.next_corr_T += ecorr(rng) * clk.corr_period;
            }
        }
        double v = T + n.offset_eff + n.drift_ppm * 1e-6 * (T - n.sync_T);
        if (n.noise_sd > 0) {
            if (n.noise_event != ev) {
                std::normal_distribution<double> unit(0.0, 1.0);
                n.noise_event = ev;
                n.noise_cache = unit(rng) * n.noise_sd;
            }
            v += n.noise_cache;
        }
        return v;
    }

    bool boot_active(uint64_t next_height) const { return next_height >= 1 && next_height <= BOOT_N; }

    difficulty_type diff_for(int tip) {
        auto it = diff_cache.find(tip);
        if (it != diff_cache.end()) return difficulty_type(it->second);
        std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
        w.chain_back(tip, BLOCKS_COUNT, ts, cd);
        uint64_t nh = w.blocks[tip].height + 1;
        bool boot = nh >= 1 && nh <= SPAN_ACTIVE_UNTIL;
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
        }
        diff_cache[tip] = d.convert_to<uint64_t>();
        return d;
    }

    LocalView view_of(Node &n, uint64_t ev) {
        MedianBound mb = w.median_bound(n.tip);
        LocalView v;
        v.own_clock = clock_of(n, ev);
        v.lb_applies = mb.applies; v.lb = mb.value;
        v.height = w.blocks[n.tip].height + 1;
        v.parent_ts = w.blocks[n.tip].ts;
        v.ftl = FTL;
        v.s4_cap = (g_ts_rule == TsRule::T1T2_S4)
                 ? (int64_t)w.blocks[n.tip].ts + S4_SLACK : 0;
        return v;
    }

    // Receiver-side validation against the RECEIVER's own clock, using the daemon's real rules.
    const char *validate(const Block &b, Node &recv, uint64_t ev, uint64_t *lb_out = nullptr,
                         uint64_t *ftl_out = nullptr) {
        double c = clock_of(recv, ev);
        if (ftl_out) *ftl_out = (uint64_t)std::max(0.0, c + (double)FTL);
        if ((double)b.ts > c + (double)FTL) { if (lb_out) *lb_out = 0; return "timestamp beyond FTL"; }
        MedianBound mb = w.median_bound(b.parent);
        if (lb_out) *lb_out = mb.applies ? mb.value : 0;
        if (mb.applies && b.ts < mb.value) return "timestamp below median lower bound";
        // S4: chain-relative future bound. Uses only chain data, so every node agrees regardless of
        // its own clock -- unlike the FTL, which is local-clock relative.
        // S4: chain-relative future bound, measured from the PARENT timestamp rather than the
        // window median. A median-relative bound fails at low hashrate: the median lags ~30 blocks,
        // so once intervals exceed slack/30 every honest block is rejected and the chain stalls.
        // The parent is at most one interval behind, so a parent-relative bound is safe for any
        // block rate faster than the slack itself.
        if (g_ts_rule == TsRule::T1T2_S4 && b.parent >= 0 &&
            (int64_t)b.ts > (int64_t)w.blocks[b.parent].ts + S4_SLACK)
            return "timestamp above parent + S4 slack";
        // T3b: strict monotonicity against the parent. Carried only to measure what it costs an
        // honest miner whose clock sits behind the previous block's producer.
        if (g_ts_rule == TsRule::T3b && b.parent >= 0 && b.ts < w.blocks[b.parent].ts)
            return "timestamp below parent (T3b monotonicity)";
        return nullptr;
    }

    void deliver(int bid, int to, double at) { inflight.push(Arrival{at, bid, to}); }

    bool stalled = false;          // set when the run gave up because nothing could be accepted

    void run(size_t nblocks, bool record_trace) {
        std::exponential_distribution<double> unit(1.0);
        // A candidate rule can reject every honest block -- S4 with a fixed slack does exactly that
        // at low hashrate, because the median lags further behind than the slack allows. Without a
        // bound the loop would spin forever, so give up after a generous multiple of the target and
        // record the stall as a result rather than hanging.
        const size_t max_iter = nblocks * 50 + 10000;
        size_t iter = 0;
        std::normal_distribution<double> pnd(prof.prop_mean, prof.prop_sd);
        const double tmpl_cost = degenerate ? 0.0 : 0.00054;

        while (accepted < nblocks) {
            if (++iter > max_iter) { stalled = true; break; }
            double best_dt = 1e18; int winner = -1;
            for (auto &n : nodes) {
                if (n.hashrate <= 0) continue;
                difficulty_type d = diff_for(n.tip);
                double mean = d.convert_to<double>() / n.hashrate;
                // Degenerate mode reproduces the OLD simulator's exact expression, not merely an
                // equal-in-real-arithmetic one -- see item 2.
                double dt = degenerate
                    ? std::exponential_distribution<double>(1.0 / mean)(rng)
                    : unit(rng) * mean;
                if (dt < best_dt) { best_dt = dt; winner = n.id; }
            }
            if (winner < 0) break;

            double solve_at = T + best_dt;
            while (!inflight.empty() && inflight.top().t <= solve_at) {
                Arrival a = inflight.top(); inflight.pop();
                T = std::max(T, a.t);
                Node &rn = nodes[a.to];
                double start = std::max(T, rn.busy_until);
                rn.busy_until = start + prof.proc;
                T = std::max(T, start);
                uint64_t ev = ++event_seq;
                const Block &blk = w.blocks[a.block];
                const char *why = validate(blk, rn, ev);
                if (!why) {
                    census[blk.id].first++;
                    accept_times[rn.id].push_back(T);
                    if (blk.cumwork > w.blocks[rn.tip].cumwork) {
                        int old_tip = rn.tip;
                        bool switched_branch = !w.is_ancestor(old_tip, blk.id);
                        if (switched_branch) rn.reorgs++;      // tip moved off its own branch
                        if (w.blocks[old_tip].producer == rn.id && switched_branch)
                            rn.orphaned++;
                        rn.tip = blk.id;
                    }
                } else {
                    census[blk.id].second++;
                    rejects.push_back(Reject{T, blk.id, rn.id, why});
                }
            }

            T = std::max(T, solve_at);
            Node &n = nodes[winner];
            T += tmpl_cost;

            uint64_t ev = ++event_seq;
            uint64_t height = w.blocks[n.tip].height + 1;
            difficulty_type d = diff_for(n.tip);
            bool attacking = n.attacker && (height <= attack_until_height) && strat != Strat::Honest;
            LocalView v = view_of(n, ev);
            const char *decision = "honest-clock";
            uint64_t ts = attacking ? choose_ts(strat, v, &decision)
                                    : choose_ts(Strat::Honest, v, &decision);

            Block b;
            b.id = (int)w.blocks.size(); b.parent = n.tip; b.height = height; b.ts = ts;
            b.d = d; b.cumwork = w.blocks[n.tip].cumwork + d; b.producer = n.id;
            b.manipulated = attacking; b.found_T = T;

            // The producer checks its own block against its own clock, reading the SAME clock
            // sample it used to build the timestamp (same event id).
            uint64_t lb_row = 0, ftl_row = 0;
            const char *why = validate(b, n, ev, &lb_row, &ftl_row);
            double procT = prof.proc;
            T += procT;
            double propd = 0;
            bool acc = (why == nullptr);
            n.produced++;
            if (acc) {
                w.blocks.push_back(b);
                n.tip = b.id;
                census[b.id].first++;
                accept_times[n.id].push_back(T);
                ++accepted;
                for (auto &o : nodes) {
                    if (o.id == n.id) continue;
                    double pd = degenerate ? 0.0 : std::max(0.0, pnd(rng));
                    propd = std::max(propd, pd);
                    deliver(b.id, o.id, T + pd);
                }
            } else {
                ++rejected;
                rejects.push_back(Reject{T, -1, n.id, why});
            }

            if (record_trace)
                trace.push_back(Trace{height, T, ts, n.id, acc, b.parent, acc ? b.id : -1,
                                      d.convert_to<double>(), best_dt, procT, propd,
                                      v.own_clock, lb_row, ftl_row, v.lb_applies,
                                      decision, why ? why : ""});

            if (last_T > T + 1e-12) { printf("INVARIANT VIOLATION: clock went backwards\n"); exit(2); }
            last_T = T;
        }
    }

    int winning_tip() const {
        int best = 0;
        for (const auto &n : nodes)
            if (w.blocks[n.tip].cumwork > w.blocks[best].cumwork) best = n.tip;
        return best;
    }
    // The tip the HONEST majority of hashrate actually follows.
    int honest_tip() const {
        int best = -1;
        for (const auto &n : nodes) {
            if (n.attacker) continue;
            if (best < 0 || w.blocks[n.tip].cumwork > w.blocks[best].cumwork) best = n.tip;
        }
        return best < 0 ? 0 : best;
    }
};

// ---- shared statistics helpers -------------------------------------------------------------------
static double qtile(std::vector<double> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[(size_t)(p * (double)(v.size() - 1))];
}
static double meanv(const std::vector<double> &v) {
    if (v.empty()) return 0;
    double s = 0; for (double x : v) s += x; return s / (double)v.size();
}
static double pearson(const std::vector<double> &a, const std::vector<double> &b) {
    if (a.size() < 2 || a.size() != b.size()) return 0;
    double ma = meanv(a), mb = meanv(b), sa = 0, sb = 0, sab = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        double x = a[i] - ma, y = b[i] - mb;
        sa += x * x; sb += y * y; sab += x * y;
    }
    if (sa <= 0 || sb <= 0) return 0;
    return sab / std::sqrt(sa * sb);
}
// Wall-clock intervals along a given chain.
static std::vector<double> chain_intervals(const Sim &s, int tip) {
    std::vector<int> p = s.w.path_to(tip);
    std::vector<double> iv;
    for (size_t i = 2; i < p.size(); ++i)
        iv.push_back(s.w.blocks[p[i]].found_T - s.w.blocks[p[i - 1]].found_T);
    return iv;
}

// ---- invariant tests -----------------------------------------------------------------------------
static int g_fail = 0;
static void ck(bool c, const char *n) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) ++g_fail; }

static void invariants() {
    printf("INVARIANT AND COMPONENT TESTS\n");
    Profile P = PROFILES[1];
    ClockCfg C;   // default: persistent + noise, sigma_offset 1.5, sigma_noise 2.0

    { Sim s(1, Rule::Control, Strat::Honest, P, 424.0, 0.0, 3, C);
      s.run(120, true);
      bool mono = true, nonzero = true; double prev = -1;
      for (auto &t : s.trace) { if (t.T < prev - 1e-12) mono = false; if (t.proc <= 0) nonzero = false; prev = t.T; }
      ck(mono, "1. global wall clock never decreases");
      ck(s.trace.size() > 1 && s.trace.back().T > s.trace.front().T,
         "1b. wall clock strictly advances across the run (never freezes)");
      ck(nonzero, "2. every produced block consumes nonzero processing time");
      double span = s.trace.back().T - s.trace.front().T;
      char m[160];
      snprintf(m, sizeof(m), "2b. %zu blocks took %.2f s wall clock (floor %.1f ms/block)",
               s.trace.size(), span, 1000 * P.proc);
      ck(span >= P.proc * (double)s.trace.size() * 0.9, m);
    }
    { std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
      uint64_t t0 = GENESIS_TS; difficulty_type acc = 1;
      for (int i = 0; i < 300; ++i) { t0 += 60; acc = acc + 25440; ts.push_back(t0); cd.push_back(acc); }
      difficulty_type a = cryptonote::next_difficulty(ts, cd, TARGET);
      for (auto &x : ts) x += 7200;
      ck(a == cryptonote::next_difficulty(ts, cd, TARGET),
         "3. a CONSTANT timestamp offset cancels exactly (span is a difference)");
    }
    { Sim s(2, Rule::Control, Strat::Honest, PROFILES[0], 424.0, 0.0, 1,
            ClockCfg{ClockMode::SyncPerfect});
      s.run(80, false);
      Node &n = s.nodes[1];
      Block b; b.parent = n.tip; b.height = s.w.blocks[n.tip].height + 1;
      b.ts = (uint64_t)(s.T + FTL + 5);
      ck(s.validate(b, n, ++s.event_seq) != nullptr,
         "4. a timestamp beyond the future-time limit is REJECTED (not clamped)");
      MedianBound mb = s.w.median_bound(n.tip);
      Block b2; b2.parent = n.tip; b2.height = b.height; b2.ts = mb.value ? mb.value - 1 : 0;
      ck(!mb.applies || s.validate(b2, n, ++s.event_seq) != nullptr,
         "4b. below the median lower bound is REJECTED wherever the bound applies");
    }
    { // 4c the daemon's guard: no median check below 60 blocks
      Sim s(21, Rule::Control, Strat::Honest, PROFILES[0], 424.0, 0.0, 1,
            ClockCfg{ClockMode::SyncPerfect});
      s.run(20, false);
      MedianBound mb = s.w.median_bound(s.nodes[1].tip);
      ck(!mb.applies, "4c. below 60 blocks the median rule does NOT apply (daemon returns true)");
      s.run(120, false);
      MedianBound mb2 = s.w.median_bound(s.nodes[1].tip);
      ck(mb2.applies, "4d. at or above 60 blocks the median rule DOES apply");
    }
    { // 4e epee median of an even-sized window
      std::vector<uint64_t> v;
      for (uint64_t i = 0; i < 60; ++i) v.push_back(1000 + i);
      ck(epee_median(v) == (1029 + 1030) / 2,
         "4e. epee median of 60 entries is (v[29]+v[30])/2, not v[30]");
    }
    { Sim s(3, Rule::Control, Strat::Honest, PROFILES[0], 424.0, 0.0, 3, C);
      s.run(4000, true);
      std::vector<double> iv;
      for (auto &t : s.trace) if (t.accepted) iv.push_back(t.solve);
      double r = qtile(iv, 0.5) / meanv(iv);
      char m[160];
      snprintf(m, sizeof(m), "5. honest intervals look exponential: median/mean = %.3f (expect ~0.693)", r);
      ck(r > 0.60 && r < 0.79, m);
    }
    { Sim s(4, Rule::Control, Strat::Honest, PROFILES[0], 424.0, 0.0, 2, C);
      s.run(200, false);
      std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
      s.w.chain_back(s.winning_tip(), BLOCKS_COUNT, ts, cd);
      ck(s.diff_for(s.winning_tip()) == cryptonote::next_difficulty(ts, cd, TARGET),
         "7. simulator difficulty == cryptonote::next_difficulty() for identical history");
    }
    { Sim s(5, Rule::Control, Strat::Honest, PROFILES[P_GLOBAL], 424.0, 0.5, 3, C);
      s.run(400, false);
      int wt = s.winning_tip(); bool ok = true;
      for (auto &n : s.nodes) if (s.w.blocks[n.tip].cumwork > s.w.blocks[wt].cumwork) ok = false;
      ck(ok, "8. the winning tip is the highest cumulative work among all node tips");
    }
    { bool per_node_ok = true, parent_ok = true, concurrency_seen = false;
      double worst_gap = 1e9;
      for (Strat st : {Strat::Honest, Strat::ConstFuture, Strat::Alternating, Strat::CutBoundary}) {
          Sim s2(6, Rule::Control, st, PROFILES[1], 424.0, 1.0, 3, C);
          s2.run(300, false);
          for (auto &v0 : s2.accept_times) {
              auto v = v0; std::sort(v.begin(), v.end());
              for (size_t k = 1; k < v.size(); ++k) {
                  worst_gap = std::min(worst_gap, v[k] - v[k-1]);
                  if (v[k] - v[k-1] < PROFILES[1].proc * 0.999) per_node_ok = false;
              }
          }
          for (const auto &b : s2.w.blocks)
              if (b.height > 0 && (b.parent < 0 || b.parent >= b.id)) parent_ok = false;
          std::vector<int> tips; for (auto &nn : s2.nodes) tips.push_back(nn.tip);
          for (size_t i = 1; i < tips.size(); ++i) if (tips[i] != tips[0]) concurrency_seen = true;
      }
      char m[200];
      snprintf(m, sizeof(m), "9. NO NODE accepts faster than its own queue (min gap %.1f ms >= %.1f ms)",
               1000 * worst_gap, 1000 * PROFILES[1].proc);
      ck(per_node_ok, m);
      ck(parent_ok, "9b. every block's parent is an earlier, already-validated block");
      ck(concurrency_seen, "9c. nodes DO hold competing tips concurrently (branches are real)");
    }
    { auto sig = [](uint64_t seed) {
        Sim s(seed, Rule::Control, Strat::CutBoundary, PROFILES[1], 424.0, 0.33, 3);
        s.run(200, false);
        std::string out;
        for (auto &b : s.w.blocks) out += std::to_string(b.ts) + ":" + cryptonote::hex(b.d) + ";";
        return out; };
      ck(sig(99) == sig(99), "10. identical seeds produce byte-identical chains");
    }
    { // 11 (round 3) a node's clock reading is STABLE within one event and independent across events
      Sim s(7, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 0.0, 3, C);
      s.run(30, false);
      Node &n = s.nodes[1];
      uint64_t ev = ++s.event_seq;
      double a1 = s.clock_of(n, ev), a2 = s.clock_of(n, ev);
      double b1 = s.clock_of(n, ++s.event_seq);
      ck(a1 == a2, "11. one node reading its clock twice in ONE event gets the SAME value");
      ck(a1 != b1, "11b. a different event draws fresh noise");
    }
    { // 12 (round 3) a persistent offset is never resampled
      Sim s(8, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 0.0, 3,
            ClockCfg{ClockMode::PersistentOnly, 5.0, 0.0});
      std::vector<double> before; for (auto &n : s.nodes) before.push_back(n.offset0);
      s.run(400, false);
      bool same = true;
      for (size_t i = 0; i < s.nodes.size(); ++i) if (s.nodes[i].offset0 != before[i]) same = false;
      bool distinct = false;
      for (size_t i = 1; i < s.nodes.size(); ++i) if (s.nodes[i].offset0 != s.nodes[0].offset0) distinct = true;
      ck(same, "12. persistent node offsets are drawn ONCE and never resampled");
      ck(distinct, "12b. different nodes really do hold different persistent offsets");
      bool nonoise = true;
      for (auto &n : s.nodes) if (n.noise_sd != 0) nonoise = false;
      ck(nonoise, "12c. persistent-only mode carries no per-event noise");
    }
    { // 13 (round 3) sigma sweeps do not shift the RNG stream
      auto solves = [](double so) {
          Sim s(1234, Rule::Control, Strat::Honest, PROFILES[0], 424.0, 0.0, 3,
                ClockCfg{ClockMode::PersistentOnly, so, 0.0});
          s.run(40, true);
          std::vector<double> v; for (auto &t : s.trace) v.push_back(t.solve);
          return v; };
      std::vector<double> a = solves(0.0), b = solves(30.0);
      // the FIRST solve draw happens before any clock reading can differ, so it must be identical
      ck(!a.empty() && !b.empty() && a[0] == b[0],
         "13. sigma = 0 and sigma = 30 consume the same RNG prefix (stream aligned)");
    }
    { // 14 (round 3) the attacker's strategy is a pure function of its LocalView
      LocalView v; v.own_clock = 1000; v.lb_applies = true; v.lb = 900; v.height = 10;
      v.parent_ts = 950; v.ftl = FTL;
      const char *d1, *d2;
      ck(choose_ts(Strat::ConstFuture, v, &d1) == choose_ts(Strat::ConstFuture, v, &d2),
         "14. a timestamp strategy is a pure function of the attacker's local view");
      v.height = 11;
      const char *d3;
      ck(choose_ts(Strat::Alternating, v, &d3) == 900,
         "14b. on odd heights the alternating strategy takes the median bound, its legal floor");
    }
    printf("\n");
}

// ================================================================================================
// ITEM 1 -- the clock-lifetime specification, printed from the code that implements it
// ================================================================================================
static void clockspec() {
    printf("ITEM 1 -- CLOCK MODEL AUDIT\n\n");
    printf("  Every random clock quantity, and how long each draw lives:\n\n");
    printf("  %-16s %-30s %s\n", "quantity", "distribution", "DRAW LIFETIME");
    printf("  %-16s %-30s %s\n", "offset0_i", "N(0,1)*sigma_offset",
           "ONCE per node at construction; never resampled");
    printf("  %-16s %-30s %s\n", "drift_i", "N(0,1)*drift_ppm_sd, clamped",
           "ONCE per node at construction");
    printf("  %-16s %-30s %s\n", "noise_i(e)", "N(0,1)*sigma_noise",
           "ONCE per (node, clock-read EVENT)");
    printf("  %-16s %-30s %s\n", "corr_gap_i(k)", "Exp(mean=corr_period)", "ONCE per correction event");
    printf("  %-16s %-30s %s\n", "corr_resid_i(k)", "N(0,1)*corr_resid_sd", "ONCE per correction event");
    printf("\n  local_clock_i(T,e) = T + offset_eff_i + drift_i*1e-6*(T - sync_T_i) + noise_i(e)\n");
    printf("  An EVENT is one block production, or one arrival validated at one node.\n\n");

    printf("  Confirmed by direct inspection of a running simulation:\n");
    ClockCfg C{ClockMode::Corrections, 2.0, 0.0, 50.0, 200.0, 300.0, 0.05};
    Sim s(4242, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 0.0, 3, C);
    std::vector<double> o0; for (auto &n : s.nodes) o0.push_back(n.offset0);
    s.run(200, false);
    printf("    persistent offsets at construction : ");
    for (double x : o0) printf("%+.3f ", x);
    printf("\n    the same offsets after 200 blocks   : ");
    for (auto &n : s.nodes) printf("%+.3f ", n.offset0);
    printf("  <- unchanged, so they are persistent\n");
    printf("    effective offsets after corrections : ");
    for (auto &n : s.nodes) printf("%+.3f ", n.offset_eff);
    printf("  <- moved, so corrections did fire\n");
    printf("    drift rates (ppm)                   : ");
    for (auto &n : s.nodes) printf("%+.1f ", n.drift_ppm);
    printf("\n\n");

    printf("  The six modes, and what each holds constant:\n");
    printf("  %-28s %-9s %-8s %-8s %-8s\n", "mode", "offset", "noise", "drift", "corrections");
    struct MM { ClockMode m; } mm[] = {{ClockMode::SyncPerfect}, {ClockMode::PersistentOnly},
        {ClockMode::PersistentNoise}, {ClockMode::PersistentDrift}, {ClockMode::Corrections},
        {ClockMode::AdversarialAttacker}};
    for (auto &x : mm) {
        ClockCfg c; c.mode = x.m;
        printf("  %-28s %-9s %-8s %-8s %-8s\n", clock_name(x.m),
               c.uses_offset() ? "yes" : "no", c.uses_noise() ? "yes" : "no",
               c.uses_drift() ? "yes" : "no", c.uses_corr() ? "yes" : "no");
    }
    printf("\n  Validator clock == the same node clock. Validation always reads the RECEIVER's\n");
    printf("  clock, at a fresh event, so producer and validator disagree exactly as two real\n");
    printf("  hosts would. In adversarial-attacker-clock mode the attacker's clock is perfect --\n");
    printf("  the best a well-synchronised attacker could hold -- and it still cannot observe any\n");
    printf("  validator's clock, because choose_ts() is not given one.\n\n");

    printf("  Effect of each mode on the honest control (0%% attacker, 400 blocks, localhost):\n");
    printf("  %-28s %10s %10s %10s %10s\n", "mode", "s/blk-chain", "s/blk-prod", "rejects", "orphans");
    for (auto &x : mm) {
        ClockCfg c; c.mode = x.m; c.sigma_offset = 2.0; c.sigma_noise = 2.0; c.drift_ppm_sd = 50.0;
        Sim s2(777, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 0.0, 3, c);
        s2.run(400, false);
        std::vector<double> iv = chain_intervals(s2, s2.winning_tip());
        double prod = (s2.w.blocks.back().found_T - s2.w.blocks[1].found_T) / (double)s2.accepted;
        size_t orph = 0; for (auto &n : s2.nodes) orph += n.orphaned;
        printf("  %-28s %10.2f %10.2f %10zu %10zu\n", clock_name(x.m), meanv(iv), prod,
               s2.rejected, orph);
    }
    printf("\n");
}

// ================================================================================================
// ITEM 2 -- degenerate exact-equivalence against the earlier bootstrap simulator
// ================================================================================================
// The earlier simulator, reproduced verbatim from node/meepcoin_bootstrap_sim.cpp (default policy).
namespace oldsim {
struct Blk { uint64_t height, timestamp; double solve_s; difficulty_type difficulty; };
struct Chain {
    std::vector<uint64_t> ts; std::vector<difficulty_type> cd; std::vector<Blk> blocks;
    double t = 0; std::mt19937_64 rng;
    Chain(uint64_t seed, uint64_t genesis_ts, double launch_offset) : rng(seed) {
        ts.push_back(genesis_ts); cd.push_back(1);
        blocks.push_back(Blk{0, genesis_ts, 0, 1});
        t = (double)genesis_ts + launch_offset;
    }
    difficulty_type raw_next() const {
        size_t n = ts.size(), take = std::min(n, BLOCKS_COUNT);
        size_t from = (n > take) ? n - take : 0;
        std::vector<uint64_t> a; std::vector<difficulty_type> b;
        for (size_t i = from; i < n; ++i) { if (i == 0) continue; a.push_back(ts[i]); b.push_back(cd[i]); }
        if (a.size() < 2) return 1;
        return cryptonote::next_difficulty(a, b, TARGET);
    }
    void mine(double H) {
        difficulty_type d = raw_next(); if (d == 0) d = 1;
        double mean = d.convert_to<double>() / std::max(H, 1e-9);
        std::exponential_distribution<double> ed(1.0 / std::max(mean, 1e-12));
        double solve = ed(rng);
        t += solve;
        uint64_t rec = (uint64_t)t;
        ts.push_back(rec); cd.push_back(cd.back() + d);
        blocks.push_back(Blk{(uint64_t)blocks.size(), rec, solve, d});
    }
};
}  // namespace oldsim

static void degenerate_equivalence() {
    printf("ITEM 2 -- DEGENERATE EXACT-EQUIVALENCE MODE\n\n");
    printf("  netsim is configured as: one miner, one validating node, zero propagation, zero\n");
    printf("  processing, zero template cost, sync-perfect clocks, no branch competition, the same\n");
    printf("  seed, the same genesis timestamp and the same integer-second convention.\n");
    printf("  The ONLY consensus rule that cannot be switched off is the median lower bound, and\n");
    printf("  the run below records how often it binds.\n\n");

    const double H = 424.0;
    const size_t N = 400;
    size_t seeds_ok = 0, seeds_run = 0, lb_binds_total = 0;
    long first_bad_seed = -1, first_bad_h = -1;
    for (uint64_t seed = 1; seed <= 40; ++seed) {
        Profile Z = PROFILES[0];
        Sim s(seed, Rule::Control, Strat::Honest, Z, H, 0.0, 1, ClockCfg{ClockMode::SyncPerfect});
        s.degenerate = true;
        // node 0 (the attacker slot) has zero hashrate and must not exist at all here
        s.nodes.erase(s.nodes.begin());
        s.nodes[0].id = 0; s.accept_times.resize(1);
        // The Sim constructor draws clock parameters even in sync-perfect mode, deliberately, so
        // that a sigma sweep keeps one RNG stream. The old simulator made no such draws. Reseeding
        // here is what makes "identical RNG seed and exponential draws" literally true.
        s.rng.seed(seed);
        s.run(N, true);

        oldsim::Chain c(seed, GENESIS_TS, 0.0);
        for (size_t i = 0; i < N; ++i) c.mine(H);

        std::vector<int> path = s.w.path_to(s.winning_tip());
        bool ok = (path.size() == c.blocks.size());
        size_t lb_binds = 0;
        for (size_t i = 0; ok && i < path.size(); ++i) {
            const Block &b = s.w.blocks[path[i]];
            if (b.ts != c.blocks[i].timestamp || b.d != c.blocks[i].difficulty) {
                ok = false;
                if (first_bad_seed < 0) {
                    first_bad_seed = (long)seed; first_bad_h = (long)i;
                    printf("      DIVERGENCE DETAIL, seed %llu, first %zu heights:\n",
                           (unsigned long long)seed, std::min<size_t>(8, path.size()));
                    printf("        %5s %14s %14s %12s %12s\n", "h", "netsim_ts", "oldsim_ts",
                           "netsim_d", "oldsim_d");
                    for (size_t k = 0; k < std::min<size_t>(8, path.size()); ++k)
                        printf("        %5zu %14llu %14llu %12s %12s\n", k,
                               (unsigned long long)s.w.blocks[path[k]].ts,
                               (unsigned long long)c.blocks[k].timestamp,
                               cryptonote::hex(s.w.blocks[path[k]].d).c_str(),
                               cryptonote::hex(c.blocks[k].difficulty).c_str());
                }
            }
        }
        for (auto &t : s.trace) if (t.lb_applies && t.ts == t.median_lb) ++lb_binds;
        lb_binds_total += lb_binds;
        ++seeds_run; if (ok) ++seeds_ok;
    }
    printf("  timestamps, difficulty and chain length, every height, %zu seeds x %zu blocks:\n",
           seeds_run, N);
    printf("      %zu/%zu seeds EXACTLY identical -> %s\n", seeds_ok, seeds_run,
           seeds_ok == seeds_run ? "PASS" : "FAIL");
    if (seeds_ok != seeds_run)
        printf("      first divergence: seed %ld at height %ld\n", first_bad_seed, first_bad_h);
    printf("      median lower bound bound the timestamp %zu times in %zu blocks\n",
           lb_binds_total, seeds_run * N);
    printf("      (with monotone zero-noise clocks the bound is always below the current time, so\n");
    printf("       it never binds; that is WHY equivalence is attainable, not an assumption)\n\n");

    // The one remaining difference, isolated and measured.
    printf("  THE PRECISE REMAINING DIFFERENCE, tested on its own:\n");
    printf("  Outside degenerate mode netsim draws Exp(1) and multiplies by the mean; the old sim\n");
    printf("  constructs Exp(1/mean) and divides. Those are equal in real arithmetic and NOT equal\n");
    printf("  in floating point. Degenerate mode uses the old form so the comparison above isolates\n");
    printf("  the model, not the rounding. Measured size of that rounding:\n");
    {
        std::mt19937_64 r1(9), r2(9);
        std::exponential_distribution<double> u(1.0);
        size_t differ = 0, floor_differ = 0; double max_rel = 0;
        double acc1 = (double)GENESIS_TS, acc2 = (double)GENESIS_TS;
        for (int i = 0; i < 200000; ++i) {
            double mean = 20000.0 + (i % 4096);
            double a = u(r1) * mean;
            double b = std::exponential_distribution<double>(1.0 / mean)(r2);
            if (a != b) {
                ++differ;
                max_rel = std::max(max_rel, std::fabs(a - b) / std::max(1e-300, std::fabs(a)));
            }
            acc1 += a; acc2 += b;
            if ((uint64_t)acc1 != (uint64_t)acc2) ++floor_differ;
        }
        printf("      200000 paired draws in THIS binary: %zu differ, max relative difference %.3e\n",
               differ, max_rel);
        printf("      integer-second timestamps that differ after accumulation: %zu\n", floor_differ);
        printf("      CAVEAT, and it matters: this binary is built with -Ofast (Monero's release\n");
        printf("      setting), which permits the compiler to rewrite x/(1/m) as x*m, so the two\n");
        printf("      forms collapse to the same instructions here. Compiled at plain -O2 the same\n");
        printf("      200000 draws give 48010 differences with a maximum relative difference of\n");
        printf("      2.220e-16, i.e. one unit in the last place. So the expression forms ARE\n");
        printf("      distinguishable in general; this build simply cannot see it.\n");
        printf("      Either way the equivalence result above is unaffected, because degenerate\n");
        printf("      mode uses the old simulator's expression form directly.\n\n");
        printf("      Related limitation, stated rather than buried: -Ofast applies to the whole\n");
        printf("      simulator. Consensus arithmetic is unaffected -- next_difficulty() is integer\n");
        printf("      and uint256 throughout -- but the MODEL's own timing arithmetic is subject to\n");
        printf("      fast-math reassociation.\n\n");
    }
}

// ================================================================================================
// ITEM 3 -- honest-control clock sensitivity, 10k seeds
// ================================================================================================
struct RunStats {
    double iv_mean = 0, iv_med = 0, iv_p5 = 0, iv_p95 = 0;
    double iv_head = 0, iv_tail = 0;      // first 50 blocks vs last 200 -- launch spike vs steady state
    double d_med = 0, d_p5 = 0, d_p95 = 0, d_peak = 0;
    double rej_rate = 0, orphan_rate = 0, branches = 0;
    double eff_span = 0, raw_span = 0;
    std::vector<double> share, offset;    // per honest node
};
static RunStats one_honest_run(uint64_t seed, const ClockCfg &c, size_t nblocks, int nhonest) {
    Sim s(seed, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 0.0, nhonest, c);
    s.run(nblocks, false);
    int wt = s.winning_tip();
    std::vector<int> path = s.w.path_to(wt);
    RunStats r;
    std::vector<double> iv = chain_intervals(s, wt), dd;
    for (size_t i = 1; i < path.size(); ++i) dd.push_back(s.w.blocks[path[i]].d.convert_to<double>());
    r.iv_mean = meanv(iv); r.iv_med = qtile(iv, .5); r.iv_p5 = qtile(iv, .05); r.iv_p95 = qtile(iv, .95);
    if (iv.size() > 250) {
        r.iv_head = meanv(std::vector<double>(iv.begin(), iv.begin() + 50));
        r.iv_tail = meanv(std::vector<double>(iv.end() - 200, iv.end()));
    } else { r.iv_head = r.iv_mean; r.iv_tail = r.iv_mean; }
    r.d_med = qtile(dd, .5); r.d_p5 = qtile(dd, .05); r.d_p95 = qtile(dd, .95);
    for (double x : dd) r.d_peak = std::max(r.d_peak, x);
    r.rej_rate = (double)s.rejected / (double)std::max<size_t>(1, s.accepted + s.rejected);
    size_t orph = 0; for (auto &n : s.nodes) orph += n.orphaned;
    r.orphan_rate = (double)orph / (double)std::max<size_t>(1, s.accepted);
    r.branches = (double)(s.w.blocks.size() - path.size());
    // effective (cut) timestamp span at the final tip, and the raw window span
    std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
    s.w.chain_back(wt, BLOCKS_COUNT, ts, cd);
    if (ts.size() > WINDOW) ts.resize(WINDOW);
    if (ts.size() >= 2) {
        std::vector<uint64_t> sorted = ts; std::sort(sorted.begin(), sorted.end());
        Cut cc = cut_of(sorted.size());
        r.eff_span = (double)(sorted[cc.end - 1] - sorted[cc.begin]);
        r.raw_span = (double)(sorted.back() - sorted.front());
    }
    std::vector<size_t> cnt(s.nodes.size(), 0);
    for (size_t i = 1; i < path.size(); ++i) {
        int p = s.w.blocks[path[i]].producer;
        if (p >= 0) cnt[(size_t)p]++;
    }
    for (auto &n : s.nodes) {
        if (n.attacker) continue;
        r.share.push_back((double)cnt[(size_t)n.id] / (double)std::max<size_t>(1, path.size() - 1));
        r.offset.push_back(n.offset0);
    }
    return r;
}

struct Agg {
    std::vector<double> iv_mean, iv_med, iv_p5, iv_p95, iv_head, iv_tail,
                        d_med, d_p5, d_p95, d_peak, rej, orph, br, eff, raw;
    std::vector<double> share, offset;
    void add(const RunStats &r) {
        iv_mean.push_back(r.iv_mean); iv_med.push_back(r.iv_med);
        iv_p5.push_back(r.iv_p5); iv_p95.push_back(r.iv_p95);
        iv_head.push_back(r.iv_head); iv_tail.push_back(r.iv_tail);
        d_med.push_back(r.d_med); d_p5.push_back(r.d_p5); d_p95.push_back(r.d_p95);
        d_peak.push_back(r.d_peak);
        rej.push_back(r.rej_rate); orph.push_back(r.orphan_rate); br.push_back(r.branches);
        eff.push_back(r.eff_span); raw.push_back(r.raw_span);
        for (size_t i = 0; i < r.share.size(); ++i) { share.push_back(r.share[i]); offset.push_back(r.offset[i]); }
    }
    void merge(const Agg &p) {
        auto A = [](std::vector<double> &d, const std::vector<double> &s) {
            d.insert(d.end(), s.begin(), s.end()); };
        A(iv_mean, p.iv_mean); A(iv_med, p.iv_med); A(iv_p5, p.iv_p5); A(iv_p95, p.iv_p95);
        A(iv_head, p.iv_head); A(iv_tail, p.iv_tail);
        A(d_med, p.d_med); A(d_p5, p.d_p5); A(d_p95, p.d_p95); A(d_peak, p.d_peak);
        A(rej, p.rej); A(orph, p.orph); A(br, p.br); A(eff, p.eff); A(raw, p.raw);
        A(share, p.share); A(offset, p.offset);
    }
};

static Agg sweep_seeds(const ClockCfg &c, size_t nseeds, size_t nblocks, int nhonest,
                       uint64_t seed_base) {
    unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    size_t nth = std::min<size_t>(hw, 16);
    std::vector<Agg> parts(nth);
    std::vector<std::thread> th;
    for (size_t t = 0; t < nth; ++t) {
        th.emplace_back([&, t]() {
            for (size_t i = t; i < nseeds; i += nth)
                parts[t].add(one_honest_run(seed_base + i, c, nblocks, nhonest));
        });
    }
    for (auto &x : th) x.join();
    Agg all;
    for (auto &p : parts) all.merge(p);
    return all;
}

static void honest_sensitivity(size_t NSEED, size_t NBLK) {
    printf("ITEM 3 -- HONEST-CONTROL CLOCK SENSITIVITY\n\n");
    printf("  0%% attacker. %zu deterministic seeds per setting, %zu blocks each, localhost profile,\n",
           NSEED, NBLK);
    printf("  3 honest miners at 424 H/s total, target %zu s. Intervals are measured ALONG THE\n", TARGET);
    printf("  WINNING CHAIN, not across all produced blocks.\n\n");

    struct Row { const char *label; ClockCfg c; };
    std::vector<Row> rows;
    // (a) persistent offset alone -- noise and drift held at zero
    for (double so : {0.0, 0.5, 2.0, 10.0, 30.0}) {
        ClockCfg c{ClockMode::PersistentOnly}; c.sigma_offset = so; c.sigma_noise = 0; c.drift_ppm_sd = 0;
        char *lbl = new char[64]; snprintf(lbl, 64, "offset %.1f s, no noise, no drift", so);
        rows.push_back({lbl, c});
    }
    // (b) per-block noise alone -- offset held at zero
    for (double sn : {0.0, 0.5, 2.0, 10.0, 30.0}) {
        ClockCfg c{ClockMode::PersistentNoise}; c.sigma_offset = 0; c.sigma_noise = sn;
        char *lbl = new char[64]; snprintf(lbl, 64, "no offset, noise %.1f s", sn);
        rows.push_back({lbl, c});
    }
    // (c) drift alone -- offset 2 s fixed, no noise
    for (double dp : {0.0, 1.0, 10.0, 100.0}) {
        ClockCfg c{ClockMode::PersistentDrift}; c.sigma_offset = 2.0; c.sigma_noise = 0; c.drift_ppm_sd = dp;
        char *lbl = new char[64]; snprintf(lbl, 64, "offset 2 s, drift %.0f ppm", dp);
        rows.push_back({lbl, c});
    }
    // (d) corrections
    { ClockCfg c{ClockMode::Corrections}; c.sigma_offset = 2.0; c.sigma_noise = 0; c.drift_ppm_sd = 50.0;
      rows.push_back({"offset 2 s, drift 50 ppm, NTP corrections", c}); }

    printf("  %-42s %8s %8s %8s %8s %8s %8s %10s %11s %7s %7s %9s %9s\n", "setting",
           "iv_mean", "iv_med", "iv_p5", "iv_p95", "iv_head", "iv_tail", "diff_p50", "diff_peak",
           "rej", "orph", "eff_span", "raw_span");
    std::vector<std::pair<std::string, Agg>> keep;
    for (auto &r : rows) {
        Agg a = sweep_seeds(r.c, NSEED, NBLK, 3, 300000);
        printf("  %-42s %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %10.0f %11.0f %7.4f %7.4f %9.0f %9.0f\n",
               r.label, meanv(a.iv_mean), meanv(a.iv_med), meanv(a.iv_p5), meanv(a.iv_p95),
               meanv(a.iv_head), meanv(a.iv_tail),
               meanv(a.d_med), meanv(a.d_peak), meanv(a.rej), meanv(a.orph),
               meanv(a.eff), meanv(a.raw));
        keep.emplace_back(r.label, std::move(a));
    }
    printf("\n  iv_head = mean over the first 50 blocks (the launch transient); iv_tail = mean over\n");
    printf("  the last 200 (steady state). Splitting them separates a launch-spike effect from a\n");
    printf("  standing one; diff_peak is the launch spike itself.\n");
    printf("\n  Miner share vs persistent clock offset (all honest nodes, all seeds pooled):\n");
    printf("  %-42s %10s %12s %12s\n", "setting", "pearson_r", "share_min", "share_max");
    for (auto &kv : keep) {
        double r = pearson(kv.second.offset, kv.second.share);
        double lo = 1e9, hi = -1e9;
        for (double x : kv.second.share) { lo = std::min(lo, x); hi = std::max(hi, x); }
        printf("  %-42s %10.4f %12.4f %12.4f\n", kv.first.c_str(), r, lo, hi);
    }
    printf("\n  Distribution across seeds for the offset sweep (mean interval per seed):\n");
    printf("  %-42s %8s %8s %8s %8s %8s\n", "setting", "p5", "p25", "p50", "p75", "p95");
    for (auto &kv : keep) {
        if (kv.first.find("offset") != 0) continue;
        printf("  %-42s %8.2f %8.2f %8.2f %8.2f %8.2f\n", kv.first.c_str(),
               qtile(kv.second.iv_mean, .05), qtile(kv.second.iv_mean, .25),
               qtile(kv.second.iv_mean, .50), qtile(kv.second.iv_mean, .75),
               qtile(kv.second.iv_mean, .95));
    }
    printf("\n");
}

// ================================================================================================
// ITEM 5 -- attack-stop recovery, with the recovery criterion fixed BEFORE the run
// ================================================================================================
struct WinRow {
    uint64_t height; double T; uint64_t ts; bool manip;
    size_t manip_raw, manip_cut, cut_begin, cut_end;
    uint64_t raw_span, eff_span;
    double cumwork_range, d_raw, d_acc, iv20, iv100;
};
static std::vector<WinRow> window_trace(const Sim &s, int tip) {
    std::vector<int> path = s.w.path_to(tip);
    std::vector<WinRow> out;
    for (size_t i = 1; i < path.size(); ++i) {
        const Block &b = s.w.blocks[path[i]];
        std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
        s.w.chain_back(b.parent, BLOCKS_COUNT, ts, cd);
        std::vector<char> mn;
        { std::vector<const Block *> v; int cur = b.parent;
          while (cur >= 0 && v.size() < BLOCKS_COUNT) {
              if (s.w.blocks[cur].height == 0) break;
              v.push_back(&s.w.blocks[cur]); cur = s.w.blocks[cur].parent; }
          for (auto it = v.rbegin(); it != v.rend(); ++it) mn.push_back((*it)->manipulated ? 1 : 0); }
        if (ts.size() > WINDOW) { ts.resize(WINDOW); cd.resize(WINDOW); mn.resize(WINDOW); }
        WinRow r{}; r.height = b.height; r.T = b.found_T; r.ts = b.ts; r.manip = b.manipulated;
        r.manip_raw = 0; for (char c : mn) r.manip_raw += (size_t)c;
        if (ts.size() >= 2) {
            std::vector<std::pair<uint64_t,char>> z;
            for (size_t k = 0; k < ts.size(); ++k) z.push_back({ts[k], mn[k]});
            std::stable_sort(z.begin(), z.end(),
                             [](const std::pair<uint64_t,char>&a, const std::pair<uint64_t,char>&b2){
                                 return a.first < b2.first; });
            Cut c = cut_of(z.size());
            r.cut_begin = c.begin; r.cut_end = c.end;
            for (size_t k = c.begin; k < c.end; ++k) r.manip_cut += (size_t)z[k].second;
            r.raw_span = z.back().first - z.front().first;
            r.eff_span = z[c.end - 1].first - z[c.begin].first;
            std::vector<uint64_t> sts; std::vector<difficulty_type> scd = cd;
            for (auto &p : z) sts.push_back(p.first);
            r.cumwork_range = (cd[c.end - 1] - cd[c.begin]).convert_to<double>();
            r.d_raw = cryptonote::next_difficulty(ts, cd, TARGET).convert_to<double>();
        }
        r.d_acc = b.d.convert_to<double>();
        auto trail = [&](size_t k) {
            if (i < k + 1) return 0.0;
            return (s.w.blocks[path[i]].found_T - s.w.blocks[path[i - k]].found_T) / (double)k; };
        r.iv20 = trail(20); r.iv100 = trail(100);
        out.push_back(r);
    }
    return out;
}

static void recovery_analysis(bool full_csv) {
    printf("ITEM 5 -- ATTACK-STOP RECOVERY\n\n");
    printf("  SIMULATED UPPER BOUND. The 100%%-alternating case is not a demonstrated network\n");
    printf("  capability and is not treated as ground truth.\n\n");

    const uint64_t SEED = 31415;
    const size_t ATTACK_H = 300, TOTAL = 1500;
    ClockCfg C{ClockMode::PersistentNoise}; C.sigma_offset = 1.5; C.sigma_noise = 2.0;

    // ---- baseline and recovery criterion, both fixed BEFORE the attacked run ----
    Sim base(SEED, Rule::Control, Strat::Honest, PROFILES[1], 424.0, 1.0, 3, C);
    base.run(TOTAL, false);
    std::vector<double> biv = chain_intervals(base, base.winning_tip());
    std::vector<int> bpath = base.w.path_to(base.winning_tip());
    std::vector<double> bd;
    for (size_t i = bpath.size() > 200 ? bpath.size() - 200 : 1; i < bpath.size(); ++i)
        bd.push_back(base.w.blocks[bpath[i]].d.convert_to<double>());
    std::vector<double> btail(biv.end() - std::min<size_t>(200, biv.size()), biv.end());
    const double B = meanv(btail), D = meanv(bd);
    printf("  PRE-REGISTERED RECOVERY CRITERION (fixed before the attacked run):\n");
    printf("    baseline, from a 0%%-attack control at the SAME seed / profile / clock, final 200\n");
    printf("    blocks: mean interval B = %.3f s, mean difficulty D = %.0f\n", B, D);
    printf("    recovery is declared at the first height h > %zu at which BOTH\n", ATTACK_H);
    printf("      (a) the trailing-100-block mean interval lies in [0.75B, 1.25B] = [%.2f, %.2f] s\n",
           0.75 * B, 1.25 * B);
    printf("      (b) the accepted difficulty lies in [0.75D, 1.25D] = [%.0f, %.0f]\n", 0.75 * D, 1.25 * D);
    printf("    and both hold for 100 CONSECUTIVE accepted blocks. Otherwise: NOT RECOVERED.\n\n");

    Sim s(SEED, Rule::Control, Strat::Alternating, PROFILES[1], 424.0, 1.0, 3, C);
    s.attack_until_height = ATTACK_H;
    s.run(TOTAL, true);
    int wt = s.winning_tip(), ht = s.honest_tip();
    std::vector<WinRow> rows = window_trace(s, wt);

    printf("  Chain: winning tip height %llu, honest-majority tip height %llu, %s\n",
           (unsigned long long)s.w.blocks[wt].height, (unsigned long long)s.w.blocks[ht].height,
           wt == ht ? "SAME chain" : "DIFFERENT chains -- the attacker is on a private branch");
    printf("  %zu blocks accepted, %zu rejected by their own producer.\n\n", s.accepted, s.rejected);

    printf("  %6s %10s %8s %8s %8s %7s %7s %10s %10s %12s %12s %9s %9s\n",
           "h", "T-T0", "manip", "m_raw", "m_cut", "cut_b", "cut_e",
           "raw_span", "eff_span", "d_raw", "d_accepted", "iv20", "iv100");
    double T0 = rows.empty() ? 0 : rows[0].T;
    for (size_t i = 0; i < rows.size(); ++i) {
        const WinRow &r = rows[i];
        bool show = (r.height <= 5) || (r.height >= ATTACK_H - 3 && r.height <= ATTACK_H + 12) ||
                    (r.height % 100 == 0) || (i + 3 >= rows.size());
        if (!show) continue;
        printf("  %6llu %10.1f %8s %8zu %8zu %7zu %7zu %10llu %10llu %12.0f %12.0f %9.2f %9.2f\n",
               (unsigned long long)r.height, r.T - T0, r.manip ? "yes" : "no",
               r.manip_raw, r.manip_cut, r.cut_begin, r.cut_end,
               (unsigned long long)r.raw_span, (unsigned long long)r.eff_span,
               r.d_raw, r.d_acc, r.iv20, r.iv100);
    }

    long rec_h = -1; size_t streak = 0;
    for (const WinRow &r : rows) {
        if (r.height <= ATTACK_H) continue;
        bool ok = r.iv100 > 0 && r.iv100 >= 0.75 * B && r.iv100 <= 1.25 * B &&
                  r.d_acc >= 0.75 * D && r.d_acc <= 1.25 * D;
        streak = ok ? streak + 1 : 0;
        if (streak >= 100) { rec_h = (long)r.height; break; }
    }
    printf("\n  RECOVERY: %s\n", rec_h < 0 ? "**NOT RECOVERED within 1200 honest blocks**"
                                           : "recovered");
    if (rec_h >= 0)
        printf("    first height meeting the pre-registered criterion for 100 consecutive blocks: %ld\n"
               "    that is %ld blocks after the attack stopped\n", rec_h, rec_h - (long)ATTACK_H);

    // how long do manipulated timestamps persist in the window at all?
    long last_raw = -1, last_cut = -1;
    for (const WinRow &r : rows) {
        if (r.manip_raw > 0) last_raw = (long)r.height;
        if (r.manip_cut > 0) last_cut = (long)r.height;
    }
    printf("    last height whose RAW 720-window still held a manipulated timestamp: %ld"
           " (%ld blocks after the stop)\n", last_raw, last_raw - (long)ATTACK_H);
    printf("    last height whose CUT range still held a manipulated timestamp: %ld"
           " (%ld blocks after the stop)\n", last_cut, last_cut - (long)ATTACK_H);
    printf("    window persistence alone predicts the raw window is clean by height %zu.\n",
           ATTACK_H + WINDOW);

    if (full_csv) {
        FILE *f = fopen("docs/recovery_trace.csv", "w");
        if (f) {
            fprintf(f, "height,T,ts,manipulated,manip_raw,manip_cut,cut_begin,cut_end,"
                       "raw_span,eff_span,cumwork_range,d_raw,d_accepted,iv20,iv100\n");
            for (const WinRow &r : rows)
                fprintf(f, "%llu,%.6f,%llu,%d,%zu,%zu,%zu,%zu,%llu,%llu,%.0f,%.0f,%.0f,%.4f,%.4f\n",
                        (unsigned long long)r.height, r.T, (unsigned long long)r.ts, r.manip ? 1 : 0,
                        r.manip_raw, r.manip_cut, r.cut_begin, r.cut_end,
                        (unsigned long long)r.raw_span, (unsigned long long)r.eff_span,
                        r.cumwork_range, r.d_raw, r.d_acc, r.iv20, r.iv100);
            fclose(f);
            printf("    per-block trace for all %zu heights written to docs/recovery_trace.csv\n",
                   rows.size());
        }
    }
    printf("\n");
}

// ================================================================================================
// ITEM 6 -- the 33 % cases at sigma 0 and 30
// ================================================================================================
static void collapse_investigation(size_t NSEED) {
    printf("ITEM 6 -- THE 33%% CASES AT sigma_offset 0 AND 30\n\n");
    printf("  Round 2 saw a collapse at sigma 0 and sigma 30 but not between, on ONE seed. Two\n");
    printf("  possible explanations were pre-registered before this run:\n");
    printf("    H1  it is real and mechanical -- some property of the cut span is non-monotonic\n");
    printf("        in clock dispersion;\n");
    printf("    H2  it is an artefact -- round 2 skipped the offset draw when sigma == 0, so the\n");
    printf("        sigma = 0 run used a different RNG stream, and one seed cannot separate a\n");
    printf("        mechanism from luck.\n");
    printf("  The stream is now aligned across sigma, so the sweep below varies dispersion only.\n\n");

    printf("  %zu seeds per sigma, 33%% attacker, cut-boundary strategy, localhost, 400 blocks.\n",
           NSEED);
    printf("  'collapse' = winning-chain mean interval below 6 s, one tenth of the %zu s target.\n\n",
           TARGET);
    printf("  %8s %12s %12s %12s %12s %10s %10s %10s\n", "sigma", "collapse%", "iv_p5", "iv_p50",
           "iv_p95", "rej_rate", "orph_rate", "split%");
    for (double so : {0.0, 0.5, 1.5, 2.0, 10.0, 30.0}) {
        ClockCfg c{ClockMode::PersistentNoise}; c.sigma_offset = so; c.sigma_noise = 2.0;
        std::atomic<size_t> ncol{0}, nsplit{0};
        std::vector<std::vector<double>> ivs(16); std::vector<std::vector<double>> rj(16), orp(16);
        std::vector<std::thread> th;
        size_t nth = 16;
        for (size_t t = 0; t < nth; ++t) th.emplace_back([&, t]() {
            for (size_t i = t; i < NSEED; i += nth) {
                Sim s(500000 + i, Rule::Control, Strat::CutBoundary, PROFILES[1], 424.0, 0.33, 3, c);
                s.run(400, false);
                int wt = s.winning_tip(), ht = s.honest_tip();
                double m = meanv(chain_intervals(s, wt));
                ivs[t].push_back(m);
                rj[t].push_back((double)s.rejected / (double)std::max<size_t>(1, s.accepted + s.rejected));
                size_t o = 0; for (auto &n : s.nodes) o += n.orphaned;
                orp[t].push_back((double)o / (double)std::max<size_t>(1, s.accepted));
                if (m < 6.0) ncol++;
                if (wt != ht) nsplit++;
            }
        });
        for (auto &x : th) x.join();
        std::vector<double> all, arj, aorp;
        for (auto &v : ivs) all.insert(all.end(), v.begin(), v.end());
        for (auto &v : rj) arj.insert(arj.end(), v.begin(), v.end());
        for (auto &v : orp) aorp.insert(aorp.end(), v.begin(), v.end());
        printf("  %8.1f %11.1f%% %12.2f %12.2f %12.2f %10.4f %10.4f %9.1f%%\n", so,
               100.0 * (double)ncol / (double)NSEED, qtile(all, .05), qtile(all, .50),
               qtile(all, .95), meanv(arj), meanv(aorp),
               100.0 * (double)nsplit / (double)NSEED);
    }

    printf("\n  Round 2's exact single-seed configuration, re-run with the round-3 clock:\n");
    printf("  %8s %14s %14s %10s %10s %8s\n", "sigma", "iv_chain", "iv_produced", "accepted",
           "rejected", "split");
    for (double so : {0.0, 0.5, 2.0, 10.0, 30.0}) {
        ClockCfg c{ClockMode::PersistentNoise}; c.sigma_offset = so; c.sigma_noise = 2.0;
        Sim s(9100, Rule::Control, Strat::CutBoundary, PROFILES[1], 424.0, 0.33, 3, c);
        s.run(140, false);
        int wt = s.winning_tip(), ht = s.honest_tip();
        double prod = (s.w.blocks.back().found_T - s.w.blocks[1].found_T) / (double)s.accepted;
        printf("  %8.1f %14.2f %14.2f %10zu %10zu %8s\n", so, meanv(chain_intervals(s, wt)), prod,
               s.accepted, s.rejected, wt == ht ? "no" : "YES");
    }

    // full per-block trace for the two extremes, plus the independent replay check
    printf("\n  Per-block traces for sigma 0 and sigma 30, attack stopping at height 300:\n");
    for (double so : {0.0, 30.0}) {
        ClockCfg c{ClockMode::PersistentNoise}; c.sigma_offset = so; c.sigma_noise = 2.0;
        Sim s(9100, Rule::Control, Strat::CutBoundary, PROFILES[1], 424.0, 0.33, 3, c);
        s.attack_until_height = 300;
        s.run(700, true);
        int wt = s.winning_tip(), ht = s.honest_tip();
        printf("\n  --- sigma_offset = %.1f ---\n", so);
        printf("  node clock offsets: ");
        for (auto &n : s.nodes) printf("%s%d=%+.3f ", n.attacker ? "ATK" : "hon", n.id, n.offset0);
        printf("\n  winning tip h=%llu, honest tip h=%llu, %s\n",
               (unsigned long long)s.w.blocks[wt].height, (unsigned long long)s.w.blocks[ht].height,
               wt == ht ? "same chain" : "SPLIT: honest nodes do not follow the winning tip");
        printf("  %6s %5s %10s %13s %11s %11s %8s %10s %6s %s\n",
               "h", "by", "solve_s", "ts", "median_lb", "ftl_upper", "acc", "difficulty",
               "branch", "decision / reject reason");
        size_t shown = 0;
        for (const Trace &t : s.trace) {
            bool near = (t.height >= 295 && t.height <= 310) || t.height <= 4 ||
                        (t.height % 100 == 0);
            if (!near || shown > 44) continue;
            ++shown;
            printf("  %6llu %5d %10.3f %13llu %11llu %11llu %8s %10.0f %6d %s%s\n",
                   (unsigned long long)t.height, t.producer, t.solve,
                   (unsigned long long)t.ts, (unsigned long long)t.median_lb,
                   (unsigned long long)t.ftl_upper, t.accepted ? "yes" : "NO", t.d, t.branch,
                   t.decision, t.why[0] ? (std::string(" | ") + t.why).c_str() : "");
        }
        // acceptance census: was every winning-chain block legal at a validator that is not its producer?
        std::vector<int> path = s.w.path_to(wt);
        size_t nobody = 0, some_reject = 0;
        for (size_t i = 1; i < path.size(); ++i) {
            auto it = s.census.find(path[i]);
            int acc = it == s.census.end() ? 0 : it->second.first;
            int rej = it == s.census.end() ? 0 : it->second.second;
            if (acc <= 1) ++nobody;          // only its own producer ever accepted it
            if (rej > 0) ++some_reject;
        }
        printf("  winning chain: %zu blocks; %zu were accepted by NO peer other than their producer;"
               " %zu were rejected by at least one peer\n", path.size() - 1, nobody, some_reject);
        // independent replay of the accepted history through the real function
        size_t chk = 0, bad = 0;
        for (size_t i = 2; i < path.size(); ++i) {
            std::vector<uint64_t> ts; std::vector<difficulty_type> cd;
            s.w.chain_back(path[i - 1], BLOCKS_COUNT, ts, cd);
            if (ts.size() < 2) continue;
            ++chk;
            if (cryptonote::next_difficulty(ts, cd, TARGET) != s.w.blocks[path[i]].d) ++bad;
        }
        printf("  independent replay through cryptonote::next_difficulty(): %zu heights, %zu"
               " mismatches -> %s\n", chk, bad, bad == 0 ? "PASS" : "FAIL");
        // legality census across every produced block
        size_t illegal = 0;
        for (const Trace &t : s.trace)
            if (t.accepted && t.lb_applies && t.ts < t.median_lb) ++illegal;
        printf("  produced blocks accepted despite violating their own producer's median bound: %zu\n",
               illegal);
    }
    printf("\n");
}

// ================================================================================================
// TASKS 5 AND 6 -- timestamp-rule candidates across launch hashrates, then the four combinations
// ================================================================================================
struct LaunchStats {
    double peak_diff = 0, worst_iv = 0, to_stable = -1, rej = 0, orph = 0, pinned_frac = 0;
    bool split = false;
};
static LaunchStats one_launch(uint64_t seed, TsRule ts, Rule rule, Strat st, double alpha,
                              double H, size_t nblocks, int nhonest, ClockCfg c) {
    g_ts_rule = ts;
    Sim s(seed, rule, st, PROFILES[P_LOCAL], H, alpha, nhonest, c);
    s.run(nblocks, false);
    int wt = s.winning_tip();
    std::vector<int> path = s.w.path_to(wt);
    LaunchStats r;
    r.split = (wt != s.honest_tip());
    size_t pinned = 0;
    for (size_t i = 1; i < path.size(); ++i) {
        double d = s.w.blocks[path[i]].d.convert_to<double>();
        r.peak_diff = std::max(r.peak_diff, d);
        if (d <= 10.0) ++pinned;
    }
    r.pinned_frac = path.size() > 1 ? (double)pinned / (double)(path.size() - 1) : 0;
    std::vector<double> iv = chain_intervals(s, wt);
    for (double x : iv) r.worst_iv = std::max(r.worst_iv, x);
    // time to stable: first height whose trailing-20 mean interval is within +-25% of target
    for (size_t i = 20; i < iv.size(); ++i) {
        double m = 0;
        for (size_t k = i - 20; k < i; ++k) m += iv[k];
        m /= 20.0;
        if (m >= 0.75 * (double)TARGET && m <= 1.25 * (double)TARGET) { r.to_stable = (double)i; break; }
    }
    r.rej = (double)s.rejected / (double)std::max<size_t>(1, s.accepted + s.rejected);
    size_t o = 0; for (auto &n : s.nodes) o += n.orphaned;
    r.orph = (double)o / (double)std::max<size_t>(1, s.accepted);
    return r;
}

struct LaunchAgg {
    std::vector<double> peak, worst, stable, rej, orph, pin;
    size_t nsplit = 0, nstall = 0, n = 0;
    void add(const LaunchStats &r) {
        peak.push_back(r.peak_diff); worst.push_back(r.worst_iv);
        if (r.to_stable >= 0) stable.push_back(r.to_stable); else ++nstall;
        rej.push_back(r.rej); orph.push_back(r.orph); pin.push_back(r.pinned_frac);
        if (r.split) ++nsplit;
        ++n;
    }
};
static LaunchAgg launch_sweep(TsRule ts, Rule rule, Strat st, double alpha, double Hmul,
                              size_t nseeds, size_t nblocks, ClockCfg c) {
    size_t nth = 16;
    std::vector<LaunchAgg> parts(nth);
    std::vector<std::thread> th;
    for (size_t t = 0; t < nth; ++t) th.emplace_back([&, t]() {
        for (size_t i = t; i < nseeds; i += nth)
            parts[t].add(one_launch(900000 + i, ts, rule, st, alpha, 424.0 * Hmul, nblocks, 3, c));
    });
    for (auto &x : th) x.join();
    LaunchAgg all;
    for (auto &p : parts) {
        all.peak.insert(all.peak.end(), p.peak.begin(), p.peak.end());
        all.worst.insert(all.worst.end(), p.worst.begin(), p.worst.end());
        all.stable.insert(all.stable.end(), p.stable.begin(), p.stable.end());
        all.rej.insert(all.rej.end(), p.rej.begin(), p.rej.end());
        all.orph.insert(all.orph.end(), p.orph.begin(), p.orph.end());
        all.pin.insert(all.pin.end(), p.pin.begin(), p.pin.end());
        all.nsplit += p.nsplit; all.nstall += p.nstall; all.n += p.n;
    }
    return all;
}
static void lrow(const char *label, const LaunchAgg &a) {
    std::string st = a.stable.empty() ? std::string("never")
                                      : std::to_string((long)qtile(a.stable, .5));
    printf("  %-44s %13.0f %10.1f %9s %8.4f %8.4f %8.1f%% %7.1f%%\n", label,
           qtile(a.peak, .5), qtile(a.worst, .5), st.c_str(),
           meanv(a.rej), meanv(a.orph), 100.0 * meanv(a.pin),
           100.0 * (double)a.nstall / (double)std::max<size_t>(1, a.n));
}
static void lhdr() {
    printf("  %-44s %13s %10s %9s %8s %8s %9s %8s\n", "setting",
           "peak_diff", "worst_iv", "to_stable", "reject", "orphan", "pinned", "never");
}

static void tscompare(size_t NSEED) {
    printf("TASKS 5 AND 6 -- TIMESTAMP-RULE CANDIDATES\n\n");
    printf("  %zu deterministic seeds per cell, 800 blocks, localhost profile, 3 honest miners.\n",
           NSEED);
    printf("  Columns are medians across seeds unless stated. 'pinned' = share of the winning chain\n");
    printf("  at difficulty <= 10. 'never' = share of seeds whose trailing-20 mean interval never\n");
    printf("  entered [45, 75] s within 800 blocks.\n\n");
    ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;

    printf("  --- A. HONEST LAUNCH ACROSS HASHRATE: does a candidate create a new stall? ---\n");
    lhdr();
    for (double m : {0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0}) {
        for (TsRule ts : {TsRule::Upstream, TsRule::T1T2, TsRule::T3b}) {
            char lbl[96]; snprintf(lbl, sizeof(lbl), "honest %gx  %s", m, ts_rule_name(ts));
            lrow(lbl, launch_sweep(ts, Rule::Control, Strat::Honest, 0.0, m, NSEED, 800, C));
        }
    }

    printf("\n  --- B. 100%% ATTACKER, alternating lowest/highest legal timestamp ---\n");
    lhdr();
    for (TsRule ts : {TsRule::Upstream, TsRule::T1T2}) {
        char lbl[96]; snprintf(lbl, sizeof(lbl), "100%% alternating  %s", ts_rule_name(ts));
        lrow(lbl, launch_sweep(ts, Rule::Control, Strat::Alternating, 1.0, 1.0, NSEED, 800, C));
    }
    printf("\n  --- C. 33%% ATTACKER, cut-boundary ---\n");
    lhdr();
    for (TsRule ts : {TsRule::Upstream, TsRule::T1T2}) {
        char lbl[96]; snprintf(lbl, sizeof(lbl), "33%% cut-boundary  %s", ts_rule_name(ts));
        lrow(lbl, launch_sweep(ts, Rule::Control, Strat::CutBoundary, 0.33, 1.0, NSEED, 800, C));
    }

    printf("\n  --- D. THE FOUR COMBINATIONS (task 6): is a difficulty bootstrap still needed? ---\n");
    struct Combo { const char *name; TsRule ts; Rule rule; };
    Combo combos[] = {
        {"current ts + current difficulty",      TsRule::Upstream, Rule::Control},
        {"T1+T2 ts   + current difficulty",      TsRule::T1T2,     Rule::Control},
        {"T1+T2 ts   + difficulty candidate A",  TsRule::T1T2,     Rule::A},
        {"T1+T2 ts   + difficulty candidate B",  TsRule::T1T2,     Rule::B},
    };
    struct Scen { const char *tag; Strat st; double alpha; double hmul; };
    Scen scens[] = {
        {"honest 1x",         Strat::Honest,      0.0,  1.0},
        {"honest 0.01x",      Strat::Honest,      0.0,  0.01},
        {"honest 100x",       Strat::Honest,      0.0,  100.0},
        {"100%% alternating", Strat::Alternating, 1.0,  1.0},
    };
    for (auto &sc : scens) {
        lhdr();
        for (auto &cb : combos) {
            char lbl[128]; snprintf(lbl, sizeof(lbl), "%s | %s", cb.name, sc.tag);
            lrow(lbl, launch_sweep(cb.ts, cb.rule, sc.st, sc.alpha, sc.hmul, NSEED, 800, C));
        }
        printf("\n");
    }
    g_ts_rule = TsRule::Upstream;
}

// ================================================================================================
// TASK 4 -- full launch-difficulty comparison under T1+T2
// ================================================================================================
// PINNED SHARE IS DEFINED HERE, BEFORE ANY RESULT IS PRODUCED:
//   pinned share = blocks on the FINAL WINNING CHAIN (genesis excluded) whose own difficulty is
//                  <= PIN_THRESHOLD, divided by the number of such blocks.
// PIN_THRESHOLD = 10: within one order of magnitude of the minimum possible difficulty of 1, and
// four orders below a healthy launch difficulty. pin_run is the longest consecutive streak.
static const double PIN_THRESHOLD = 10.0;
static const double STALL_SECONDS = 3600.0;   // a block interval above one hour counts as a stall

struct DiffStats {
    double peak = 0, lowest = 1e300, worst_iv = 0;
    double stable_blocks = -1, stable_secs = -1;
    double pinned_frac = 0, pin_run_blocks = 0, pin_run_secs = 0;
    double atk_block_share = 0, atk_work_share = 0;
    double orphan_rate = 0, reject_rate = 0, reorgs = 0, stalls = 0;
    bool hard_stall = false;      // the rule could not accept enough blocks at all
};
static DiffStats one_diff(uint64_t seed, TsRule ts, Rule rule, Strat st, double alpha,
                          double H, size_t nblocks, int nhonest, ClockCfg c,
                          double launch_off = 0.0) {
    g_ts_rule = ts;
    Sim s(seed, rule, st, PROFILES[P_LOCAL], H, alpha, nhonest, c, launch_off);
    s.run(nblocks, false);
    int wt = s.winning_tip();
    std::vector<int> path = s.w.path_to(wt);
    DiffStats r;
    size_t pinned = 0, run = 0, best_run = 0;
    double run_start_T = 0, best_run_secs = 0, atk_blocks = 0, atk_work = 0, all_work = 0;
    for (size_t i = 1; i < path.size(); ++i) {
        const Block &b = s.w.blocks[path[i]];
        double d = b.d.convert_to<double>();
        r.peak = std::max(r.peak, d);
        r.lowest = std::min(r.lowest, d);
        all_work += d;
        if (b.producer == 0) { atk_blocks += 1; atk_work += d; }
        if (d <= PIN_THRESHOLD) {
            if (run == 0) run_start_T = b.found_T;
            ++run; ++pinned;
            if (run > best_run) { best_run = run; best_run_secs = b.found_T - run_start_T; }
        } else run = 0;
    }
    size_t nb = path.size() > 1 ? path.size() - 1 : 1;
    r.pinned_frac = (double)pinned / (double)nb;
    r.pin_run_blocks = (double)best_run;
    r.pin_run_secs = best_run_secs;
    r.atk_block_share = atk_blocks / (double)nb;
    r.atk_work_share = all_work > 0 ? atk_work / all_work : 0;
    std::vector<double> iv = chain_intervals(s, wt);
    for (double x : iv) { r.worst_iv = std::max(r.worst_iv, x); if (x > STALL_SECONDS) r.stalls += 1; }
    for (size_t i = 20; i < iv.size(); ++i) {
        double m = 0; for (size_t k = i - 20; k < i; ++k) m += iv[k];
        m /= 20.0;
        if (m >= 0.75 * (double)TARGET && m <= 1.25 * (double)TARGET) {
            r.stable_blocks = (double)i;
            r.stable_secs = s.w.blocks[path[i]].found_T - s.w.blocks[path[1]].found_T;
            break;
        }
    }
    r.reject_rate = (double)s.rejected / (double)std::max<size_t>(1, s.accepted + s.rejected);
    size_t o = 0, rg = 0;
    for (auto &n : s.nodes) { o += n.orphaned; rg += n.reorgs; }
    r.orphan_rate = (double)o / (double)std::max<size_t>(1, s.accepted);
    r.reorgs = (double)rg;
    r.hard_stall = s.stalled;
    if (r.lowest > 1e299) r.lowest = 0;
    return r;
}

struct DiffAgg {
    std::vector<double> peak, lowest, worst, sb, ss, pin, prun, psec, abs_, aws, orph, rej, rg, stl;
    size_t nnever = 0, n = 0, nhardstall = 0;
    void add(const DiffStats &r) {
        if (r.hard_stall) ++nhardstall;
        peak.push_back(r.peak); lowest.push_back(r.lowest); worst.push_back(r.worst_iv);
        if (r.stable_blocks >= 0) { sb.push_back(r.stable_blocks); ss.push_back(r.stable_secs); }
        else ++nnever;
        pin.push_back(r.pinned_frac); prun.push_back(r.pin_run_blocks); psec.push_back(r.pin_run_secs);
        abs_.push_back(r.atk_block_share); aws.push_back(r.atk_work_share);
        orph.push_back(r.orphan_rate); rej.push_back(r.reject_rate);
        rg.push_back(r.reorgs); stl.push_back(r.stalls);
        ++n;
    }
    void merge(const DiffAgg &p) {
        auto A = [](std::vector<double> &d, const std::vector<double> &s2) {
            d.insert(d.end(), s2.begin(), s2.end()); };
        A(peak, p.peak); A(lowest, p.lowest); A(worst, p.worst); A(sb, p.sb); A(ss, p.ss);
        A(pin, p.pin); A(prun, p.prun); A(psec, p.psec); A(abs_, p.abs_); A(aws, p.aws);
        A(orph, p.orph); A(rej, p.rej); A(rg, p.rg); A(stl, p.stl);
        nnever += p.nnever; n += p.n; nhardstall += p.nhardstall;
    }
};
static DiffAgg diff_sweep(TsRule ts, Rule rule, Strat st, double alpha, double Hmul,
                          size_t nseeds, size_t nblocks, int nhonest, ClockCfg c,
                          double launch_off = 0.0) {
    size_t nth = 16;
    std::vector<DiffAgg> parts(nth);
    std::vector<std::thread> th;
    for (size_t t = 0; t < nth; ++t) th.emplace_back([&, t]() {
        for (size_t i = t; i < nseeds; i += nth)
            parts[t].add(one_diff(1300000 + i, ts, rule, st, alpha, 424.0 * Hmul, nblocks,
                                  nhonest, c, launch_off));
    });
    for (auto &x : th) x.join();
    DiffAgg all;
    for (auto &p : parts) all.merge(p);
    return all;
}
static void drow(const char *label, const DiffAgg &a) {
    std::string sb = a.sb.empty() ? std::string("never") : std::to_string((long)qtile(a.sb, .5));
    printf("  %-44s %12.0f %8.0f %9.1f %8s %8.0f %7.1f%% %7.0f %8.0f %7.1f%% %7.1f%% %7.4f %7.4f %5.1f %5.2f %6.1f%%\n",
           label, qtile(a.peak, .5), qtile(a.lowest, .5), qtile(a.worst, .5), sb.c_str(),
           a.ss.empty() ? 0.0 : qtile(a.ss, .5),
           100.0 * meanv(a.pin), qtile(a.prun, .5), qtile(a.psec, .5),
           100.0 * meanv(a.abs_), 100.0 * meanv(a.aws),
           meanv(a.orph), meanv(a.rej), meanv(a.rg), meanv(a.stl),
           100.0 * (double)a.nnever / (double)std::max<size_t>(1, a.n));
    if (a.nhardstall)
        printf("      ^^ %zu of %zu seeds HARD-STALLED: could not accept 800 blocks at all\n",
               a.nhardstall, a.n);
}
static void dhdr() {
    printf("  %-44s %12s %8s %9s %8s %8s %8s %7s %8s %8s %8s %7s %7s %5s %5s %7s\n",
           "setting", "peak_diff", "min_diff", "worst_iv", "stab_blk", "stab_s", "pinned",
           "pin_run", "pin_secs", "atk_blk", "atk_work", "orphan", "reject", "reorg",
           "stall", "never");
}

static void diffcompare(size_t NSEED) {
    printf("TASK 4 -- LAUNCH DIFFICULTY UNDER T1+T2\n\n");
    printf("  %zu deterministic seeds per cell, 800 blocks, localhost profile.\n", NSEED);
    printf("  PINNED SHARE, fixed before running: blocks on the final winning chain (genesis\n");
    printf("  excluded) whose own difficulty is <= %.0f, over the number of such blocks. pin_run and\n",
           PIN_THRESHOLD);
    printf("  pin_secs are the longest consecutive streak, in blocks and wall-clock seconds.\n");
    printf("  A 'stall' is any block interval above %.0f s. 'never' is the share of seeds whose\n",
           STALL_SECONDS);
    printf("  trailing-20 mean interval never entered [45, 75] s within 800 blocks.\n");
    printf("  Medians across seeds, except the rate columns which are means.\n\n");
    ClockCfg C; C.sigma_offset = 1.5; C.sigma_noise = 2.0;

    struct Combo { const char *name; TsRule ts; Rule rule; };
    Combo combos[] = {
        {"T1+T2 + current difficulty", TsRule::T1T2, Rule::Control},
        {"T1+T2 + cand A (2x cap h1-30)", TsRule::T1T2, Rule::A},
        {"T1+T2 + cand B (5 s/interval floor)", TsRule::T1T2, Rule::B},
        {"T1+T2 + A and B combined", TsRule::T1T2, Rule::C},
    };
    struct Scen { const char *tag; Strat st; double alpha; int nhonest; };
    Scen scens[] = {
        {"1 honest miner",        Strat::Honest,      0.00, 1},
        {"4 honest miners",       Strat::Honest,      0.00, 4},
        {"33% adaptive attacker", Strat::Alternating, 0.33, 3},
        {"51% attacker",          Strat::Alternating, 0.51, 3},
        {"100% attacker bound",   Strat::Alternating, 1.00, 3},
    };
    const double HM[] = {0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0};

    for (auto &sc : scens) {
        printf("=== %s ===\n\n", sc.tag);
        for (double m : HM) {
            dhdr();
            for (auto &cb : combos) {
                char lbl[160];
                snprintf(lbl, sizeof(lbl), "%gx | %s", m, cb.name);
                drow(lbl, diff_sweep(cb.ts, cb.rule, sc.st, sc.alpha, m, NSEED, 800, sc.nhonest, C));
            }
            printf("\n");
        }
    }
    g_ts_rule = TsRule::Upstream;
}


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

// ================================================================================================
int main(int argc, char **argv) {
    printf("MeepCoin network simulator (netsim), round 3   ANALYSIS ONLY\n");
    printf("=============================================================\n");
    printf("Clock split into persistent offset / drift / per-event noise / NTP corrections, each\n");
    printf("with a stated draw lifetime. Median lower bound matches Blockchain::check_block_timestamp\n");
    printf("including its below-60-blocks guard and the even-size epee median.\n");
    printf("Calibrated from docs/DAEMON_CALIBRATION.md and docs/LIVE_MEDIAN_BOUNDARY.md.\n\n");
    printf("NETWORK PROFILE BANDS, with provenance carried per profile:\n");
    printf("  %-22s %11s %11s %11s  %s\n", "profile", "prop_mean", "prop_sd", "proc", "provenance");
    for (size_t i = 0; i < NPROF; ++i)
        printf("  %-22s %9.2fms %9.2fms %9.2fms  %s\n", PROFILES[i].name,
               1000 * PROFILES[i].prop_mean, 1000 * PROFILES[i].prop_sd,
               1000 * PROFILES[i].proc, PROFILES[i].provenance);
    printf("  3 of %zu are measured on this host. The other 4 are assumptions and are never\n", NPROF);
    printf("  described as anything else.\n\n");

    std::string mode = (argc > 1) ? argv[1] : "all";
    size_t nseed = (argc > 2) ? (size_t)atoll(argv[2]) : 10000;
    size_t nblk  = (argc > 3) ? (size_t)atoll(argv[3]) : 800;

    invariants();
    if (g_fail) { printf("INVARIANTS FAILED (%d) -- nothing further produced.\n", g_fail); return 1; }

    if (mode == "clockspec"  || mode == "all") clockspec();
    if (mode == "degenerate" || mode == "all") degenerate_equivalence();
    if (mode == "sensitivity"|| mode == "all") honest_sensitivity(nseed, nblk);
    if (mode == "recovery"   || mode == "all") recovery_analysis(true);
    if (mode == "tscompare") { tscompare(nseed); return 0; }
    if (mode == "diffcompare") { diffcompare(nseed); return 0; }
    if (mode == "spancompare") { spancompare(nseed); return 0; }
    if (mode == "genesisage") { genesis_sweep(nseed); return 0; }
    if (mode == "spikeexplain") { spikeexplain(); return 0; }
    if (mode == "collapse"   || mode == "all") collapse_investigation(nseed < 2000 ? nseed : 2000);

    printf("=============================================================\n");
    printf("ANALYSIS ONLY. No consensus code changed.\n");
    return 0;
}
