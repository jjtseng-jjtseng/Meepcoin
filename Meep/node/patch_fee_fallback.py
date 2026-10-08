#!/usr/bin/env python3
"""Make the wallet's fee fallback scale-aware, anchored to what the constant actually MEANS.

AUDIT FINDING -- the premise that a decimal change requires rescaling this constant by 10 is
arithmetically right but semantically wrong, and acting on it would introduce a bug.

FEE_PER_BYTE is the value the WALLET falls back to when the daemon's dynamic-fee RPC fails
(wallet2.cpp:8573, :8611, :8616 -- all three sites are wallet-side; it appears nowhere in consensus).
Its job is to be a fee the network will still accept. So its meaning is a SAFETY MARGIN ABOVE THE
NETWORK MINIMUM, not an amount of coin.

The v16 network minimum is reward-derived, not decimal-derived. Reproducing
Blockchain::get_dynamic_base_fee exactly (HF_VERSION_2021_SCALING branch):

    lo = block_reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT
    lo /= median_block_weight            (clamped to >= min_block_weight == 300000 at v16)
    lo /= median_block_weight
    lo -= lo / 20                        (the 0.95)

    Monero,   reward 0.6 XMR  = 600,000,000,000 atomic  ->  min fee    19,000 atomic/byte
              FEE_PER_BYTE = 300,000                    ->  margin      15.79x
    MeepCoin, reward           1,192,092,895,507 atomic  ->  min fee    37,750 atomic/byte
              daemon's live estimate (measured)                         40,000 atomic/byte

MeepCoin's per-block reward is ~20x Monero's in COIN terms (11.92 MEEP vs 0.6 XMR), so its
reward-derived minimum is HIGHER in atomic terms even at one fewer decimal. Rescaling the fallback
DOWN by 10 therefore moves it the wrong way:

    proposed 30,000  ->  0.75x the 40,000 minimum  ->  BELOW IT. Transactions priced with this
                         fallback would be rejected for insufficient fee.
    current 300,000  ->  7.50x  -> still safe, merely less conservative than Monero's 15.79x
    15x reference    ->  14.16x -> preserves Monero's actual semantics

So the constant is not currently broken. What it lacks is any expression of WHY it is that number,
which is what let a plausible-looking rescale to 30,000 look correct.

FIX: derive it from the same reward-based reference the daemon uses, with the margin named. A future
change to decimals, COIN, MONEY_SUPPLY, the emission factor or the block target now moves the
fallback with the minimum automatically, and the margin stays explicit.

Wallet fee estimation only. No consensus rule, no daemon behaviour, and the normal dynamic-fee path
is untouched -- the fallback is reached only when the daemon RPC has already failed.

Idempotent.
"""
import os, re, sys

ROOT = os.path.expanduser("~/meepcoin-node")
CFG = os.path.join(ROOT, "src/cryptonote_config.h")
MARK = "MeepCoin: the wallet's fee fallback is derived"

OLD = "#define FEE_PER_BYTE                                    ((uint64_t)300000)\n"

# The definition has to MOVE, not just change: DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT is declared
# four lines below the old FEE_PER_BYTE, so a derived macro defined in place would have expanded with
# an empty token and compiled to something meaningless. The ordering guard at the bottom of this
# script exists because that is exactly what the first attempt did.
ANCHOR_AFTER = "#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT         ((uint64_t)3000)\n"

NEW = '''
// ''' + MARK + ''' from the same reward-based reference the
// daemon uses, not from COIN. See node/patch_fee_fallback.py for the audit.
//
// FEE_PER_BYTE is what wallet2 falls back to when the daemon's dynamic-fee RPC fails. Its meaning
// is a safety margin above the network minimum -- NOT an amount of coin. The v16 minimum is
// reward-derived (Blockchain::get_dynamic_base_fee, HF_VERSION_2021_SCALING branch), so rescaling
// this constant when the decimal point changes moves it independently of the thing it must exceed.
// Concretely: Monero's 300,000 sits 15.79x above its 19,000/byte minimum, while MeepCoin's minimum
// is 37,750/byte because its block reward is ~20x Monero's in coin terms. A naive "one fewer
// decimal, so divide by ten" would give 30,000 -- BELOW the minimum, and every transaction priced
// with it would be rejected for insufficient fee.
//
// The reference below mirrors get_dynamic_base_fee's integer arithmetic exactly, evaluated at the
// INITIAL block reward. That is the safe anchor: the reward only falls and the median only grows,
// and both push the minimum down, so a fallback safe at genesis stays safe.
#define MEEPCOIN_EFFECTIVE_EMISSION_SHIFT \\
  (EMISSION_SPEED_FACTOR_PER_MINUTE - (DIFFICULTY_TARGET_V2 / 60 - 1))
#define MEEPCOIN_INITIAL_BLOCK_REWARD \\
  (MONEY_SUPPLY >> MEEPCOIN_EFFECTIVE_EMISSION_SHIFT)
// reward * ref_weight / median / median, with median == min_block_weight at v16
#define MEEPCOIN_FEE_REFERENCE_RAW \\
  (MEEPCOIN_INITIAL_BLOCK_REWARD * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT \\
   / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
// the daemon's 0.95, written as (x - x/20) so the integer truncation matches bit for bit
#define MEEPCOIN_FEE_REFERENCE_PER_BYTE \\
  (MEEPCOIN_FEE_REFERENCE_RAW - MEEPCOIN_FEE_REFERENCE_RAW / 20)
// Monero's effective margin, rounded to an integer and stated rather than implied.
#define MEEPCOIN_FEE_FALLBACK_MARGIN                    15
#define FEE_PER_BYTE \\
  ((uint64_t)(MEEPCOIN_FEE_REFERENCE_PER_BYTE * MEEPCOIN_FEE_FALLBACK_MARGIN))'''

s = open(CFG).read()
if MARK in s:
    print("= fee fallback already derived")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found: FEE_PER_BYTE definition")
    sys.exit(1)
if ANCHOR_AFTER not in s:
    print("! anchor not found: DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT definition")
    sys.exit(1)

DEPS = ("DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT",
        "CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5",
        "EMISSION_SPEED_FACTOR_PER_MINUTE", "MONEY_SUPPLY", "DIFFICULTY_TARGET_V2")

# Remove the old definition, then re-insert the derived one after whichever dependency is defined
# LAST. Anchoring on a guessed neighbour is what produced two failed attempts: the dependencies are
# scattered across the file (the block-target macros sit well below the fee block).
s = s.replace(OLD, "", 1)

last_end = -1
last_name = None
for dep in DEPS:
    m = re.search(r"^#define\s+" + dep + r"\b.*$", s, re.MULTILINE)
    if not m:
        print(f"! dependency {dep} not found")
        sys.exit(1)
    if m.end() > last_end:
        last_end, last_name = m.end(), dep
print(f"  last dependency in file order: {last_name}")

# Advance past any comment lines that belong to that dependency, so the insertion does not orphan a
# NOTE from the #define it explains (DIFFICULTY_TARGET_V2 has a multi-line note under it).
while True:
    nl = s.find("\n", last_end)
    if nl == -1:
        break
    nxt_end = s.find("\n", nl + 1)
    line = s[nl + 1: nxt_end if nxt_end != -1 else len(s)]
    if line.lstrip().startswith("//"):
        last_end = nxt_end if nxt_end != -1 else len(s)
    else:
        break

s = s[:last_end] + "\n" + NEW + s[last_end:]

# Every dependency must now be defined BEFORE the new definition, or the macro expands to
# something meaningless that still compiles. Verify rather than trust the placement.
i_fee = s.index("#define FEE_PER_BYTE")
for dep in ("DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT",
            "CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5",
            "EMISSION_SPEED_FACTOR_PER_MINUTE", "MONEY_SUPPLY", "DIFFICULTY_TARGET_V2"):
    m = re.search(r"#define\s+" + dep + r"\b", s)
    if not m:
        print(f"! dependency {dep} not found")
        sys.exit(1)
    if m.start() > i_fee:
        print(f"! dependency {dep} is still defined AFTER FEE_PER_BYTE; the macro would not "
              f"expand. Refusing to ship a silently-broken constant.")
        sys.exit(1)

open(CFG, "w").write(s)
print("+ FEE_PER_BYTE derived from the reward-based reference x MEEPCOIN_FEE_FALLBACK_MARGIN")
print("FEE_FALLBACK_DERIVED_OK")
