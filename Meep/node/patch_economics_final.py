#!/usr/bin/env python3
"""Install the approved MeepCoin development-chain economics.

Approved by the project owner for the private development chain:

    decimal places          11
    COIN                    100,000,000,000                 (10^11)
    main-emission parameter 25,000,000 MEEP
    MONEY_SUPPLY            2,500,000,000,000,000,000        (2.5 x 10^18 atomic)
    block target            60 seconds                       (already installed)
    emission speed factor   21 effective at the 60 s target
    initial reward          1,192,092,895,507 atomic         (= MONEY_SUPPLY >> 21)
    permanent tail reward   0.125 MEEP per block
    FINAL_SUBSIDY_PER_MINUTE 12,500,000,000 atomic           (per 60 s block, target_minutes == 1)
    premine                 0
    founder/developer       0
    fees                    paid to miners
    dev unlock window       10 blocks                        (already installed)
    future mainnet unlock   60 blocks                        (NOT installed; proposal only)

Supply wording that must be used: approximately 25 million MEEP of main emission, followed by
permanent tail emission of 0.125 MEEP per block. MeepCoin is NOT hard-capped.

get_block_reward() derives the shift from the block target:

    emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1)
                          = 21 - (1 - 1) = 21
    base_reward           = (MONEY_SUPPLY - already_generated_coins) >> 21
                          = 2500000000000000000 >> 21 = 1192092895507       at genesis

and the tail floor as FINAL_SUBSIDY_PER_MINUTE * target_minutes = 12,500,000,000 * 1.

The reward function itself is NOT modified. Only the constants it reads.

NOT CHANGED, deliberately: the inherited fee constants (FEE_PER_KB, FEE_PER_BYTE,
DYNAMIC_FEE_PER_KB_BASE_FEE, DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, ...). Those are absolute
atomic-unit figures Monero calibrated against 12 decimals, so at 11 decimals each denotes ten times
as much MEEP as the equivalent XMR amount. Retuning them is an economics decision that was not
approved, so it is reported rather than performed. See docs/DECIMAL_AUDIT.md.

Idempotent.
"""
import os, re, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_config.h")
MARK = "MeepCoin approved economics"

SUBS = [
    # (regex, replacement, label)
    (r'#define MONEY_SUPPLY\s+\(\(uint64_t\)\(-1\)\)',
     '#define MONEY_SUPPLY                                    ((uint64_t)2500000000000000000) '
     '// MeepCoin approved economics: 25,000,000 MEEP main-emission parameter at 11 decimals',
     'MONEY_SUPPLY'),

    (r'#define EMISSION_SPEED_FACTOR_PER_MINUTE\s+\(20\)',
     '#define EMISSION_SPEED_FACTOR_PER_MINUTE                (21) '
     '// effective shift 21 at the 60 s target',
     'EMISSION_SPEED_FACTOR_PER_MINUTE'),

    (r'#define FINAL_SUBSIDY_PER_MINUTE\s+\(\(uint64_t\)300000000000\)[^\n]*',
     '#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)12500000000) '
     '// 0.125 MEEP permanent tail per 60 s block (target_minutes == 1, so this IS the per-block tail)',
     'FINAL_SUBSIDY_PER_MINUTE'),

    (r'#define CRYPTONOTE_DISPLAY_DECIMAL_POINT\s+12',
     '#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                11  // MeepCoin: 11 decimals',
     'CRYPTONOTE_DISPLAY_DECIMAL_POINT'),

    (r'#define COIN\s+\(\(uint64_t\)1000000000000\)[^\n]*',
     '#define COIN                                            ((uint64_t)100000000000) '
     '// pow(10, 11) -- MeepCoin: 11 decimals',
     'COIN'),
]

OLD_TARGET_NOTE = """// 60 s is therefore the fastest legal block target; it also moves the emission speed factor
// from 19 (at Monero-s 120 s) to 20, which halves the per-block reward. Intentional: dev coins."""
NEW_TARGET_NOTE = """// 60 s is therefore the fastest legal block target. With EMISSION_SPEED_FACTOR_PER_MINUTE = 21
// the effective shift is 21 - (1 - 1) = 21. Note this coupling: changing the block target changes
// emission. It is not economically neutral."""

s = open(P).read()
if MARK in s:
    print("= approved economics already installed")
    sys.exit(0)

for pat, rep, label in SUBS:
    s, n = re.subn(pat, rep, s, count=1)
    if n != 1:
        print(f"! anchor not found: {label}")
        sys.exit(1)
    print(f"+ {label}")

if OLD_TARGET_NOTE in s:
    s = s.replace(OLD_TARGET_NOTE, NEW_TARGET_NOTE, 1)
    print("+ corrected the block-target comment (shift is now 21, not 20)")

open(P, "w").write(s)
print("ECONOMICS_INSTALLED_OK")
