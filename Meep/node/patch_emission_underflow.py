#!/usr/bin/env python3
"""Fix an integer underflow in get_block_reward() that MeepCoin's economics make reachable.

    uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor;

Monero sets MONEY_SUPPLY = 2^64 - 1. already_generated_coins is a uint64, so it can never exceed
that, and the subtraction can never underflow. The expression is safe *because of* the constant.

MeepCoin sets MONEY_SUPPLY = 2,500,000,000,000,000,000 atomic AND pays a permanent tail reward of
12,500,000,000 atomic per block. Cumulative emission therefore passes MONEY_SUPPLY and keeps going.
From that block onward the subtraction underflows to a value near 2^64 and the shift produces a
huge reward instead of the tail.

Measured with meepcoin-emission-probe against the compiled rules, before this patch:

    already_generated_coins    reward atomic      reward MEEP
    MONEY_SUPPLY  (exact)      12500000000        0.12500000000     correct (the tail)
    MONEY_SUPPLY + 1           8796093022207      87.96093022207    703x the tail
    MONEY_SUPPLY + 1 MEEP      8796092974524      87.96092974524
    MONEY_SUPPLY + 1000 MEEP   8796045338492      87.96045338492

Projected activation, from iterating the real function: emitted supply reaches MONEY_SUPPLY at
height 11,655,417 (about 22.16 years at the 60-second target), so the defect would begin at height
11,655,418.

This is not an unapproved economics change. The approved rules are a 25,000,000 MEEP main-emission
parameter AND a permanent 0.125 MEEP tail; those two together require the emitted total to pass
MONEY_SUPPLY, so the reward function has to define what happens there. Left alone it defines
"emit 703x the tail forever", which is not what was approved.

Fix: clamp the subtraction. Once emission has reached MONEY_SUPPLY the main emission is finished, so
the base reward is 0 and the existing tail floor immediately below takes over. Behaviour at every
already_generated_coins < MONEY_SUPPLY is bit-for-bit unchanged, so no reward on the current chain
moves and no vector changes.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_basic/cryptonote_basic_impl.cpp")
MARK = "MeepCoin: MONEY_SUPPLY is reachable"

OLD = """    uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor;
    if (base_reward < FINAL_SUBSIDY_PER_MINUTE*target_minutes)
    {
      base_reward = FINAL_SUBSIDY_PER_MINUTE*target_minutes;
    }"""

NEW = """    // """ + MARK + """, unlike Monero's 2^64-1, and the permanent
    // tail reward means cumulative emission passes it (projected height 11,655,418, ~22.2 years at
    // the 60 s target). Without this clamp the subtraction underflows and base_reward becomes
    // ~8.796e12 atomic -- 703x the tail -- forever. Once emission reaches MONEY_SUPPLY the main
    // emission is over, so the base reward is 0 and the tail floor below takes over.
    uint64_t base_reward = already_generated_coins >= MONEY_SUPPLY
      ? 0
      : ((MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor);
    if (base_reward < FINAL_SUBSIDY_PER_MINUTE*target_minutes)
    {
      base_reward = FINAL_SUBSIDY_PER_MINUTE*target_minutes;
    }"""

s = open(P).read()
if MARK in s:
    print("= emission underflow already patched")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found in get_block_reward")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ clamped MONEY_SUPPLY - already_generated_coins against underflow")
print("EMISSION_UNDERFLOW_FIXED_OK")
