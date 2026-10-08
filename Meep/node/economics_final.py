#!/usr/bin/env python3
"""MeepCoin final emission comparison — exact uint64 atomic-unit arithmetic.

APPROVED PARAMETERS (owner decisions):
    COIN          = 100,000,000,000 atomic units per MEEP        (11 decimals)
    MONEY_SUPPLY  = 2,500,000,000,000,000,000 atomic units       (25,000,000 MEEP)
    block target  = 60 seconds
    TAIL_REWARD   = 12,500,000,000 atomic units                  (0.125 MEEP) -- PROPOSED
    premine       = 0
    founder/dev   = 0
    fees          -> miners
    burned genesis reward accounted SEPARATELY from circulating supply

Consensus computation, reproduced exactly:

    base_reward = (MONEY_SUPPLY - already_generated_coins) >> EMISSION_SPEED_FACTOR
    if base_reward < TAIL_REWARD: base_reward = TAIL_REWARD
    already_generated_coins += base_reward

Integers throughout. Floats appear only in percentage columns.

PROPOSAL ONLY -- nothing here is implemented.
"""
from datetime import datetime, timedelta, timezone

UINT64_MAX     = 2**64 - 1
COIN           = 100_000_000_000
MONEY_SUPPLY   = 2_500_000_000_000_000_000
TAIL_REWARD    = 12_500_000_000
BLOCK_SECONDS  = 60
BLOCKS_PER_YEAR = 365 * 24 * 60 * 60 // BLOCK_SECONDS      # 525,600
BLOCKS_PER_DAY  = 24 * 60 * 60 // BLOCK_SECONDS            # 1,440
GENESIS_DATE    = datetime(2026, 7, 29, tzinfo=timezone.utc)

MARKS = [("1 day", BLOCKS_PER_DAY),
         ("30 days", BLOCKS_PER_DAY * 30),
         ("1 year", BLOCKS_PER_YEAR * 1),
         ("5 years", BLOCKS_PER_YEAR * 5),
         ("10 years", BLOCKS_PER_YEAR * 10),
         ("15 years", BLOCKS_PER_YEAR * 15),
         ("20 years", BLOCKS_PER_YEAR * 20),
         ("25 years", BLOCKS_PER_YEAR * 25)]
HORIZON = BLOCKS_PER_YEAR * 25


def meep(atomic):
    return f"{atomic // COIN:,}.{atomic % COIN:011d}"


def simulate(esf):
    """Exact consensus loop. Genesis (height 0) issues the first reward and is BURNED."""
    already = 0
    burned = 0
    tail_start = None
    snaps = {}
    want = {h for _, h in MARKS}

    # Height 0: the genesis coinbase claims the exact first reward. It is counted in emitted
    # supply (HF_VERSION_EXACT_COINBASE forbids a zero-value genesis) but is permanently
    # unspendable, so it never enters circulating supply.
    genesis_reward = (MONEY_SUPPLY - already) >> esf
    already += genesis_reward
    burned = genesis_reward

    for h in range(1, HORIZON + 1):
        base = (MONEY_SUPPLY - already) >> esf
        if base < TAIL_REWARD:
            base = TAIL_REWARD
            if tail_start is None:
                tail_start = (h, already)
        already += base
        if h in want:
            snaps[h] = (already, base)
    return {"genesis_reward": genesis_reward, "burned": burned, "total": already,
            "snaps": snaps, "tail_start": tail_start}


def annual_tail():
    return TAIL_REWARD * BLOCKS_PER_YEAR


def report(esf):
    r = simulate(esf)
    print(f"\n{'=' * 96}")
    print(f"## EMISSION SPEED FACTOR {esf}")
    print(f"{'=' * 96}")
    print(f"  initial (genesis) reward : {r['genesis_reward']:>22,} atomic = {meep(r['genesis_reward'])} MEEP")
    print(f"  burned genesis amount    : {r['burned']:>22,} atomic = {meep(r['burned'])} MEEP")

    ts = r["tail_start"]
    if ts:
        h, at = ts
        when = GENESIS_DATE + timedelta(seconds=h * BLOCK_SECONDS)
        circ = at - r["burned"]
        print(f"  tail-start block height  : {h:>22,}")
        print(f"  estimated tail-start date: {when.date()}")
        print(f"  emitted supply at tail   : {at:>22,} atomic = {meep(at)} MEEP")
        print(f"  circulating at tail      : {circ:>22,} atomic = {meep(circ)} MEEP")
        print(f"  vs nominal 25,000,000    : {at * 100 / MONEY_SUPPLY:.4f}% "
              f"(shortfall {meep(MONEY_SUPPLY - at)} MEEP, never issued by the main curve)")
        at_tail_infl = annual_tail() * 100 / at
        print(f"  tail inflation at start  : {at_tail_infl:.4f}%")
    else:
        print("  tail-start block height  : NOT REACHED within 25 years")
    print(f"  annual tail issuance     : {annual_tail():>22,} atomic = {meep(annual_tail())} MEEP")

    print(f"\n  {'elapsed':>9} | {'height':>11} | {'block reward (MEEP)':>22} | "
          f"{'emitted supply (MEEP)':>24} | {'circulating (MEEP)':>24}")
    print(f"  {'-'*9}-+-{'-'*11}-+-{'-'*22}-+-{'-'*24}-+-{'-'*24}")
    for label, h in MARKS:
        if h in r["snaps"]:
            cum, br = r["snaps"][h]
            print(f"  {label:>9} | {h:>11,} | {meep(br):>22} | {meep(cum):>24} | "
                  f"{meep(cum - r['burned']):>24}")

    # Reward at each yearly milestone (the value used to mine THAT block).
    print(f"\n  reward at milestones:")
    for y in (1, 5, 10, 15, 20, 25):
        h = BLOCKS_PER_YEAR * y
        if h in r["snaps"]:
            print(f"    year {y:>2}: {meep(r['snaps'][h][1])} MEEP")

    # Tail inflation at start, +5y and +20y after start.
    if ts:
        print(f"\n  tail inflation:")
        h0, at0 = ts
        for label, dy in (("at tail start", 0), ("5 years later", 5), ("20 years later", 20)):
            hh = h0 + BLOCKS_PER_YEAR * dy
            # supply at hh = supply at tail start + tail issuance for the elapsed blocks
            supply = at0 + TAIL_REWARD * (hh - h0)
            print(f"    {label:>14}: {annual_tail() * 100 / supply:.4f}%  "
                  f"(supply {meep(supply)} MEEP at height {hh:,})")
    return r


def main():
    print("=" * 96)
    print("MeepCoin FINAL emission comparison — exact uint64 atomic-unit arithmetic")
    print("PROPOSAL ONLY. Nothing implemented.")
    print("=" * 96)
    print(f"  COIN              = {COIN:,} atomic units per MEEP (11 decimals)")
    print(f"  MONEY_SUPPLY      = {MONEY_SUPPLY:,} atomic = {meep(MONEY_SUPPLY)} MEEP")
    print(f"  uint64 max        = {UINT64_MAX:,}  (MONEY_SUPPLY fits: "
          f"{MONEY_SUPPLY <= UINT64_MAX}, {MONEY_SUPPLY * 100 / UINT64_MAX:.2f}% of range)")
    print(f"  TAIL_REWARD       = {TAIL_REWARD:,} atomic = {meep(TAIL_REWARD)} MEEP per block")
    print(f"  block target      = {BLOCK_SECONDS} s  ->  {BLOCKS_PER_YEAR:,} blocks/year")
    print(f"  premine           = 0")
    print(f"  founder/developer = 0")
    print(f"  fees              = paid to miners (additional to the schedule below)")

    print(f"\n{'=' * 96}")
    print("## ROUNDING RULES (exact)")
    print(f"{'=' * 96}")
    print("  1. `>>` is an integer right shift: it TRUNCATES toward zero. The discarded fraction is")
    print("     never issued -- it is not carried, rounded up, or accumulated.")
    print("  2. Every block reward is therefore a whole number of atomic units; the maximum loss per")
    print("     block is < 1 atomic unit (1e-11 MEEP).")
    print("  3. Over 25 years (13,140,000 blocks) the cumulative truncation loss is bounded above by")
    print(f"     13,140,000 atomic units = {meep(13_140_000)} MEEP. Actual supply is therefore")
    print("     always marginally BELOW a continuous model.")
    print("  4. TAIL_REWARD is exact (12,500,000,000) and involves no rounding.")
    print("  5. The tail floor is applied AFTER the shift, so the transition block takes exactly")
    print("     TAIL_REWARD, not a blend.")

    results = {esf: report(esf) for esf in (20, 21, 22)}

    print(f"\n{'=' * 96}")
    print("## SIDE-BY-SIDE COMPARISON")
    print(f"{'=' * 96}")
    print(f"  {'metric':<32} | {'ESF 20':>24} | {'ESF 21':>24} | {'ESF 22':>24}")
    print(f"  {'-'*32}-+-{'-'*24}-+-{'-'*24}-+-{'-'*24}")

    def row(label, fn):
        vals = []
        for esf in (20, 21, 22):
            try:
                vals.append(fn(results[esf]))
            except Exception:
                vals.append("n/a")
        print(f"  {label:<32} | {vals[0]:>24} | {vals[1]:>24} | {vals[2]:>24}")

    row("initial reward (MEEP)", lambda r: meep(r["genesis_reward"]))
    for y in (1, 5, 10, 15, 20, 25):
        h = BLOCKS_PER_YEAR * y
        row(f"reward @ year {y} (MEEP)", lambda r, h=h: meep(r["snaps"][h][1]))
    row("emitted @ 1 day", lambda r: meep(r["snaps"][BLOCKS_PER_DAY][0]))
    row("emitted @ 30 days", lambda r: meep(r["snaps"][BLOCKS_PER_DAY * 30][0]))
    for y in (1, 5, 10, 15, 20, 25):
        h = BLOCKS_PER_YEAR * y
        row(f"emitted @ year {y}", lambda r, h=h: meep(r["snaps"][h][0]))
    row("tail-start height", lambda r: f"{r['tail_start'][0]:,}" if r["tail_start"] else ">25y")
    row("tail-start date", lambda r: str((GENESIS_DATE + timedelta(seconds=r["tail_start"][0] * BLOCK_SECONDS)).date())
        if r["tail_start"] else ">25y")
    row("supply at tail start", lambda r: meep(r["tail_start"][1]) if r["tail_start"] else "n/a")
    row("burned genesis (MEEP)", lambda r: meep(r["burned"]))
    row("circulating at tail start", lambda r: meep(r["tail_start"][1] - r["burned"]) if r["tail_start"] else "n/a")
    row("annual tail issuance", lambda r: meep(annual_tail()))
    row("tail inflation at start", lambda r: f"{annual_tail()*100/r['tail_start'][1]:.4f}%" if r["tail_start"] else "n/a")

    print(f"\n{'=' * 96}")
    print("## NOMINAL 25,000,000 vs ACTUAL SUPPLY AT TAIL START")
    print(f"{'=' * 96}")
    for esf in (20, 21, 22):
        r = results[esf]
        if r["tail_start"]:
            at = r["tail_start"][1]
            print(f"  ESF {esf}: {meep(at)} MEEP = {at*100/MONEY_SUPPLY:.4f}% of nominal; "
                  f"shortfall {meep(MONEY_SUPPLY - at)} MEEP never issued by the main curve.")
        else:
            print(f"  ESF {esf}: tail not reached within 25 years.")
    print("\n  The shortfall is structural, not rounding: the geometric curve crosses the tail floor")
    print("  before it converges to MONEY_SUPPLY. Supply then GROWS PAST 25,000,000 forever via the")
    print("  tail. MeepCoin is NOT hard-capped.")


if __name__ == "__main__":
    main()
