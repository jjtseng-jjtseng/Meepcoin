#!/usr/bin/env python3
"""MeepCoin emission projection — exact integer atomic-unit arithmetic.

Mirrors the consensus computation exactly (Monero's get_block_reward):

    base_reward = (MONEY_SUPPLY - already_generated_coins) >> EMISSION_SPEED_FACTOR
    if base_reward < TAIL_REWARD: base_reward = TAIL_REWARD

Every value below is an integer number of atomic units. No floating point is used anywhere in the
emission path; floats appear only when formatting a human-readable column.

PROPOSAL ONLY. Nothing here is implemented in consensus.
"""
from datetime import datetime, timedelta, timezone

# ---- inherited representation limit -------------------------------------------------------------
UINT64_MAX = 2**64 - 1          # Monero's money type is uint64; MONEY_SUPPLY cannot exceed this

BLOCK_SECONDS = 60
BLOCKS_PER_YEAR = 365 * 24 * 60 * 60 // BLOCK_SECONDS       # 525,600
GENESIS = datetime(2026, 7, 29, tzinfo=timezone.utc)


def coin(decimals):
    return 10 ** decimals


def simulate(money_supply, esf, tail, horizon_blocks, marks):
    """Run the exact consensus loop. Returns (already, per-mark snapshots, tail-start info)."""
    already = 0
    tail_start = None
    snaps = {}
    marks = sorted(marks)
    mi = 0
    for h in range(1, horizon_blocks + 1):
        base = (money_supply - already) >> esf
        if base < tail:
            base = tail
            if tail_start is None:
                tail_start = (h, already)
        already += base
        while mi < len(marks) and h == marks[mi]:
            snaps[h] = (already, base)
            mi += 1
    return already, snaps, tail_start


def fmt(atomic, c):
    return f"{atomic // c:,}.{atomic % c:0{len(str(c)) - 1}d}"


def main():
    print("=" * 78)
    print("MeepCoin emission projection — exact integer atomic units")
    print("=" * 78)

    # ---- Feasibility of the requested parameters -------------------------------------------------
    print("\n## Representability check (this constrains everything else)\n")
    target_meep = 25_000_000
    for dec in (12, 11, 10):
        c = coin(dec)
        need = target_meep * c
        fits = need <= UINT64_MAX
        print(f"  decimals={dec:2d}  25,000,000 MEEP = {need:,} atomic units  "
              f"{'FITS' if fits else 'DOES NOT FIT'} in uint64")
    print(f"\n  uint64 maximum                    = {UINT64_MAX:,} atomic units")
    print(f"  at 12 decimals that is            = {UINT64_MAX / 10**12:,.6f} MEEP")
    print("  -> 25,000,000 MEEP at 12 decimals is NOT REPRESENTABLE in the inherited money type.")

    # ---- Options ---------------------------------------------------------------------------------
    options = [
        ("A: 11 decimals, 25M target", 11, 25_000_000, 21),
        ("B: 12 decimals, 18.4M cap ", 12, None, 21),
    ]
    print("\n## Candidate parameter sets\n")
    for label, dec, tgt, esf in options:
        c = coin(dec)
        ms = tgt * c if tgt else UINT64_MAX
        print(f"  {label}: COIN=10^{dec}, MONEY_SUPPLY={ms:,} atomic "
              f"({ms / c:,.4f} MEEP), ESF={esf}")

    # ---- APPROVED PARAMETERS (owner decision): 11 decimals, 25,000,000 main-emission target -----
    DEC = 11
    C = coin(DEC)
    MONEY_SUPPLY = 25_000_000 * C
    TAIL = 125_000_000_000 // (10 ** (12 - DEC))       # 0.125 MEEP expressed at DEC decimals

    print(f"\n{'=' * 78}\n## Option A detail — 11 decimals, MONEY_SUPPLY 25,000,000 MEEP\n{'=' * 78}")
    print(f"  COIN            = {C:,} atomic units per MEEP")
    print(f"  MONEY_SUPPLY    = {MONEY_SUPPLY:,} atomic ({MONEY_SUPPLY / C:,.0f} MEEP)")
    print(f"  TAIL_REWARD     = {TAIL:,} atomic ({TAIL / C} MEEP) per block")
    print(f"  BLOCK_SECONDS   = {BLOCK_SECONDS}, blocks/year = {BLOCKS_PER_YEAR:,}")

    year_marks = [BLOCKS_PER_YEAR * y for y in (1, 5, 10, 15, 20, 25)]
    marks = sorted(set([BLOCKS_PER_YEAR // 365, BLOCKS_PER_YEAR // 12] + year_marks))
    horizon = BLOCKS_PER_YEAR * 25

    for esf in (20, 21, 22):
        total, snaps, tstart = simulate(MONEY_SUPPLY, esf, TAIL, horizon, marks)
        first = (MONEY_SUPPLY - 0) >> esf
        print(f"\n### ESF = {esf}")
        print(f"  initial base reward = {first:,} atomic = {fmt(first, C)} MEEP")
        if tstart:
            h, at = tstart
            when = GENESIS + timedelta(seconds=h * BLOCK_SECONDS)
            print(f"  tail begins at height {h:,} (~{when.date()}), supply then "
                  f"{fmt(at, C)} MEEP ({at * 100 / MONEY_SUPPLY:.3f}% of nominal)")
        else:
            print("  tail not reached within 25 years")
        annual_tail = TAIL * BLOCKS_PER_YEAR
        print(f"  annual tail issuance = {fmt(annual_tail, C)} MEEP")
        print(f"  {'elapsed':>10} | {'height':>12} | {'block reward':>18} | {'cumulative supply':>22}")
        print(f"  {'-'*10}-+-{'-'*12}-+-{'-'*18}-+-{'-'*22}")
        labels = [(BLOCKS_PER_YEAR // 365, '1 day'), (BLOCKS_PER_YEAR // 12, '1 month')] + \
                 [(BLOCKS_PER_YEAR * y, f'{y} year' + ('s' if y > 1 else '')) for y in (1, 5, 10, 15, 20, 25)]
        for h, lab in labels:
            if h in snaps:
                cum, br = snaps[h]
                print(f"  {lab:>10} | {h:>12,} | {fmt(br, C):>18} | {fmt(cum, C):>22}")
        # tail inflation at milestones
        print(f"  tail inflation:", end=' ')
        infl = []
        for h, lab in labels:
            if h in snaps and tstart and h >= tstart[0]:
                cum, _ = snaps[h]
                infl.append(f"{lab} {annual_tail * 100 / cum:.3f}%")
        print(', '.join(infl) if infl else '(tail not yet started at any milestone)')

    # ---- ESF comparison table --------------------------------------------------------------------
    print(f"\n{'=' * 78}\n## Emission speed factor comparison (11 decimals, 25M, 0.125 tail)\n{'=' * 78}")
    print(f"  {'ESF':>4} | {'initial reward':>16} | {'reward @1y':>14} | {'reward @5y':>14} | "
          f"{'supply @10y':>16} | {'tail height':>12}")
    print(f"  {'-'*4}-+-{'-'*16}-+-{'-'*14}-+-{'-'*14}-+-{'-'*16}-+-{'-'*12}")
    for esf in (20, 21, 22):
        total, snaps, tstart = simulate(MONEY_SUPPLY, esf, TAIL, horizon, marks)
        first = MONEY_SUPPLY >> esf
        r1 = snaps[BLOCKS_PER_YEAR][1]
        r5 = snaps[BLOCKS_PER_YEAR * 5][1]
        s10 = snaps[BLOCKS_PER_YEAR * 10][0]
        th = f"{tstart[0]:,}" if tstart else '>25y'
        print(f"  {esf:>4} | {fmt(first, C):>16} | {fmt(r1, C):>14} | {fmt(r5, C):>14} | "
              f"{fmt(s10, C):>16} | {th:>12}")


if __name__ == '__main__':
    main()
