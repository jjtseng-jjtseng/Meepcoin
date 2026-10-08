#!/usr/bin/env python3
"""Make the wallet's hard-fork check work with a SPARSE fork schedule.

Monero's wallet validates each block's version with check_block_hard_fork_version(), which assumes
the hard-fork table is DENSE and INDEXED BY VERSION -- entry i describes version i+1:

    wallet_is_outdated = hf_version > wallet_num_hard_forks;          // 16 > 1  -> "outdated"
    start_height = wallet_hard_forks[hf_version - 1].height;          // index 15 of a 1-entry table

That holds for Monero, whose networks really did pass through versions 1..16 in order. MeepCoin has
a single entry {16, height 0}, so the wallet declared itself outdated on every block and refused to
scan:

    Unexpected hard fork version v16 at height 0. Make sure your wallet is up to date

Observed as a wallet stuck at height 1 with a zero balance while the daemon mined normally.

The replacement makes no density assumption: it finds the highest fork entry whose activation
height is <= the block's height and compares versions. For Monero's own dense tables this produces
identical results.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/wallet/wallet2.cpp")
MARK = "MeepCoin: sparse hard-fork schedule"

OLD = """  wallet_is_outdated = static_cast<size_t>(hf_version) > wallet_num_hard_forks;
  if (wallet_is_outdated)
    return;

  // check block's height falls within wallet's expected range for block's given version
  uint64_t start_height = hf_version == 1 ? 0 : wallet_hard_forks[hf_version - 1].height;
  uint64_t end_height = static_cast<size_t>(hf_version) + 1 > wallet_num_hard_forks
    ? std::numeric_limits<uint64_t>::max()
    : wallet_hard_forks[hf_version].height;

  daemon_is_outdated = height < start_height || height >= end_height;"""

NEW = """  // """ + MARK + """. The original implementation indexed the fork
  // table BY VERSION (wallet_hard_forks[hf_version - 1]), which assumes a dense 1..N schedule.
  // MeepCoin activates version 16 at height 0 with a single entry, so that indexing declared the
  // wallet outdated on every block and scanning never started. Search the table instead; for a
  // dense table this yields identical results.
  uint8_t max_known_version = 0;
  for (size_t i = 0; i < wallet_num_hard_forks; ++i)
    if (wallet_hard_forks[i].version > max_known_version)
      max_known_version = wallet_hard_forks[i].version;

  wallet_is_outdated = hf_version > max_known_version;
  if (wallet_is_outdated)
    return;

  // Expected version at this height: the highest fork entry whose activation height <= height.
  uint8_t expected_version = 0;
  for (size_t i = 0; i < wallet_num_hard_forks; ++i)
    if (wallet_hard_forks[i].height <= height && wallet_hard_forks[i].version > expected_version)
      expected_version = wallet_hard_forks[i].version;

  daemon_is_outdated = hf_version != expected_version;"""

s = open(P).read()
if MARK in s:
    print("= wallet hard-fork lookup already patched")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found in check_block_hard_fork_version")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ check_block_hard_fork_version now searches the table (sparse-schedule safe)")
print("WALLET_HARDFORK_LOOKUP_OK")
