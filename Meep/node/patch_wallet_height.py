#!/usr/bin/env python3
"""MeepCoin devnet: make new wallets scan from genesis.

Monero's wallet2::get_approximate_blockchain_height() extrapolates from the inherited hard-fork
height/time tables and returns roughly 1.45M for TESTNET. A freshly created wallet sets its
refresh-from-block height to that estimate, so on a chain only a few hundred blocks tall it scans
nothing and reports a zero balance -- even after mining the coinbase itself. Observed directly:

    ERROR wallet.wallet2 src/wallet/wallet2.cpp:3961  Blocks start before blockchain offset: 0 1450000

MeepCoin has no long history to estimate, so scan from genesis. This touches only the wallet's
scan-start heuristic; it is NOT consensus code and does not affect block validation.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/wallet/wallet2.cpp")

MARK = "MeepCoin devnet: scan from genesis"
ANCHOR = (
    "uint64_t wallet2::get_approximate_blockchain_height() const\n"
    "{\n"
    "  const size_t wallet_num_hard_forks"
)
REPL = (
    "uint64_t wallet2::get_approximate_blockchain_height() const\n"
    "{\n"
    "  // " + MARK + ". The inherited estimate extrapolates from Monero's\n"
    "  // hard-fork tables and yields ~1.45M for TESTNET; a new wallet would then start scanning\n"
    "  // above our chain tip and report a zero balance despite having mined the coinbase.\n"
    "  // Scan-start heuristic only -- NOT consensus.\n"
    "  return 0;\n"
    "\n"
    "  const size_t wallet_num_hard_forks"
)

s = open(P).read()
if MARK in s:
    print("= wallet scan-start already patched")
elif ANCHOR in s:
    open(P, "w").write(s.replace(ANCHOR, REPL, 1))
    print("+ get_approximate_blockchain_height -> 0 (scan from genesis)")
else:
    print("! anchor not found in wallet2.cpp")
    sys.exit(1)
