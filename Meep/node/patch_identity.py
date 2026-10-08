#!/usr/bin/env python3
"""MeepCoin devnet identity + development chain parameters.

Applied to the pinned Monero v0.18.5.1 fork tree. Idempotent.

Every network-identity value differs from Monero's, so a MeepCoin node cannot peer with Monero and
MeepCoin addresses cannot be confused with Monero addresses.

ALL COINS ON THIS CHAIN ARE DEV/TEST COINS WITH NO MONETARY VALUE.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
CFG = "src/cryptonote_config.h"
results = []


def patch(path, old, new, label, required=True):
    p = os.path.join(ROOT, path)
    s = open(p).read()
    if new in s and old not in s:
        results.append((label, "already"))
        return True
    if old not in s:
        results.append((label, "ANCHOR MISSING" if required else "skipped"))
        return not required
    open(p, "w").write(s.replace(old, new, 1))
    results.append((label, "patched"))
    return True


ok = True

# --------------------------------------------------------------------------------------------
# Chain name and data directory: ~/.bitmonero -> ~/.meepcoin
# --------------------------------------------------------------------------------------------
ok &= patch(CFG, '#define CRYPTONOTE_NAME                         "bitmonero"',
                 '#define CRYPTONOTE_NAME                         "meepcoin"',
            "chain name / data dir -> meepcoin")

# --------------------------------------------------------------------------------------------
# Development chain parameters
#   block target 120 s -> 30 s          : faster local blocks
#   unlock window 60 -> 10 blocks       : the demo must SPEND a mined reward (requirement 13);
#                                         60 blocks makes that impractical at any local hashrate
# --------------------------------------------------------------------------------------------
ok &= patch(CFG, "#define DIFFICULTY_TARGET_V2                            120  // seconds",
                 "#define DIFFICULTY_TARGET_V2                            30  // seconds (MeepCoin devnet)",
            "block target 120s -> 30s")
ok &= patch(CFG, "#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60",
                 "#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            10  // MeepCoin devnet",
            "mined-money unlock window 60 -> 10")

# --------------------------------------------------------------------------------------------
# Network IDs — fresh UUIDs, distinct from Monero's in every byte position that matters.
# Monero uses 0x12,0x30,0xF1,0x71,... ("Bender's nightmare"); MeepCoin uses its own constant.
# --------------------------------------------------------------------------------------------
MONERO_ID = "0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x1"
MEEP_ID = "0x4D, 0x45, 0x45, 0x50, 0xC0, 0x1A, 0x4D, 0xE7, 0xB0, 0x0B, 0x5E, 0xED, 0x1A, 0xBE, 0x11, 0x0"
for slot, suffix in ((0, "mainnet-slot"), (1, "devnet"), (2, "stagenet-slot")):
    ok &= patch(CFG, MONERO_ID + str(slot), MEEP_ID + str(slot),
                f"NETWORK_ID {suffix}")

# --------------------------------------------------------------------------------------------
# Ports, address prefixes, genesis nonce.
#   mainnet slot  19080/1/2   prefixes 61/62/64   nonce 20000   (NOT launched; distinct so no
#                                                                config can land on Monero's)
#   devnet slot   29080/1/2   prefixes 71/72/74   nonce 20001   <- the demonstration network
#   stagenet slot 39080/1/2   prefixes 81/82/84   nonce 20002
# --------------------------------------------------------------------------------------------
PORTS = [
    # (monero_value, meep_value, label)
    ("uint16_t const P2P_DEFAULT_PORT = 18080;", "uint16_t const P2P_DEFAULT_PORT = 19080;", "mainnet-slot P2P"),
    ("uint16_t const RPC_DEFAULT_PORT = 18081;", "uint16_t const RPC_DEFAULT_PORT = 19081;", "mainnet-slot RPC"),
    ("uint16_t const ZMQ_RPC_DEFAULT_PORT = 18082;", "uint16_t const ZMQ_RPC_DEFAULT_PORT = 19082;", "mainnet-slot ZMQ"),
    ("uint16_t const P2P_DEFAULT_PORT = 28080;", "uint16_t const P2P_DEFAULT_PORT = 29080;", "devnet P2P"),
    ("uint16_t const RPC_DEFAULT_PORT = 28081;", "uint16_t const RPC_DEFAULT_PORT = 29081;", "devnet RPC"),
    ("uint16_t const ZMQ_RPC_DEFAULT_PORT = 28082;", "uint16_t const ZMQ_RPC_DEFAULT_PORT = 29082;", "devnet ZMQ"),
    ("uint16_t const P2P_DEFAULT_PORT = 38080;", "uint16_t const P2P_DEFAULT_PORT = 39080;", "stagenet-slot P2P"),
    ("uint16_t const RPC_DEFAULT_PORT = 38081;", "uint16_t const RPC_DEFAULT_PORT = 39081;", "stagenet-slot RPC"),
    ("uint16_t const ZMQ_RPC_DEFAULT_PORT = 38082;", "uint16_t const ZMQ_RPC_DEFAULT_PORT = 39082;", "stagenet-slot ZMQ"),
]
for old, new, label in PORTS:
    ok &= patch(CFG, old, new, label)

PREFIXES = [
    ("uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 18;",
     "uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 61;", "mainnet-slot addr prefix"),
    ("uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 19;",
     "uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 62;", "mainnet-slot integrated"),
    ("uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 42;",
     "uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 64;", "mainnet-slot subaddress"),
    ("uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53;",
     "uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 71;", "devnet addr prefix"),
    ("uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;",
     "uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 72;", "devnet integrated"),
    ("uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;",
     "uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 74;", "devnet subaddress"),
    ("uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;",
     "uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 81;", "stagenet-slot addr prefix"),
    ("uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;",
     "uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 82;", "stagenet-slot integrated"),
    ("uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;",
     "uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 84;", "stagenet-slot subaddress"),
]
for old, new, label in PREFIXES:
    ok &= patch(CFG, old, new, label)

# Genesis: a distinct GENESIS_NONCE yields a distinct genesis block hash. This mirrors how Monero
# itself distinguishes its own networks (mainnet/testnet share GENESIS_TX and differ only in nonce),
# so it is the upstream-sanctioned way to fork a new chain's genesis.
for old, new, label in (
    ("uint32_t const GENESIS_NONCE = 10000;", "uint32_t const GENESIS_NONCE = 20000;", "mainnet-slot genesis nonce"),
    ("uint32_t const GENESIS_NONCE = 10001;", "uint32_t const GENESIS_NONCE = 20001;", "devnet genesis nonce"),
    ("uint32_t const GENESIS_NONCE = 10002;", "uint32_t const GENESIS_NONCE = 20002;", "stagenet-slot genesis nonce"),
):
    ok &= patch(CFG, old, new, label)

# --------------------------------------------------------------------------------------------
# Binary names
# --------------------------------------------------------------------------------------------
ok &= patch("src/daemon/CMakeLists.txt", 'OUTPUT_NAME "monerod")', 'OUTPUT_NAME "meepcoind")',
            "daemon -> meepcoind")
ok &= patch("src/simplewallet/CMakeLists.txt", 'OUTPUT_NAME "monero-wallet-cli")',
            'OUTPUT_NAME "meepcoin-wallet-cli")', "wallet cli -> meepcoin-wallet-cli")
ok &= patch("src/wallet/CMakeLists.txt", 'OUTPUT_NAME "monero-wallet-rpc")',
            'OUTPUT_NAME "meepcoin-wallet-rpc")', "wallet rpc -> meepcoin-wallet-rpc")

width = max(len(l) for l, _ in results)
for label, status in results:
    flag = "!" if "MISSING" in status else "+"
    print(f"  {flag} {label.ljust(width)}  {status}")
print("IDENTITY_PATCH_OK" if ok else "IDENTITY_PATCH_FAILED")
sys.exit(0 if ok else 1)
