#!/usr/bin/env python3
"""HardFork must be constructed with MeepCoin's actual original version, not Monero's.

Blockchain::init constructs:

    HardFork(*db, 1, testnet_hard_fork_version_1_till)   // = (1, 624633)

Two inherited assumptions, both wrong for MeepCoin:

  * original_version = 1        -- MeepCoin has NO version-1 era; genesis is version 16.
  * original_version_till_height = 624633 (testnet) / 1009826 (mainnet) -- inherited from Monero's
    own history and never updated.

Consequence: HardFork::get_block_version(height) returns

    if (height <= original_version_till_height) return original_version;   // -> 1

i.e. **version 1 for every height up to 624,633** — the whole MeepCoin chain and then some.

Severity as found: that member function is currently NEVER CALLED (verified repo-wide), so this is
a latent trap rather than an active defect. It is patched anyway because the next caller added
would silently get version 1, and because the same `original_version` is used as the genesis-height
fallback in reorganize_from_block_height:

    const uint8_t start_version = height == 0 ? original_version : db.get_hard_fork_version(height);

Fix: construct with (CURRENT_BLOCK_MAJOR_VERSION, 0) on every network. MeepCoin has no pre-v16 era,
so the "original version" IS 16 and it applies from height 0.

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
P = os.path.join(ROOT, "src/cryptonote_core/blockchain.cpp")
MARK = "MeepCoin: no pre-v16 era"

OLD = """    if (m_nettype ==  FAKECHAIN || m_nettype == STAGENET)
      m_hardfork = new HardFork(*db, 1, 0);
    else if (m_nettype == TESTNET)
      m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);
    else
      m_hardfork = new HardFork(*db, 1, mainnet_hard_fork_version_1_till);"""

NEW = """    // """ + MARK + """, so the "original version" is 16 and it applies from
    // height 0. Upstream passed (1, <monero's version-1-till height>), which made
    // HardFork::get_block_version() report version 1 for every height below 624,633 on testnet --
    // the entire MeepCoin chain. That member is currently uncalled, so this is hardening against
    // the next caller rather than a fix for observed breakage.
    m_hardfork = new HardFork(*db, CURRENT_BLOCK_MAJOR_VERSION, 0);
    (void)testnet_hard_fork_version_1_till;
    (void)mainnet_hard_fork_version_1_till;"""

s = open(P).read()
if MARK in s:
    print("= HardFork construction already patched")
    sys.exit(0)
if OLD not in s:
    print("! anchor not found in Blockchain::init")
    sys.exit(1)
open(P, "w").write(s.replace(OLD, NEW, 1))
print("+ HardFork constructed with (CURRENT_BLOCK_MAJOR_VERSION, 0) on every network")
print("HARDFORK_ORIGINAL_VERSION_OK")
