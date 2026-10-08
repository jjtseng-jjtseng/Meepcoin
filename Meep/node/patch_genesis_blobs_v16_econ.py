#!/usr/bin/env python3
"""Install the regenerated v16 genesis coinbases for the approved economics.

HF_VERSION_EXACT_COINBASE (13) requires the genesis coinbase output to equal
get_block_reward(0, 0, 0, ., 16) exactly. Changing MONEY_SUPPLY from 2^64-1 to 2.5e18 and the
emission speed factor from 20 to 21 moves that from 17,592,186,044,415 to 1,192,092,895,507 atomic,
so the previous genesis coinbase is now invalid and the daemon will not start until it is replaced.

Each blob was produced by:

    meepcoin-genesis16 gen <context-label> 1192092895507 <nonce> 1785283200

    config slot   context label   nonce
    mainnet       mainnet         20000
    testnet       devnet          20001     <-- the slot the private devnet runs on
    stagenet      stagenet        20002

The burn-key construction is unchanged: B and A are hash-to-point images of published
nothing-up-my-sleeve context strings with no known discrete log, r is published and does not enable
spending, and P = Hs(r*A || 0)*G + B. None of those inputs mention an amount, so for the testnet
slot B, A, r, R, P and the view tag are byte-identical to the previous blob -- only the amount varint
changed, from ffffffffffff03 to 939298f2d822.

REPRODUCIBILITY NOTE, recorded because it is a real gap that this patch closes: the previous
mainnet- and stagenet-slot blobs were installed by an ad-hoc edit, and the context labels used were
never written down. They could not be reproduced by any label tried (main, mainnet, meepcoin,
production, stage, stagenet, test, testnet). Those two slots therefore get new keys here, derived
from labels that ARE recorded above and reproducible by the command above. The devnet slot -- the
only one that runs -- keeps its exact keys, because `gen devnet` reproduces them.

Expected genesis block hashes after installing (verify against the running daemon, do not trust
this comment):

    mainnet  slot  5ee183402674af0316053bcf27ff159df18e8f62edef8137cb13a67dbb6f211f
    testnet  slot  871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74
    stagenet slot  825a2f71d74fe8f5db559c42e81cd7f940de16c47461038aa1be4459b8e0df88

Idempotent.
"""
import os, re, sys

ROOT = os.path.expanduser("~/meepcoin-node")
CFG = os.path.join(ROOT, "src/cryptonote_config.h")

# The old blobs are read out of the file rather than transcribed here -- an earlier revision of this
# script split a hardcoded hex string at the wrong byte and silently failed to match.
GENESIS_TX_RE = re.compile(r'(std::string const GENESIS_TX = ")([0-9a-f]+)(";)')

# --- approved economics (amount 939298f2d822 = 1,192,092,895,507) -------------------------------
NEW_MAIN = ("020a01ff0001939298f2d822032d93f4ab9f25653f3834e54baca3643100036dc7c05936d9f1857c87bf849643"
            "a82101acb3056c30c748f18bef691fee552e68e66f7136a82e401ed93cec6aff0fd09800")
NEW_TEST = ("020a01ff0001939298f2d82203f0d2a4ce0987104c2a012faa2c0e4f9d6692cdce578434575de531cda04457ec"
            "972101dcd49fb892af9ddd1c7f0d1a8ab718cbd510bb4919c33ec21c718bcf1a44255600")
NEW_STAGE = ("020a01ff0001939298f2d82203ddb422f419db0e9ea82970ae7ae700a8ace99d8e56bd103b80a12ac81df1c5e8"
             "e62101afc9bd9e8a2f0ac691bb6583800f2c2d91c6e7df515aa31039c1a7748c3ed00e00")

s = open(CFG).read()

if NEW_TEST in s and NEW_MAIN in s and NEW_STAGE in s:
    print("= approved-economics genesis blobs already installed")
    sys.exit(0)

# The three initialised GENESIS_TX definitions appear in file order: namespace config (mainnet
# slot), config::testnet, config::stagenet. Verify that before relying on the order.
found = list(GENESIS_TX_RE.finditer(s))
if len(found) != 3:
    print(f"! expected 3 initialised GENESIS_TX definitions, found {len(found)}")
    sys.exit(1)

NEW_BY_SLOT = [("mainnet slot", NEW_MAIN),
               ("testnet slot (devnet)", NEW_TEST),
               ("stagenet slot", NEW_STAGE)]

# Confirm the namespace preceding each match matches the slot we intend to write.
EXPECT_NS = ["namespace config", "namespace testnet", "namespace stagenet"]
for i, m in enumerate(found):
    head = s[:m.start()]
    last_ns = None
    for ns in ("namespace config", "namespace testnet", "namespace stagenet"):
        p = head.rfind(ns)
        if p != -1 and (last_ns is None or p > last_ns[1]):
            last_ns = (ns, p)
    if last_ns is None or last_ns[0] != EXPECT_NS[i]:
        got = last_ns[0] if last_ns else "none"
        print(f"! GENESIS_TX #{i} is inside '{got}', expected '{EXPECT_NS[i]}' -- refusing to guess")
        sys.exit(1)

# Rewrite back-to-front so earlier offsets stay valid.
for i in range(2, -1, -1):
    m = found[i]
    label, new = NEW_BY_SLOT[i]
    old = m.group(2)
    if old == new:
        print(f"= {label}: already current")
        continue
    s = s[:m.start()] + m.group(1) + new + m.group(3) + s[m.end():]
    print(f"+ {label}: {old[:22]}... -> {new[:22]}...")

# Sanity: the amount varint must appear exactly three times and the old one not at all.
if s.count("939298f2d822") != 3:
    print(f"! expected 3 new amount varints, found {s.count('939298f2d822')}")
    sys.exit(1)
if "ffffffffffff0303" in s:
    print("! an old-amount genesis blob is still present")
    sys.exit(1)

open(CFG, "w").write(s)
print("GENESIS_BLOBS_V16_ECON_OK")
