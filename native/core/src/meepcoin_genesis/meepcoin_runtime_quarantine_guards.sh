#!/bin/sh
# MeepCoin: SOURCE AND CONFIGURATION GUARDS for the inherited Monero runtime contacts.
#
# The companion binary (meepcoin-runtime-quarantine-test) proves what can be proven by running
# code: that the genesis is environment-independent and that the shared update helper fails closed.
# This script proves the things a binary cannot, and the things it would be irresponsible to prove
# by running them:
#
#   - a removed peer seed is only removed if the literal is gone from the source. Instantiating
#     node_server<> to ask it for its seed list needs a live core and a database;
#   - "the DNS resolver no longer probes on construction" is honestly proven by reading the
#     constructor, NOT by constructing one and hoping nothing leaves the machine;
#   - "--enable-dns-blocklist is refused" is a startup-validation property, and exercising it for
#     real would mean starting a daemon, which this round explicitly does not do.
#
# THIS SCRIPT MAKES NO NETWORK REQUEST. It reads files and runs grep.
#
# COMMENT-AWARE. The MeepCoin sources deliberately explain, in comments, exactly which Monero
# endpoint each change removed. A naive grep for "moneropulse" therefore matches the explanation
# rather than a live endpoint. code_grep() below strips // comment lines before matching, so these
# guards test code and not prose. That is not a loophole: a real endpoint literal lives on a code
# line, and the accompanying binary-strings check in the build recipe catches anything that somehow
# reached .rodata anyway.
#
# Usage:  sh src/meepcoin_genesis/meepcoin_runtime_quarantine_guards.sh  [repo-root]

ROOT=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$ROOT" || { echo "cannot cd to $ROOT"; exit 2; }

PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

# 0 if a NON-COMMENT line in $1 matches $2
code_grep() {
  grep -n "$2" "$1" 2>/dev/null | sed 's/^[0-9]*://' | grep -v '^[[:space:]]*//' | grep -q .
}

# assert that no non-comment line of $1 matches $2
absent() { # file pattern label
  if code_grep "$1" "$2"; then bad "$3"; else ok "$3"; fi
}

# assert that some line of $1 matches $2 (comments included: used for required behaviour)
present() { # file pattern label
  if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi
}

echo "================================================================="
echo "MeepCoin runtime-quarantine source guards"
echo "repo: $ROOT"
echo "NOTE: this script makes no DNS, TCP or HTTP request."
echo "================================================================="

# ---------------------------------------------------------------- 1. deterministic genesis
echo
echo "-- genesis is environment-independent --"

GEN=src/cryptonote_core/cryptonote_tx_utils.cpp
if grep -rn "getenv[[:space:]]*([[:space:]]*\"MEEPCOIN_EXPERIMENTAL_GENESIS_TS\"" \
     src/ --include=*.cpp --include=*.h --include=*.inl 2>/dev/null \
   | sed 's/^[^:]*:[0-9]*://' | grep -v '^[[:space:]]*//' | grep -q .; then
  bad "no production source reads MEEPCOIN_EXPERIMENTAL_GENESIS_TS"
else
  ok "no production source reads MEEPCOIN_EXPERIMENTAL_GENESIS_TS"
fi

absent "$GEN" 'MGINFO_RED("EXPERIMENTAL BUILD' "the experimental-genesis warning is gone"
present "$GEN" 'bl.timestamp = MEEPCOIN_GENESIS_TIMESTAMP' "genesis timestamp comes from the compiled constant"
present src/meepcoin_genesis/HARNESS_COMPAT.md 'NO-GO until separately redesigned' \
  "HARNESS_COMPAT.md records that the old launchers are NO-GO"

# The genesis VALUES must not have moved in this commit.
present src/cryptonote_config.h 'MEEPCOIN_GENESIS_TIMESTAMP              1785283200ULL' \
  "MEEPCOIN_GENESIS_TIMESTAMP is unchanged"

# ---------------------------------------------------------------- 2. peer discovery defaults
echo
echo "-- no inherited default peer --"

NN_H=src/p2p/net_node.h
NN_I=src/p2p/net_node.inl

present "$NN_H" 'const std::vector<std::string> m_seed_nodes_list = {};' \
  "the clearnet DNS seed list is empty"

for d in seeds.moneroseeds.se seeds.moneroseeds.ae.org seeds.moneroseeds.ch seeds.moneroseeds.li; do
  absent "$NN_H" "\"$d\"" "clearnet seed removed: $d"
done

for ip in "176.9.0.187:18080" "88.198.163.90:18080" "192.99.8.110:18080" \
          "37.187.74.171:18080" "88.99.195.15:18080" "5.104.84.64:18080" \
          "176.9.0.187:28080" "192.99.8.110:28080" "37.187.74.171:28080" \
          "88.99.195.15:28080" "5.104.84.64:28080" \
          "176.9.0.187:38080" "192.99.8.110:38080" "37.187.74.171:38080" \
          "88.99.195.15:38080" "5.104.84.64:38080"; do
  absent "$NN_I" "\"$ip\"" "fallback IP seed removed: $ip"
done

absent "$NN_I" '\.onion:18083' "all six inherited onion seeds removed"
absent "$NN_I" 'b32\.i2p"' "all three inherited I2P seeds removed"

present "$NN_I" 'no bootstrap seeds are configured' \
  "the daemon says plainly that it has no peer to contact"

# Explicit operator paths must still exist. These are the CLI option names as an operator types
# them -- "seed-node", not the arg_p2p_seed_node descriptor variable that declares it.
for a in seed-node add-peer add-priority-node add-exclusive-node; do
  if grep -q "\"$a\"" src/p2p/net_node.cpp 2>/dev/null; then
    ok "operator peer option still registered: --$a"
  else
    bad "operator peer option still registered: --$a"
  fi
done

# ---------------------------------------------------------------- 3. DNS blocklist
echo
echo "-- DNS blocklist refused, endpoints gone --"

for d in blocklist.moneropulse.se blocklist.moneropulse.org blocklist.moneropulse.net \
         blocklist.moneropulse.co blocklist.moneropulse.fr blocklist.moneropulse.de \
         blocklist.moneropulse.ch; do
  absent "$NN_I" "\"$d\"" "blocklist endpoint removed: $d"
done

present "$NN_I" 'is not supported by MeepCoin: the inherited' \
  "--enable-dns-blocklist is refused at argument handling"
absent "$NN_I" 'm_enable_dns_blocklist = command_line::get_arg' \
  "--enable-dns-blocklist no longer feeds the flag directly"
present "$NN_I" 'm_enable_dns_blocklist = false;' \
  "the blocklist flag is forced off"

# ---------------------------------------------------------------- 4. update supply chain
echo
echo "-- update supply chain removed --"

UPD=src/common/updates.cpp
CORE=src/cryptonote_core/cryptonote_core.cpp
RPC=src/rpc/core_rpc_server.cpp

for d in updates.moneropulse.org updates.moneropulse.net updates.moneropulse.fr \
         updates.moneropulse.de updates.moneropulse.co updates.moneropulse.ch \
         updates.moneropulse.se; do
  absent "$UPD" "\"$d\"" "update endpoint removed: $d"
done

absent "$UPD" 'https://downloads.getmonero.org/' "download base URL removed: downloads.getmonero.org"
absent "$UPD" 'https://updates.getmonero.org/'   "download base URL removed: updates.getmonero.org"
absent "$UPD" 'load_txt_records_from_dns'        "the update helper performs no DNS lookup"

present "$CORE" ', "disabled"' "--check-updates defaults to disabled"
present "$CORE" 'is not supported by MeepCoin: the inherited update' \
  "a non-disabled --check-updates value is refused"
absent "$CORE" 'check_updates_string == "notify"'   "the notify mode is gone"
absent "$CORE" 'check_updates_string == "download"' "the download mode is gone"
absent "$CORE" 'check_updates_string == "update"'   "the update mode is gone"
absent "$CORE" 'm_check_updates_interval.do_call'   "the periodic update check is not scheduled"

# Match the CALL, not the type. core::stop() still declares a tools::download_async_handle and
# cancels it, which is correct and inert: m_update_download is initialised to 0 and nothing assigns
# it any more, so the handle is always 0 and download_cancel() is never reached. What must be gone
# is the thing that STARTS a download.
absent "$CORE" 'tools::download_async(' "the core cannot start an update download"
if grep -n 'm_update_download *=' "$CORE" 2>/dev/null | grep -v '= 0;' | grep -v '^[[:space:]]*//' | grep -q .; then
  bad "m_update_download is never assigned a live download handle"
else
  ok "m_update_download is never assigned a live download handle"
fi

absent "$RPC" 'tools::check_updates'   "the update RPC no longer calls the update helper"
absent "$RPC" 'tools::download('       "the update RPC cannot download"
present "$RPC" 'update checking is not supported by MeepCoin' \
  "the update RPC returns an explicit unsupported result"

# ---------------------------------------------------------------- 5. general DNS resolver
echo
echo "-- DNS resolver does not probe on construction --"

DNS=src/common/dns_utils.cpp

# Bound the check to the constructor body, so an unrelated later use of get_txt_record (the public
# API, which callers legitimately use) does not mask or fake this result.
CTOR=$(awk '/^DNSResolver::DNSResolver\(\)/,/^DNSResolver::~DNSResolver/' "$DNS")

if printf '%s\n' "$CTOR" | sed 's#//.*##' | grep -q 'probe_hostname'; then
  bad "the constructor has no probe hostname"
else
  ok "the constructor has no probe hostname"
fi
if printf '%s\n' "$CTOR" | sed 's#//.*##' | grep -q 'get_txt_record'; then
  bad "the constructor performs no DNS lookup"
else
  ok "the constructor performs no DNS lookup"
fi
if printf '%s\n' "$CTOR" | sed 's#//.*##' | grep -q 'DEFAULT_DNS_PUBLIC_ADDR'; then
  bad "the constructor has no hidden public-resolver fallback"
else
  ok "the constructor has no hidden public-resolver fallback"
fi

# Explicitly configured behaviour must SURVIVE. This is not a general DNS rewrite.
printf '%s\n' "$CTOR" | grep -q 'getenv("DNS_PUBLIC")' \
  && ok "explicit DNS_PUBLIC configuration still honoured" \
  || bad "explicit DNS_PUBLIC configuration still honoured"
printf '%s\n' "$CTOR" | grep -q 'ub_ctx_resolvconf' \
  && ok "the system resolver is still used by default" \
  || bad "the system resolver is still used by default"
present src/common/dns_utils.h 'get_record' "generic DNS/OpenAlias API is still present"

# ---------------------------------------------------------------- 5b. seed schedule and RandomX priming
echo
echo "-- the seed schedule reads no environment; RandomX is not primed for block PoW --"

absent src/crypto/rx-slow-hash.c 'getenv("SEEDHASH_EPOCH' "rx-slow-hash.c reads no SEEDHASH_EPOCH_* environment variable"
present src/crypto/rx-slow-hash.c 'define SEEDHASH_EPOCH_BLOCKS[[:space:]]*((uint64_t)2048)' "the epoch length is the compile-time constant 2048"
present src/crypto/rx-slow-hash.c 'define SEEDHASH_EPOCH_LAG[[:space:]]*((uint64_t)64)' "the epoch lag is the compile-time constant 64"

# No production caller primes RandomX: rx_set_main_seedhash and rx_set_miner_thread are called nowhere
# outside their own definition (hash-ops.h declares them; rx-slow-hash.c defines them).
for fn in rx_set_main_seedhash rx_set_miner_thread; do
  callers=$(grep -rln "$fn(" src --include='*.c' --include='*.cpp' --include='*.inl' \
            | grep -v '^src/crypto/rx-slow-hash.c$' \
            | while read -r f; do code_grep "$f" "$fn(" && echo "$f"; done)
  if [ -z "$callers" ]; then ok "$fn has no caller"; else bad "$fn has no caller (found: $callers)"; fi
done

# RandomX hashing that is deliberately RETAINED: the RPC-payment server and the wallet's RPC-payment
# client. Nothing on the block proof-of-work path calls rx_slow_hash.
rx_callers=$(grep -rln 'rx_slow_hash(' src --include='*.c' --include='*.cpp' --include='*.inl' \
             | grep -v '^src/crypto/rx-slow-hash.c$' \
             | while read -r f; do code_grep "$f" 'rx_slow_hash(' && echo "$f"; done | LC_ALL=C sort | tr '\n' ' ')
if [ "$rx_callers" = "src/rpc/rpc_payment.cpp src/wallet/wallet_rpc_payments.cpp " ]; then
  ok "rx_slow_hash is called only by the retained RPC-payment paths"
else
  bad "rx_slow_hash is called only by the retained RPC-payment paths (found: $rx_callers)"
fi

# Every seed-height caller: the block template, get_miner_data, main- and alternative-chain PoW, the
# miner notification after add/reorg (blockchain.cpp), the main-chain PoW (cryptonote_tx_utils.cpp) and
# the template RPC's next seed (core_rpc_server.cpp). One function, one rule.
sh_callers=$(grep -rlnE 'rx_seedheights?\(' src --include='*.c' --include='*.cpp' --include='*.inl' \
             | grep -v '^src/crypto/rx-slow-hash.c$' | grep -v '^src/meepcoin_genesis/' \
             | while read -r f; do code_grep "$f" 'rx_seedheight' && echo "$f"; done | LC_ALL=C sort | tr '\n' ' ')
if [ "$sh_callers" = "src/cryptonote_core/blockchain.cpp src/cryptonote_core/cryptonote_tx_utils.cpp src/rpc/core_rpc_server.cpp " ]; then
  ok "rx_seedheight/rx_seedheights are called only by the block template, PoW, notification and template-RPC paths"
else
  bad "rx_seedheight/rx_seedheights callers are the known block paths (found: $sh_callers)"
fi

# Retained and NOT the seed schedule: the block-sync batch clamp still reads SEEDHASH_EPOCH_BLOCKS. It
# bounds how many blocks one sync request may carry; it does not change any seed height.
present src/cryptonote_core/cryptonote_core.cpp 'getenv("SEEDHASH_EPOCH_BLOCKS")' "the block-sync batch clamp (not the seed schedule) is the one remaining reader, and is retained"

# ---------------------------------------------------------------- 6. scope invariants
echo
echo "-- scope invariants: nothing else moved --"

# These files must be byte-identical to the previous commit (19a27b8). Consensus values, the
# hash, the wallet key format and the hardfork schedule are all out of scope for this round.
BASE=19a27b83dfc33b9d21e0d4b29b91570243e44f8a
for f in src/cryptonote_config.h \
         src/crypto/meep-hash.cpp \
         src/crypto/meep-hash.h \
         src/hardforks/hardforks.cpp \
         src/cryptonote_basic/hardfork.cpp \
         src/cryptonote_basic/hardfork.h \
         src/blockchain_db/blockchain_db.cpp \
         src/checkpoints/checkpoints.cpp \
         src/wallet/wallet2.cpp \
         src/simplewallet/simplewallet.cpp; do
  if git cat-file -e "$BASE:$f" 2>/dev/null; then
    if git diff --quiet "$BASE" -- "$f" 2>/dev/null; then
      ok "unchanged since $(echo $BASE | cut -c1-7): $f"
    else
      bad "unchanged since $(echo $BASE | cut -c1-7): $f"
    fi
  else
    bad "expected file present at $(echo $BASE | cut -c1-7): $f"
  fi
done

# The previous round's consensus correction must still hold.
if [ -e src/blocks/checkpoints.dat ]; then
  bad "the inherited Monero checkpoint blob is still deleted"
else
  ok "the inherited Monero checkpoint blob is still deleted"
fi

echo
echo "================================================================="
echo "RESULT: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
  echo "RUNTIME QUARANTINE GUARDS: PASS"
  exit 0
else
  echo "RUNTIME QUARANTINE GUARDS: FAIL"
  exit 1
fi
