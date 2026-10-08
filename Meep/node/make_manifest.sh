#!/usr/bin/env bash
# Build the frozen-baseline manifest. Read-only: hashes and queries only.
set -u
R=/mnt/c/Users/tseng/meepcoin
B=$HOME/meepcoin-node/build/release/bin
M=$R/docs/BASELINE_MANIFEST_V16_ECONOMICS.md

cd "$R"
COMMIT=$(git rev-parse HEAD)
COMMIT_SHORT=$(git rev-parse --short HEAD)
V2FROZEN=$(git rev-parse v2-frozen^{commit})
V2TAGOBJ=$(git rev-parse v2-frozen)
CLEAN=$(git status --porcelain | wc -l)

gh () { curl -s -m 8 -X POST http://127.0.0.1:$1/json_rpc -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":0}}" \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['block_header']['hash'])" 2>/dev/null; }

LIVE_GENESIS=$(gh 29081)
HEIGHT=$(curl -s -m 8 -X POST http://127.0.0.1:29081/get_info -H 'Content-Type: application/json' -d '{}' \
         | python3 -c "import sys,json;print(json.load(sys.stdin)['height'])" 2>/dev/null)
TIP=$(curl -s -m 8 -X POST http://127.0.0.1:29081/get_info -H 'Content-Type: application/json' -d '{}' \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['top_block_hash'])" 2>/dev/null)

gen () { "$B/meepcoin-genesis16" gen "$1" 1192092895507 "$2" 1785283200 \
         | grep -oP 'genesis_block_hash\s+=\s+\K[0-9a-f]{64}'; }

{
echo "# MeepCoin — Validated Private-Devnet Baseline Manifest"
echo
echo "**PRIVATE DEVELOPMENT CHAIN. Dev/test coins with NO monetary value.** No public network exists."
echo
echo "Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "## Git"
echo
echo "| Item | Value |"
echo "|---|---|"
echo "| Commit this manifest was generated from | \`$COMMIT\` |"
echo "| Short | \`$COMMIT_SHORT\` |"
echo "| Tag | \`v16-economics-freeze\` — annotated, applied to the commit that ADDS this file, i.e. the child of the commit above |"
echo "| Working tree | $([ "$CLEAN" = "0" ] && echo 'clean' || echo "$CLEAN uncommitted change(s)") |"
echo "| Frozen MeepHash-W tag | \`v2-frozen\` |"
echo "| ... tag object | \`$V2TAGOBJ\` |"
echo "| ... commit it points to | \`$V2FROZEN\` |"
echo
echo "## Genesis hashes — all three network slots"
echo
echo "| Config slot | Context label | Nonce | Genesis block hash |"
echo "|---|---|---|---|"
echo "| \`config\` (mainnet) | \`mainnet\` | 20000 | \`$(gen mainnet 20000)\` |"
echo "| \`config::testnet\` (devnet, in use) | \`devnet\` | 20001 | \`$(gen devnet 20001)\` |"
echo "| \`config::stagenet\` | \`stagenet\` | 20002 | \`$(gen stagenet 20002)\` |"
echo
echo "Genesis coinbase amount, all slots: **1,192,092,895,507 atomic = 11.92092895507 MEEP**."
echo
echo "Live devnet confirmation (only this slot runs):"
echo
echo "| | Value |"
echo "|---|---|"
echo "| Daemon-reported genesis | \`$LIVE_GENESIS\` |"
echo "| Chain height at freeze | $HEIGHT |"
echo "| Tip at freeze | \`$TIP\` |"
echo
echo "## Binary SHA-256"
echo
echo '```'
cd "$B" && sha256sum meepcoind meepcoin-wallet-rpc meepcoin-wallet-cli 2>/dev/null
echo '```'
echo
echo "## Tool SHA-256"
echo
echo '```'
cd "$B" && sha256sum meepcoin-genesis meepcoin-genesis16 meepcoin-blockhashing meepcoin-econ-dump \
  meepcoin-emission-probe meepcoin-hardfork-test meepcoin-decimal-test meepcoin-fee-fallback-test 2>/dev/null
echo '```'
echo
echo "## MeepHash-W v2 tool and vector SHA-256"
echo
echo '```'
cd "$R/meepow" && sha256sum build/release/meepow-v2-hash build/release/meepow-unit \
  build/release/meepow-kat-v2-api vectors/vectors_v2.txt 2>/dev/null
echo '```'
echo
echo "## Block-vector SHA-256"
echo
echo '```'
cd "$R" && sha256sum meepow/vectors/block_vectors_v16_devnet.json \
  meepow/vectors/block_vectors_v16_altchain.json \
  meepow/vectors/superseded_v16_inherited_economics/block_vectors_v16_devnet.json \
  meepow/vectors/superseded_v16_inherited_economics/block_vectors_v16_altchain.json 2>/dev/null
echo '```'
echo
echo "## Source SHA-256 of the patched consensus files"
echo
echo '```'
cd "$HOME/meepcoin-node" && sha256sum src/cryptonote_config.h src/cryptonote_basic/cryptonote_basic_impl.cpp \
  src/cryptonote_basic/hardfork.cpp src/cryptonote_basic/hardfork.h \
  src/cryptonote_basic/cryptonote_format_utils.cpp src/cryptonote_core/blockchain.cpp \
  src/hardforks/hardforks.cpp src/wallet/wallet2.cpp 2>/dev/null
echo '```'
echo
echo "## Compiled economics"
echo
echo '```'
"$B/meepcoin-econ-dump" 2>/dev/null | sed -n '/Assertions against/,/RESULT/p'
echo '```'
echo
echo "_Dev/test coins on a private localhost chain. No monetary value._"
} > "$M"

echo "wrote $M"
echo
sed -n '1,60p' "$M"
