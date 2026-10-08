#!/usr/bin/env bash
# Verify the EXPERIMENTAL runtime genesis-timestamp override actually takes effect.
set -u
BIN="$HOME/meepcoin-node/build/release/bin/meepcoind.expgen"
DIR="$HOME/.meepcoin-gtest"
rm -rf "$DIR"; mkdir -p "$DIR"
TS=$(date +%s)
echo "requested genesis timestamp: $TS"
MEEPCOIN_EXPERIMENTAL_GENESIS_TS="$TS" setsid "$BIN" --testnet --data-dir "$DIR" --offline \
  --p2p-bind-ip 127.0.0.1 --p2p-bind-port 32900 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 32901 \
  --zmq-rpc-bind-ip 127.0.0.1 --zmq-rpc-bind-port 35901 \
  --no-igd --hide-my-port --non-interactive --fixed-difficulty 0 \
  --log-file "$DIR/d.log" --log-level 0 >/dev/null 2>&1 &
for i in $(seq 1 60); do
  curl -s -m 2 -X POST http://127.0.0.1:32901/get_info >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s -m 5 -X POST http://127.0.0.1:32901/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":0}}' \
  | python3 -c 'import json,sys; h=json.load(sys.stdin)["result"]["block_header"]; print("genesis timestamp:",h["timestamp"]," hash:",h["hash"][:32])'
grep -m1 -o "genesis timestamp overridden.*" "$DIR/d.log" | head -1
curl -s -m 5 -X POST http://127.0.0.1:32901/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"stop_daemon"}' >/dev/null 2>&1
sleep 2
