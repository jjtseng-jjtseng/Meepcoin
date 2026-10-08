#!/usr/bin/env bash
# Source the pinned emsdk env, then build the Wasm module. Run from WSL/Linux.
set -euo pipefail
EMSDK_DIR="${EMSDK_DIR:-$HOME/emsdk}"
# shellcheck disable=SC1091
source "$EMSDK_DIR/emsdk_env.sh" >/dev/null 2>&1
REPO="$(cd "$(dirname "$0")/.." && pwd)"
bash "$REPO/meepow/wasm/build-wasm.sh"
