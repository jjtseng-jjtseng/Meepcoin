#!/usr/bin/env bash
# Capture exact toolchain identities for reproducibility and append them to docs/TOOLCHAIN.md.
# Records image digests (if Docker is available), compiler versions, and vendored checksums.
set -euo pipefail
cd "$(dirname "$0")/.."

{
  echo ""
  echo "## Recorded on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo '```'
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    for img in ubuntu:24.04 emscripten/emsdk:6.0.3; do
      digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$img" 2>/dev/null || echo "not pulled")
      echo "image $img -> $digest"
    done
  else
    echo "docker unavailable; image digests not recorded on this host"
  fi
  echo "gcc:   $(gcc --version 2>/dev/null | head -1 || echo n/a)"
  echo "clang: $(clang --version 2>/dev/null | head -1 || echo n/a)"
  echo "cmake: $(cmake --version 2>/dev/null | head -1 || echo n/a)"
  echo "emcc:  $(emcc --version 2>/dev/null | head -1 || echo 'n/a (source emsdk_env.sh)')"
  echo "node:  $(node --version 2>/dev/null || echo n/a)"
  echo '```'
  echo ""
  echo "Vendored checksums (verify with \`sha256sum -c\`):"
  echo '```'
  cat meepow/third_party/CHECKSUMS.sha256
  echo '```'
} >> docs/TOOLCHAIN.md

echo "appended toolchain record to docs/TOOLCHAIN.md"
