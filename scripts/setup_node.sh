#!/usr/bin/env bash
# setup_node.sh — reproducibly install the pinned local Node.js toolchain into
# .toolchain/ (no sudo, no system changes). The dashboard needs Node to build/run.
#
#   ./scripts/setup_node.sh && source .toolchain/activate.sh
#
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="${NODE_VERSION:-v24.21.0}"
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) NARCH="linux-arm64" ;;
  x86_64|amd64)  NARCH="linux-x64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
DEST="$REPO/.toolchain"
TARBALL="node-${VER}-${NARCH}.tar.xz"
mkdir -p "$DEST"
cd "$DEST"
if [ -x "node-${VER}-${NARCH}/bin/node" ]; then
  echo "Node ${VER} already present."
else
  echo "Downloading ${TARBALL} from nodejs.org ..."
  curl -fsSL -O "https://nodejs.org/dist/${VER}/${TARBALL}"
  curl -fsSL -O "https://nodejs.org/dist/${VER}/SHASUMS256.txt"
  echo "Verifying checksum ..."
  grep " ${TARBALL}\$" SHASUMS256.txt | sha256sum -c -
  tar -xf "${TARBALL}"
  rm -f "${TARBALL}" SHASUMS256.txt
fi
cat > activate.sh <<ACT
# Source this to put the pinned local Node toolchain on PATH.
export PATH="$DEST/node-${VER}-${NARCH}/bin:\$PATH"
ACT
echo "Done. Run:  source .toolchain/activate.sh && node --version"
"$DEST/node-${VER}-${NARCH}/bin/node" --version
