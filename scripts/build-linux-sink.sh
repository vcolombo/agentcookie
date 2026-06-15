#!/usr/bin/env bash
#
# build-linux-sink.sh — produce a Linux agentcookie binary for the VPS sink.
#
# The sink's cookie sidecar uses github.com/mattn/go-sqlite3, which needs
# CGO_ENABLED=1 and a C toolchain. Cross-compiling CGO from macOS is painful,
# so this builds inside the pinned golang Docker image (which has gcc). The
# result lands at bin/agentcookie-linux-<arch> and runs on the Linux VPS.
#
# Usage:
#   scripts/build-linux-sink.sh            # linux/amd64 (default)
#   ARCH=arm64 scripts/build-linux-sink.sh # linux/arm64 (e.g. ARM VPS)
#
# On the VPS itself (which has Go + gcc) the Docker step is unnecessary:
#   CGO_ENABLED=1 go build -o bin/agentcookie ./cmd/agentcookie
#
set -euo pipefail

ARCH="${ARCH:-amd64}"
GO_IMAGE="${GO_IMAGE:-golang:1.26}"
OUT="bin/agentcookie-linux-${ARCH}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
mkdir -p bin

echo "Building ${OUT} (linux/${ARCH}, CGO) via ${GO_IMAGE}..."

# Run the container AT the target platform so its native gcc matches GOARCH.
# This sidesteps CGO cross-compilation (no -m64 / cross-toolchain dance); on a
# mismatched host (e.g. arm64 Mac building amd64) Docker emulates via qemu.
docker run --rm \
  --platform "linux/${ARCH}" \
  -v "$repo_root":/src \
  -w /src \
  -e CGO_ENABLED=1 \
  -e GOOS=linux \
  -e GOARCH="$ARCH" \
  -e GOFLAGS=-buildvcs=false \
  "$GO_IMAGE" \
  sh -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq gcc libc6-dev >/dev/null
    go build -o "'"$OUT"'" ./cmd/agentcookie
  '

echo "Built ${OUT}"
