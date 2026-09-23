#!/usr/bin/env bash
# Build the test image and run the full gate in Docker.
# Cache volumes: cargo registry/git, cargo target, go module/build caches.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${IMAGE:-tachyon-core-test:latest}"

docker build -q -t "$IMAGE" -f "$ROOT/tests/docker/Dockerfile" "$ROOT/tests/docker" >/dev/null

HOST_DIR="${HOST_DIR:-$(pwd -W 2>/dev/null || pwd)}"
echo "== docker run: $HOST_DIR -> /src (image: $IMAGE)"

# Git-bash rewrites leading-slash args (/src -> C:/Program Files/Git/src)
export MSYS_NO_PATHCONV=1

docker run --rm \
    -v "$HOST_DIR:/src" \
    -v tachyon-core-cargo-registry:/usr/local/cargo/registry \
    -v tachyon-core-cargo-git:/usr/local/cargo/git \
    -v tachyon-core-target:/cache/target \
    -v tachyon-core-gomod:/go/pkg/mod \
    -v tachyon-core-gobuild:/root/.cache/go-build \
    -w /src \
    -e CARGO_TARGET_DIR=/cache/target \
    -e GOMODCACHE=/go/pkg/mod \
    -e GOCACHE=/root/.cache/go-build \
    "$IMAGE"
