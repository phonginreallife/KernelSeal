#!/bin/bash
# Build BPF programs using Cilium's eBPF builder Docker image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "🐳 Building BPF programs using Cilium eBPF builder..."
echo ""

docker run --rm \
    -v "$PROJECT_ROOT:/app" \
    -w /app \
    --user "$(id -u):$(id -g)" \
    docker.io/cilium/ebpf-builder:1698931239 \
    make bpf

echo ""
echo "✅ BPF programs compiled successfully!"
echo ""
ls -la bpf/*.o
