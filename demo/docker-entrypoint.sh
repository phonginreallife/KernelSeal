#!/bin/bash
# KernelSeal Demo Entry Point

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           KernelSeal Secret Protection Demo                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Set demo secrets
# ⚠️ SECURITY: These are DEMO/PLACEHOLDER values only!
# Never use these in production - replace with real secrets from a secret manager
export KernelSeal_DEMO_API_KEY="${KernelSeal_DEMO_API_KEY:-demo-placeholder-api-key}"
export KernelSeal_DEMO_DB_PASSWORD="${KernelSeal_DEMO_DB_PASSWORD:-demo-placeholder-password}"
export KernelSeal_DEMO_SECRET="${KernelSeal_DEMO_SECRET:-demo-placeholder-secret}"

echo "📋 Demo Configuration:"
echo "   API_KEY: ${KernelSeal_DEMO_API_KEY:0:15}..."
echo "   DB_PASS: ${KernelSeal_DEMO_DB_PASSWORD:0:10}..."
echo ""

# Create config file
cat > /etc/kernelseal/config.yaml << 'EOF'
version: v1

policy:
  mode: audit
  blockEnviron: true
  blockMem: true
  blockPtrace: true
  auditAll: true

secrets:
  - name: cat-demo
    selector:
      binary: "cat"
    secretRefs:
      - name: DEMO_API_KEY
        source:
          envRef: "KernelSeal_DEMO_API_KEY"
      - name: DEMO_DB_PASSWORD
        source:
          envRef: "KernelSeal_DEMO_DB_PASSWORD"

  - name: sleep-demo
    selector:
      binary: "sleep"
    secretRefs:
      - name: DEMO_SECRET
        source:
          envRef: "KernelSeal_DEMO_SECRET"

  - name: curl-demo
    selector:
      binary: "curl"
    secretRefs:
      - name: API_TOKEN
        source:
          envRef: "KernelSeal_DEMO_API_KEY"
EOF

echo "🚀 Starting KernelSeal..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "In another terminal, exec into this container and run:"
echo ""
echo "  docker exec -it kernelseal-demo cat /etc/hostname"
echo "  docker exec -it kernelseal-demo sleep 2"
echo "  docker exec -it kernelseal-demo curl --version"
echo ""
echo "Watch this terminal for:"
echo "  📍 EXEC: Process detection"
echo "  💉 Secret injection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run KernelSeal
exec /app/kernelseal \
    -config /etc/kernelseal/config.yaml \
    -exec-monitor /app/bpf/exec_monitor.bpf.o \
    -lsm /app/bpf/lsm_file_protect.bpf.o
