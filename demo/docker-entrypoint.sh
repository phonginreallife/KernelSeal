#!/bin/bash
# X00 Demo Entry Point

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           X00 Secret Protection Demo                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Set demo secrets
# ⚠️ SECURITY: These are DEMO/PLACEHOLDER values only!
# Never use these in production - replace with real secrets from a secret manager
export X00_DEMO_API_KEY="${X00_DEMO_API_KEY:-demo-placeholder-api-key}"
export X00_DEMO_DB_PASSWORD="${X00_DEMO_DB_PASSWORD:-demo-placeholder-password}"
export X00_DEMO_SECRET="${X00_DEMO_SECRET:-demo-placeholder-secret}"

echo "📋 Demo Configuration:"
echo "   API_KEY: ${X00_DEMO_API_KEY:0:15}..."
echo "   DB_PASS: ${X00_DEMO_DB_PASSWORD:0:10}..."
echo ""

# Create config file
cat > /etc/x00/config.yaml << 'EOF'
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
          envRef: "X00_DEMO_API_KEY"
      - name: DEMO_DB_PASSWORD
        source:
          envRef: "X00_DEMO_DB_PASSWORD"

  - name: sleep-demo
    selector:
      binary: "sleep"
    secretRefs:
      - name: DEMO_SECRET
        source:
          envRef: "X00_DEMO_SECRET"

  - name: curl-demo
    selector:
      binary: "curl"
    secretRefs:
      - name: API_TOKEN
        source:
          envRef: "X00_DEMO_API_KEY"
EOF

echo "🚀 Starting X00..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "In another terminal, exec into this container and run:"
echo ""
echo "  docker exec -it x00-demo cat /etc/hostname"
echo "  docker exec -it x00-demo sleep 2"
echo "  docker exec -it x00-demo curl --version"
echo ""
echo "Watch this terminal for:"
echo "  📍 EXEC: Process detection"
echo "  💉 Secret injection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run X00
exec /app/x00 \
    -config /etc/x00/config.yaml \
    -exec-monitor /app/bpf/exec_monitor.bpf.o \
    -lsm /app/bpf/lsm_file_protect.bpf.o
