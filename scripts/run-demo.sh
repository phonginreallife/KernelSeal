#!/bin/bash
# X00 Local Demo Script
# This script runs X00 locally and demonstrates secret injection

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              X00 Secret Protection Demo                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ This demo requires root privileges for BPF operations${NC}"
    echo -e "${YELLOW}   Run: sudo $0${NC}"
    exit 1
fi

# Set demo secrets as environment variables
# ⚠️ SECURITY: These are DEMO/PLACEHOLDER values only!
# Never use these in production - replace with real secrets from a secret manager
export X00_DEMO_API_KEY="${X00_DEMO_API_KEY:-demo-placeholder-api-key}"
export X00_DEMO_DB_PASSWORD="${X00_DEMO_DB_PASSWORD:-demo-placeholder-password}"
export X00_DEMO_SECRET="${X00_DEMO_SECRET:-demo-placeholder-secret}"
export X00_PYTHON_API_KEY="${X00_PYTHON_API_KEY:-demo-placeholder-python-key}"

echo -e "${GREEN}✓ Demo secrets set in environment${NC}"
echo ""

# Check if BPF objects exist
if [ ! -f "bpf/exec_monitor.bpf.o" ]; then
    echo -e "${YELLOW}⚠ BPF objects not compiled. Attempting to build...${NC}"
    
    # Try to compile with clang
    if command -v clang &> /dev/null; then
        echo -e "${BLUE}→ Compiling BPF programs with clang...${NC}"
        make bpf || {
            echo -e "${RED}❌ BPF compilation failed${NC}"
            echo -e "${YELLOW}   Try: make docker-dev (requires Docker)${NC}"
            exit 1
        }
    else
        echo -e "${RED}❌ clang not found${NC}"
        echo -e "${YELLOW}   Install clang or use Docker: make docker-dev${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ BPF objects ready${NC}"

# Build Go binary
echo -e "${BLUE}→ Building X00 binary...${NC}"
go build -o build/x00 ./cmd/main.go
echo -e "${GREEN}✓ Binary built: build/x00${NC}"
echo ""

# Show the configuration
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Configuration (examples/demo-config.yaml):${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Secrets will be injected into:"
echo "    • cat      → DEMO_API_KEY, DEMO_DB_PASSWORD"
echo "    • sleep    → DEMO_SECRET"
echo "    • python3  → PYTHON_API_KEY"
echo ""
echo "  Policy: audit mode (log but don't block)"
echo ""

# Run X00
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🚀 Starting X00...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}In another terminal, try these commands to trigger secret injection:${NC}"
echo ""
echo "    cat /etc/hostname"
echo "    sleep 5"
echo "    python3 -c 'print(\"hello\")'"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop X00${NC}"
echo ""

# Run X00 with demo config
exec ./build/x00 \
    -config examples/demo-config.yaml \
    -exec-monitor bpf/exec_monitor.bpf.o \
    -lsm bpf/lsm_file_protect.bpf.o
