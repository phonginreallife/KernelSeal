#!/bin/bash
# KernelSeal Docker Demo Runner
# This script builds and runs the KernelSeal demo with Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           KernelSeal Docker Demo - Secret Protection                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker daemon is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is available${NC}"
echo ""

# Check for pre-built BPF objects
if [ ! -f "../bpf/exec_monitor.bpf.o" ]; then
    echo -e "${YELLOW}⚠ BPF objects not found. Building first...${NC}"
    cd ..
    make bpf || {
        echo -e "${RED}❌ Failed to build BPF objects${NC}"
        echo -e "${YELLOW}   The demo will try to build them in Docker${NC}"
    }
    cd "$SCRIPT_DIR"
fi

echo -e "${BLUE}→ Building Docker images...${NC}"
docker-compose build

echo ""
echo -e "${GREEN}🚀 Starting KernelSeal Demo...${NC}"
echo ""
echo -e "${YELLOW}You will see two services:${NC}"
echo "  • kernelseal: The security sidecar (monitors and injects secrets)"
echo "  • demo-app: A test application"
echo ""
echo -e "${YELLOW}Watch for these log messages:${NC}"
echo "  📍 EXEC: Process execution detected"
echo "  💉 Secrets injected into PID"
echo "  🛡️  LSM BLOCKED: Access attempt blocked"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Run with logs
docker-compose up --abort-on-container-exit

# Cleanup
echo ""
echo -e "${BLUE}→ Cleaning up...${NC}"
docker-compose down
echo -e "${GREEN}✓ Demo complete${NC}"
