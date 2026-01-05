#!/bin/bash
# Demo Application
# This script demonstrates X00's secret injection

echo "=========================================="
echo "  X00 Demo Application"
echo "=========================================="
echo ""
echo "This application will:"
echo "  1. Run various commands that X00 monitors"
echo "  2. Show injected secrets (if X00 is working)"
echo ""
echo "Starting demo loop..."
echo ""

counter=0
while true; do
    counter=$((counter + 1))
    echo "--- Iteration $counter ---"
    
    # Run 'cat' which should trigger secret injection
    echo "[cat] Running cat command..."
    cat /etc/hostname 2>/dev/null || echo "hostname not available"
    
    # Check if secrets were injected into environment
    echo "[env] Checking for injected secrets..."
    if [ -n "$DEMO_API_KEY" ]; then
        echo "  ✅ DEMO_API_KEY is set: ${DEMO_API_KEY:0:10}..."
    else
        echo "  ⏳ DEMO_API_KEY not yet injected"
    fi
    
    if [ -n "$DEMO_DB_PASSWORD" ]; then
        echo "  ✅ DEMO_DB_PASSWORD is set: ${DEMO_DB_PASSWORD:0:10}..."
    else
        echo "  ⏳ DEMO_DB_PASSWORD not yet injected"
    fi
    
    # Run 'sleep' which also has secrets configured
    echo "[sleep] Running sleep command..."
    sleep 2
    
    echo ""
    sleep 3
done
