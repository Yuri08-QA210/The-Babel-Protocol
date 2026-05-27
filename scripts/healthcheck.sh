#!/bin/bash
# QA CTF Challenge — Health Check Script
# Run this to verify all services are healthy

echo "[*] Checking services..."

# Check Stage 1
if curl -s http://localhost/api/health | grep -q "healthy"; then
    echo "[+] Stage 1: OK"
else
    echo "[-] Stage 1: FAIL"
fi

# Check Stage 2
if curl -s http://localhost/portal/ | grep -q "service"; then
    echo "[+] Stage 2: OK"
else
    echo "[-] Stage 2: FAIL"
fi

# Check Stage 3
if curl -s http://localhost/api/vault/status | grep -q "ok"; then
    echo "[+] Stage 3: OK"
else
    echo "[-] Stage 3: FAIL"
fi

echo "[*] All checks complete"
