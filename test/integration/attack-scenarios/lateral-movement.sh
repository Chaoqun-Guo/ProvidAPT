#!/usr/bin/env bash
# lateral-movement.sh — Simulate lateral movement techniques.
# Tests ProvidAPT network provenance capture.

set -euo pipefail

echo "[*] Lateral Movement Simulation"
echo "---"

echo "[1] SSH connection attempt (simulated)"
nc -zv -w 2 localhost 22 2>/dev/null && echo "  -> port 22 open" \
    || echo "  -> port 22 closed (expected)"

echo "[2] DNS lookup"
host google.com 2>/dev/null || nslookup google.com 2>/dev/null || echo "  -> DNS query sent"

echo "[3] curl to external service"
curl -s -o /dev/null --connect-timeout 3 https://example.com && \
    echo "  -> HTTP connection established"

echo "[4] SCP simulation (local file copy)"
dd if=/dev/urandom of=/tmp/exfil.dat bs=1024 count=1 2>/dev/null
cp /tmp/exfil.dat /tmp/exfil_copy.dat
echo "  -> file copy completed"

echo "---"
echo "[*] Simulation complete. Check ProvidAPT logs for network events."
