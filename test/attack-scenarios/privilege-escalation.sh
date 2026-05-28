#!/usr/bin/env bash
# privilege-escalation.sh — Simulate a privilege escalation attack
# for testing ProvidAPT provenance capture.
#
# This script performs:
#   1. SUID binary exploitation simulation
#   2. sudo abuse
#   3. Capability abuse check
#
# Use: Ensure ProvidAPT is running, then execute this script.
#      Check /var/log/providapt/ for captured events.

set -euo pipefail

echo "[*] Privilege Escalation Simulation"
echo "---"

echo "[1] Attempting file read as current user"
cat /etc/passwd > /dev/null 2>&1 && echo "  -> read /etc/passwd"

echo "[2] Attempting sudo access"
sudo -n true 2>/dev/null && echo "  -> sudo accessed" || echo "  -> sudo failed (expected if no password)"

echo "[3] Creating test script"
cat > /tmp/esc_test.sh << 'SCRIPT'
#!/bin/bash
echo "  -> escalation test payload executed with PID $$"
SCRIPT
chmod +x /tmp/esc_test.sh
/tmp/esc_test.sh

echo "[4] Attempting capability check"
capsh --print 2>/dev/null || cat /proc/self/status | grep Cap

echo "---"
echo "[*] Simulation complete. Check ProvidAPT logs."
