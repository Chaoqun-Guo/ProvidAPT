#!/usr/bin/env bash
# persistence.sh — Simulate common persistence mechanisms.
# Tests ProvidAPT file-write and cron provenance capture.

set -euo pipefail

echo "[*] Persistence Mechanism Simulation"
echo "---"

echo "[1] Writing to /tmp/persist.sh"
cat > /tmp/persist.sh << 'SCRIPT'
#!/bin/bash
# persistence simulation payload
while true; do sleep 3600; done
SCRIPT
chmod +x /tmp/persist.sh

echo "[2] Simulating cron installation"
echo "* * * * * /tmp/persist.sh" > /tmp/fake_cron 2>/dev/null
echo "  -> fake cron entry created in /tmp"

echo "[3] Simulating SSH authorized_keys modification"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA..." > /tmp/fake_authorized_keys 2>/dev/null
echo "  -> fake authorized key written to /tmp"

echo "[4] Simulating systemd service creation"
cat > /tmp/persist.service << 'SERVICE'
[Unit]
Description=Persistence simulation
[Service]
ExecStart=/tmp/persist.sh
[Install]
WantedBy=multi-user.target
SERVICE
echo "  -> fake systemd unit written"

echo "---"
echo "[*] Simulation complete. Check ProvidAPT logs."
