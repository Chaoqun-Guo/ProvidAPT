#!/usr/bin/env bash
# =============================================================
# attack_sim.sh — Simulate an APT attack chain for ProvidAPT
# capture verification.
#
# Scenario:
#   Phase 1 — Initial access:  drop reverse-shell script in /tmp
#   Phase 2 — Execution:        execute the script
#   Phase 3 — Reconnaissance:   read /etc/shadow
#   Phase 4 — Persistence:      modify /etc/passwd (backdoor user)
#   Phase 5 — Exfiltration:     C2 connection to external host
#
# Safety:
#   - Does NOT modify real system files (operates on copies)
#   - Does NOT connect to real attacker infrastructure
#   - All changes are confined to $SIM_TMPDIR
#   - Cleanup is triggered on EXIT
#
# Usage:
#   ./test/attack-scenarios/attack_sim.sh
#   make attack-sim
# =============================================================
set -euo pipefail

SIM_TMPDIR=$(mktemp -d /tmp/providapt_attack_sim_XXXXXX)
PID_FILE="$SIM_TMPDIR/shell.pid"
PAYLOAD="$SIM_TMPDIR/evil.sh"
EXFIL_DATA="$SIM_TMPDIR/exfil.dat"
PASSWD_COPY="$SIM_TMPDIR/passwd_backdoored"

cleanup() {
    echo "[sim] cleaning up..."
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
    rm -rf "$SIM_TMPDIR"
    echo "[sim] cleanup done"
}
trap cleanup EXIT

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ProvidAPT — APT Attack Simulation                    ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "  Simulation temp dir: $SIM_TMPDIR"
echo ""

# ── Phase 1: Initial Access ──────────────────────────────
echo "────────────────────────────────────────────────────────"
echo "[Phase 1] Initial access — planting malicious script"
echo "────────────────────────────────────────────────────────"

cat > "$PAYLOAD" << 'PAYLOAD'
#!/bin/bash
# Simulated reverse shell / backdoor payload
# In a real attack this would be a Meterpreter / CobaltStrike beacon
echo "evil_payload_running"
logger -t "providapt_attack_sim" "EVIL_PAYLOAD_EXECUTED"
PAYLOAD
chmod +x "$PAYLOAD"
echo "  created payload: $PAYLOAD"
ls -la "$PAYLOAD"

# ── Phase 2: Execution ───────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
echo "[Phase 2] Execution — running payload from /tmp"
echo "────────────────────────────────────────────────────────"

bash "$PAYLOAD" &
PAYLOAD_PID=$!
echo "$PAYLOAD_PID" > "$PID_FILE"
echo "  payload running as PID $PAYLOAD_PID"

# ── Phase 3: Reconnaissance ──────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
echo "[Phase 3] Reconnaissance — reading sensitive files"
echo "────────────────────────────────────────────────────────"

echo "  reading /etc/shadow (sensitive file access)..."
head -5 /etc/shadow > /dev/null 2>&1 || echo "  (read only, no output displayed)"

echo "  reading /etc/passwd..."
head -5 /etc/passwd > /dev/null 2>&1

echo "  listing /root (restricted directory)..."
ls /root/ > /dev/null 2>&1 || echo "  (access denied — expected for non-root)"

# ── Phase 4: Persistence ─────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
echo "[Phase 4] Persistence — modifying system authentication"
echo "────────────────────────────────────────────────────────"

echo "  copying /etc/passwd to temp..."
cp /etc/passwd "$SIM_TMPDIR/passwd_original"

echo "  adding backdoor user entry..."
cp /etc/passwd "$PASSWD_COPY"
echo "backdoor:x:0:0:backdoor:/root:/bin/bash" >> "$PASSWD_COPY"
echo "  simulation: backdoor user would be added to /etc/passwd"
echo "  (wrote to $PASSWD_COPY instead of real /etc/passwd)"

# Also simulate writing to a cron job
echo "* * * * * root $PAYLOAD" > "$SIM_TMPDIR/evil_cron"
echo "  created persistence: $SIM_TMPDIR/evil_cron"

# ── Phase 5: Exfiltration ────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
echo "[Phase 5] Exfiltration — C2 communication simulation"
echo "────────────────────────────────────────────────────────"

echo "  creating exfiltration data..."
dd if=/dev/urandom of="$EXFIL_DATA" bs=1024 count=1 2>/dev/null
echo "  exfil data size: $(wc -c < "$EXFIL_DATA") bytes"

echo "  simulating C2 connection (localhost)..."
# Simulate network connection — this is the key event ProvidAPT
# should capture as used(process, network)
curl -s -o /dev/null --connect-timeout 2 http://127.0.0.1:1/ 2>/dev/null || true
wget -q -O /dev/null --timeout=2 http://127.0.0.1:1/ 2>/dev/null || true
echo "  network connection attempted"

# ── Generate some extra noise ────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────"
echo "[Extra] Benign activity for contrast"
echo "────────────────────────────────────────────────────────"

echo "  running normal commands..."
ls -la /tmp > /dev/null
date > /dev/null
whoami > /dev/null
echo "  benign activity: OK"

# ── Summary ──────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Attack simulation complete                            ║"
echo "║                                                       ║"
echo "║  Expected provenance chain:                           ║"
echo "║    bash --wasInformedBy--> evil.sh (fork)             ║"
echo "║    evil.sh --used--> /etc/shadow (read)               ║"
echo "║    evil.sh --used--> /etc/passwd (read)               ║"
echo "║    evil.sh --wasGeneratedBy--> passwd_backdoored      ║"
echo "║    evil.sh --wasGeneratedBy--> evil_cron (write)      ║"
echo "║    evil.sh --used--> 127.0.0.1:1 (C2 connect)        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Run verification:  make verify-capture"
echo ""
