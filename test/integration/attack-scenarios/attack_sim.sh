#!/usr/bin/env bash
set -euo pipefail

# Simulate a safe multi-stage APT chain for ProvidAPT capture verification.
#
# The script records a small JSONL ground-truth file that can be used later for
# detector training/evaluation. It never modifies real system authentication
# files and never connects to external attacker infrastructure.

RUN_ID="${RUN_ID:-providapt-attack-sim-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
if [ -z "${GROUND_TRUTH_PATH:-}" ]; then
    if mkdir -p /var/log/providapt/ground-truth 2>/dev/null && [ -w /var/log/providapt/ground-truth ]; then
        GROUND_TRUTH_PATH="/var/log/providapt/ground-truth/${RUN_ID}.jsonl"
    else
        GROUND_TRUTH_PATH="/tmp/providapt_attack_ground_truth_${RUN_ID}.jsonl"
    fi
fi
SIM_TMPDIR=$(mktemp -d /tmp/providapt_attack_sim_XXXXXX)
PID_FILE="$SIM_TMPDIR/shell.pid"
PAYLOAD="$SIM_TMPDIR/evil.sh"
EXFIL_DATA="$SIM_TMPDIR/exfil.dat"
PASSWD_COPY="$SIM_TMPDIR/passwd_backdoored"
CRON_COPY="$SIM_TMPDIR/evil_cron"

cleanup() {
    echo "[sim] cleaning up temporary working directory..."
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
    rm -rf "$SIM_TMPDIR"
    echo "[sim] cleanup done"
}
trap cleanup EXIT

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

record_truth() {
    local phase="$1"
    local tactic="$2"
    local technique="$3"
    local command="$4"
    local expected_event="$5"
    local relation="$6"
    local actor="$7"
    local object="$8"
    local malicious="${9:-true}"

    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$(dirname "$GROUND_TRUTH_PATH")"
    {
        printf '{"schema":"providapt.attack_ground_truth.v1"'
        printf ',"run_id":%s' "$(json_escape "$RUN_ID")"
        printf ',"timestamp":%s' "$(json_escape "$ts")"
        printf ',"phase":%s' "$(json_escape "$phase")"
        printf ',"tactic":%s' "$(json_escape "$tactic")"
        printf ',"technique":%s' "$(json_escape "$technique")"
        printf ',"command":%s' "$(json_escape "$command")"
        printf ',"expected_event":%s' "$(json_escape "$expected_event")"
        printf ',"expected_relation":%s' "$(json_escape "$relation")"
        printf ',"actor":%s' "$(json_escape "$actor")"
        printf ',"object":%s' "$(json_escape "$object")"
        printf ',"malicious":%s' "$malicious"
        printf '}\n'
    } >> "$GROUND_TRUTH_PATH"
}

phase() {
    echo ""
    echo "----------------------------------------------------------------"
    echo "[$1] $2"
    echo "----------------------------------------------------------------"
}

echo ""
echo "ProvidAPT APT attack simulation"
echo "  Run ID:       $RUN_ID"
echo "  Temp dir:     $SIM_TMPDIR"
echo "  Ground truth: $GROUND_TRUTH_PATH"
echo ""

phase "Phase 1" "Initial access: plant malicious script"
cat > "$PAYLOAD" << 'PAYLOAD'
#!/bin/bash
echo "evil_payload_running"
logger -t "providapt_attack_sim" "EVIL_PAYLOAD_EXECUTED"
PAYLOAD
chmod +x "$PAYLOAD"
record_truth "initial_access" "TA0001" "T1105 ingress tool transfer" "create payload script" "file_write" "prov:wasGeneratedBy" "bash" "$PAYLOAD" true
echo "  created payload: $PAYLOAD"
ls -la "$PAYLOAD"

phase "Phase 2" "Execution: run payload from /tmp"
bash "$PAYLOAD" &
PAYLOAD_PID=$!
echo "$PAYLOAD_PID" > "$PID_FILE"
record_truth "execution" "TA0002" "T1059 command and scripting interpreter" "bash $PAYLOAD" "process_exec" "prov:wasInformedBy" "bash" "pid:$PAYLOAD_PID" true
echo "  payload running as PID $PAYLOAD_PID"

phase "Phase 3" "Reconnaissance: read sensitive files"
head -5 /etc/shadow > /dev/null 2>&1 || true
record_truth "reconnaissance" "TA0007" "T1003 credential file discovery" "head -5 /etc/shadow" "file_open" "prov:used" "head" "/etc/shadow" true
head -5 /etc/passwd > /dev/null 2>&1
record_truth "reconnaissance" "TA0007" "T1087 account discovery" "head -5 /etc/passwd" "file_open" "prov:used" "head" "/etc/passwd" true
ls /root/ > /dev/null 2>&1 || true
record_truth "reconnaissance" "TA0007" "T1083 file and directory discovery" "ls /root" "file_open" "prov:used" "ls" "/root" true
echo "  sensitive file and directory probes completed"

phase "Phase 4" "Persistence: simulate credential and cron modification"
cp /etc/passwd "$SIM_TMPDIR/passwd_original"
cp /etc/passwd "$PASSWD_COPY"
echo "backdoor:x:0:0:backdoor:/root:/bin/bash" >> "$PASSWD_COPY"
record_truth "persistence" "TA0003" "T1136 create account" "append backdoor account to passwd copy" "file_write" "prov:wasGeneratedBy" "bash" "$PASSWD_COPY" true
echo "* * * * * root $PAYLOAD" > "$CRON_COPY"
record_truth "persistence" "TA0003" "T1053 scheduled task/job" "write cron persistence copy" "file_write" "prov:wasGeneratedBy" "bash" "$CRON_COPY" true
echo "  simulated persistence files created under $SIM_TMPDIR"

phase "Phase 5" "Exfiltration/C2: local connection attempts"
dd if=/dev/urandom of="$EXFIL_DATA" bs=1024 count=1 2>/dev/null
record_truth "collection" "TA0009" "T1005 data from local system" "dd random exfil data" "file_write" "prov:wasGeneratedBy" "dd" "$EXFIL_DATA" true
curl -s -o /dev/null --connect-timeout 2 http://127.0.0.1:1/ 2>/dev/null || true
record_truth "command_and_control" "TA0011" "T1071 application layer protocol" "curl http://127.0.0.1:1/" "network_connect" "prov:used" "curl" "127.0.0.1:1" true
wget -q -O /dev/null --timeout=2 http://127.0.0.1:1/ 2>/dev/null || true
record_truth "command_and_control" "TA0011" "T1071 application layer protocol" "wget http://127.0.0.1:1/" "network_connect" "prov:used" "wget" "127.0.0.1:1" true
echo "  local C2-like connection attempts completed"

phase "Benign" "Normal commands for contrast"
ls -la /tmp > /dev/null
record_truth "benign" "benign" "directory listing" "ls -la /tmp" "file_open" "prov:used" "ls" "/tmp" false
date > /dev/null
record_truth "benign" "benign" "time query" "date" "process_exec" "prov:wasInformedBy" "date" "stdout" false
whoami > /dev/null
record_truth "benign" "benign" "identity query" "whoami" "process_exec" "prov:wasInformedBy" "whoami" "stdout" false
echo "  benign activity completed"

echo ""
echo "Attack simulation complete"
echo "Expected provenance chain:"
echo "  bash -> evil.sh              [exec/fork]"
echo "  head -> /etc/shadow          [read/use]"
echo "  head -> /etc/passwd          [read/use]"
echo "  bash -> passwd_backdoored    [write/create]"
echo "  bash -> evil_cron            [write/create]"
echo "  curl/wget -> 127.0.0.1:1     [network/use]"
echo ""
echo "Ground truth JSONL saved at:"
echo "  $GROUND_TRUTH_PATH"
echo ""
echo "Run verification: make verify-capture"
