#!/usr/bin/env bash
set -euo pipefail

# Safe ATT&CK-aligned full-chain simulation for ProvidAPT.
#
# The script intentionally limits all writes to a temporary directory and all
# network activity to localhost or TEST-NET documentation ranges. It records a
# JSONL ground-truth stream with step, tactic, technique, and expected telemetry
# fields for detector training and evaluation.

RUN_ID="${RUN_ID:-providapt-full-chain-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
if [ -z "${GROUND_TRUTH_PATH:-}" ]; then
    if mkdir -p /var/log/providapt/ground-truth 2>/dev/null && [ -w /var/log/providapt/ground-truth ]; then
        GROUND_TRUTH_PATH="/var/log/providapt/ground-truth/${RUN_ID}.jsonl"
    else
        GROUND_TRUTH_PATH="/tmp/providapt_full_chain_ground_truth_${RUN_ID}.jsonl"
    fi
fi

SIM_TMPDIR=$(mktemp -d /tmp/providapt_full_chain_XXXXXX)
MANIFEST_PATH="${MANIFEST_PATH:-$(dirname "$GROUND_TRUTH_PATH")/${RUN_ID}.manifest.json}"
PAYLOAD="$SIM_TMPDIR/payload.sh"
STAGED_TOOL="$SIM_TMPDIR/tools/diagnostic-tool.sh"
CONFIG_STUB="$SIM_TMPDIR/.config/autostart/providapt-sim.desktop"
SYSTEMD_STUB="$SIM_TMPDIR/systemd/user/providapt-sim.service"
CREDENTIAL_COPY="$SIM_TMPDIR/loot/shadow.copy"
ACCOUNT_COPY="$SIM_TMPDIR/loot/passwd.copy"
HOST_DISCOVERY="$SIM_TMPDIR/discovery/host.txt"
PROCESS_DISCOVERY="$SIM_TMPDIR/discovery/processes.txt"
NETWORK_DISCOVERY="$SIM_TMPDIR/discovery/network.txt"
COLLECTION_ARCHIVE="$SIM_TMPDIR/collection.tar"
EXFIL_STAGING="$SIM_TMPDIR/exfil/staged.bin"
IMPACT_MARKER="$SIM_TMPDIR/impact/marker.txt"
PAYLOAD_PID=""

cleanup() {
    if [ -n "${PAYLOAD_PID:-}" ]; then
        kill "$PAYLOAD_PID" 2>/dev/null || true
    fi
    if [ "${KEEP_SIM_ARTIFACTS:-0}" = "1" ]; then
        echo "[full-chain] keeping artifacts under $SIM_TMPDIR"
    else
        rm -rf "$SIM_TMPDIR"
    fi
}
trap cleanup EXIT

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

record_truth() {
    local step_index="$1"
    local step_name="$2"
    local category="$3"
    local phase="$4"
    local tactic_id="$5"
    local tactic_name="$6"
    local technique_id="$7"
    local technique_name="$8"
    local command="$9"
    local expected_event="${10}"
    local relation="${11}"
    local actor="${12}"
    local object="${13}"
    local malicious="${14:-true}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$(dirname "$GROUND_TRUTH_PATH")"
    {
        printf '{"schema":"providapt.attack_ground_truth.v1"'
        printf ',"run_id":%s' "$(json_escape "$RUN_ID")"
        printf ',"timestamp":%s' "$(json_escape "$ts")"
        printf ',"chain":"full_chain"'
        printf ',"category":%s' "$(json_escape "$category")"
        printf ',"step_index":%s' "$step_index"
        printf ',"step_id":%s' "$(json_escape "$(printf 'fc-%02d' "$step_index")")"
        printf ',"step_name":%s' "$(json_escape "$step_name")"
        printf ',"phase":%s' "$(json_escape "$phase")"
        printf ',"tactic":%s' "$(json_escape "$tactic_id")"
        printf ',"tactic_id":%s' "$(json_escape "$tactic_id")"
        printf ',"tactic_name":%s' "$(json_escape "$tactic_name")"
        printf ',"technique":%s' "$(json_escape "$technique_id $technique_name")"
        printf ',"technique_id":%s' "$(json_escape "$technique_id")"
        printf ',"technique_name":%s' "$(json_escape "$technique_name")"
        printf ',"mitre_url":%s' "$(json_escape "https://attack.mitre.org/techniques/${technique_id//./\/}/")"
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

mkdir -p \
    "$SIM_TMPDIR/tools" \
    "$SIM_TMPDIR/.config/autostart" \
    "$SIM_TMPDIR/systemd/user" \
    "$SIM_TMPDIR/loot" \
    "$SIM_TMPDIR/discovery" \
    "$SIM_TMPDIR/exfil" \
    "$SIM_TMPDIR/impact"

cat > "$MANIFEST_PATH" <<EOF
{
  "schema": "providapt.attack_manifest.v1",
  "run_id": "$RUN_ID",
  "source": "MITRE ATT&CK Enterprise Matrix",
  "source_url": "https://attack.mitre.org/matrices/enterprise/",
  "safety": "all writes are confined to the simulation temp directory; network calls use localhost or documentation ranges"
}
EOF

echo "ProvidAPT full-chain ATT&CK simulation"
echo "  Run ID:       $RUN_ID"
echo "  Temp dir:     $SIM_TMPDIR"
echo "  Ground truth: $GROUND_TRUTH_PATH"
echo "  Manifest:     $MANIFEST_PATH"

phase "1" "Reconnaissance / Resource Development"
uname -a > "$HOST_DISCOVERY"
record_truth 1 "Gather victim host information" "pre-compromise" "reconnaissance" "TA0043" "Reconnaissance" "T1592.002" "Gather Victim Host Information: Software" "uname -a > $HOST_DISCOVERY" "file_write" "prov:wasGeneratedBy" "uname" "$HOST_DISCOVERY" true
printf '#!/usr/bin/env bash\necho staged-diagnostic-tool\n' > "$STAGED_TOOL"
chmod +x "$STAGED_TOOL"
record_truth 2 "Stage diagnostic tool capability" "pre-compromise" "resource_development" "TA0042" "Resource Development" "T1587.001" "Develop Capabilities: Malware" "write staged diagnostic tool" "file_write" "prov:wasGeneratedBy" "bash" "$STAGED_TOOL" true

phase "2" "Initial Access / Execution"
cat > "$PAYLOAD" <<'PAYLOAD'
#!/usr/bin/env bash
echo "providapt full-chain payload"
sleep 2
PAYLOAD
chmod +x "$PAYLOAD"
record_truth 3 "Plant payload script" "compromise" "initial_access" "TA0001" "Initial Access" "T1105" "Ingress Tool Transfer" "write payload script" "file_write" "prov:wasGeneratedBy" "bash" "$PAYLOAD" true
bash "$PAYLOAD" &
PAYLOAD_PID=$!
record_truth 4 "Execute payload with Unix shell" "compromise" "execution" "TA0002" "Execution" "T1059.004" "Unix Shell" "bash $PAYLOAD" "process_exec" "prov:wasInformedBy" "bash" "pid:$PAYLOAD_PID" true

phase "3" "Persistence / Privilege Escalation / Defense Evasion"
cat > "$CONFIG_STUB" <<EOF
[Desktop Entry]
Type=Application
Name=ProvidAPT Simulation
Exec=$PAYLOAD
EOF
record_truth 5 "Simulate logon autostart persistence" "post-compromise" "persistence" "TA0003" "Persistence" "T1547.013" "Boot or Logon Autostart Execution: XDG Autostart Entries" "write XDG autostart stub" "file_write" "prov:wasGeneratedBy" "bash" "$CONFIG_STUB" true
cat > "$SYSTEMD_STUB" <<EOF
[Service]
ExecStart=$PAYLOAD
EOF
record_truth 6 "Simulate systemd service persistence" "post-compromise" "privilege_escalation" "TA0004" "Privilege Escalation" "T1543.002" "Create or Modify System Process: Systemd Service" "write systemd user service stub" "file_write" "prov:wasGeneratedBy" "bash" "$SYSTEMD_STUB" true
chmod 600 "$PAYLOAD"
record_truth 7 "Change payload permissions for hiding" "post-compromise" "defense_evasion" "TA0005" "Defense Evasion" "T1222.002" "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification" "chmod 600 $PAYLOAD" "file_write" "prov:wasGeneratedBy" "chmod" "$PAYLOAD" true

phase "4" "Credential Access / Discovery"
cp /etc/shadow "$CREDENTIAL_COPY" 2>/dev/null || touch "$CREDENTIAL_COPY"
record_truth 8 "Copy shadow credential artifact" "post-compromise" "credential_access" "TA0006" "Credential Access" "T1003.008" "OS Credential Dumping: /etc/passwd and /etc/shadow" "copy /etc/shadow to simulation loot" "file_open" "prov:used" "cp" "/etc/shadow" true
cp /etc/passwd "$ACCOUNT_COPY"
record_truth 9 "Copy local account database" "post-compromise" "discovery" "TA0007" "Discovery" "T1087.001" "Account Discovery: Local Account" "copy /etc/passwd to simulation loot" "file_open" "prov:used" "cp" "/etc/passwd" true
ps aux > "$PROCESS_DISCOVERY"
record_truth 10 "Enumerate processes" "post-compromise" "discovery" "TA0007" "Discovery" "T1057" "Process Discovery" "ps aux > $PROCESS_DISCOVERY" "file_write" "prov:wasGeneratedBy" "ps" "$PROCESS_DISCOVERY" true
ip addr > "$NETWORK_DISCOVERY" 2>/dev/null || ifconfig > "$NETWORK_DISCOVERY" 2>/dev/null || true
record_truth 11 "Enumerate network configuration" "post-compromise" "discovery" "TA0007" "Discovery" "T1016" "System Network Configuration Discovery" "ip addr > $NETWORK_DISCOVERY" "file_write" "prov:wasGeneratedBy" "ip" "$NETWORK_DISCOVERY" true

phase "5" "Lateral Movement / Collection / Command and Control"
ssh -o BatchMode=yes -o ConnectTimeout=2 127.0.0.1 true 2>/dev/null || true
record_truth 12 "Attempt localhost SSH lateral movement" "movement" "lateral_movement" "TA0008" "Lateral Movement" "T1021.004" "Remote Services: SSH" "ssh 127.0.0.1 true" "network_connect" "prov:used" "ssh" "127.0.0.1:22" true
tar -cf "$COLLECTION_ARCHIVE" -C "$SIM_TMPDIR" loot discovery
record_truth 13 "Archive staged collection" "collection" "collection" "TA0009" "Collection" "T1560.001" "Archive Collected Data: Archive via Utility" "tar -cf $COLLECTION_ARCHIVE loot discovery" "file_write" "prov:wasGeneratedBy" "tar" "$COLLECTION_ARCHIVE" true
curl -s -o /dev/null --connect-timeout 2 http://127.0.0.1:1/beacon 2>/dev/null || true
record_truth 14 "Beacon over HTTP to localhost" "c2" "command_and_control" "TA0011" "Command and Control" "T1071.001" "Application Layer Protocol: Web Protocols" "curl http://127.0.0.1:1/beacon" "network_connect" "prov:used" "curl" "127.0.0.1:1" true

phase "6" "Exfiltration / Impact / Benign Contrast"
dd if="$COLLECTION_ARCHIVE" of="$EXFIL_STAGING" bs=1024 count=1 2>/dev/null || cp "$COLLECTION_ARCHIVE" "$EXFIL_STAGING"
record_truth 15 "Stage exfiltration artifact" "exfiltration" "exfiltration" "TA0010" "Exfiltration" "T1041" "Exfiltration Over C2 Channel" "copy collection archive to exfil staging" "file_write" "prov:wasGeneratedBy" "dd" "$EXFIL_STAGING" true
printf 'simulated impact marker only\n' > "$IMPACT_MARKER"
record_truth 16 "Create harmless impact marker" "impact" "impact" "TA0040" "Impact" "T1485" "Data Destruction" "write harmless impact marker" "file_write" "prov:wasGeneratedBy" "bash" "$IMPACT_MARKER" true
date > /dev/null
record_truth 17 "Benign time query" "benign" "benign" "benign" "Benign" "benign" "Time Query" "date" "process_exec" "prov:wasInformedBy" "date" "stdout" false
whoami > /dev/null
record_truth 18 "Benign identity query" "benign" "benign" "benign" "Benign" "benign" "Identity Query" "whoami" "process_exec" "prov:wasInformedBy" "whoami" "stdout" false

echo ""
echo "Full-chain simulation complete"
echo "Ground truth JSONL:"
echo "  $GROUND_TRUTH_PATH"
echo "Manifest:"
echo "  $MANIFEST_PATH"
echo ""
echo "Classification summary:"
python3 - "$GROUND_TRUTH_PATH" <<'PY'
import collections, json, sys
counts = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    if line.strip():
        rec = json.loads(line)
        counts[(rec.get("category"), rec.get("tactic_id"), rec.get("tactic_name"))] += 1
for (category, tactic_id, tactic_name), count in sorted(counts.items()):
    print(f"  {category:16s} {tactic_id:8s} {tactic_name:28s} {count}")
PY
