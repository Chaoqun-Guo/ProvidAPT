#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bootstrap-tls.sh [options]

Generate a ProvidAPT mTLS certificate bundle for production bootstrap or staged
rotation. Existing leaf cert/key files are backed up before replacement.

Options:
  -o, --out-dir DIR       Output directory (default: build/tls)
      --server-cn NAME    Server certificate common name (default: providapt-control-plane)
      --server-san LIST   Comma-separated SANs, e.g. DNS:cp-0.example.com,IP:10.0.0.10
      --agent-cn LIST     Comma-separated agent/client CNs (default: providapt-agent)
      --days DAYS         Leaf certificate validity days (default: 397)
      --ca-days DAYS      CA certificate validity days (default: 3650)
      --force-ca          Rotate CA even when ca.crt/ca.key already exist
      --no-backup         Replace existing leaf files without .bak timestamp copies
  -h, --help              Show this help
EOF
}

out_dir="build/tls"
server_cn="providapt-control-plane"
server_san=""
agent_cn_list="providapt-agent"
leaf_days=397
ca_days=3650
force_ca=0
backup_existing=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --server-cn)
      server_cn="${2:-}"
      shift 2
      ;;
    --server-san)
      server_san="${2:-}"
      shift 2
      ;;
    --agent-cn|--agent-cns)
      agent_cn_list="${2:-}"
      shift 2
      ;;
    --days)
      leaf_days="${2:-}"
      shift 2
      ;;
    --ca-days)
      ca_days="${2:-}"
      shift 2
      ;;
    --force-ca)
      force_ca=1
      shift
      ;;
    --no-backup)
      backup_existing=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 2
fi
if ! [[ "$leaf_days" =~ ^[0-9]+$ ]] || [ "$leaf_days" -le 0 ]; then
  echo "--days must be a positive integer" >&2
  exit 2
fi
if ! [[ "$ca_days" =~ ^[0-9]+$ ]] || [ "$ca_days" -le 0 ]; then
  echo "--ca-days must be a positive integer" >&2
  exit 2
fi
case "$server_cn$server_san$agent_cn_list" in
  *\"*|*\\*)
    echo "certificate names and SAN values must not contain quotes or backslashes" >&2
    exit 2
    ;;
esac

umask 077
mkdir -p "$out_dir"

ca_key="$out_dir/ca.key"
ca_crt="$out_dir/ca.crt"
server_key="$out_dir/server.key"
server_csr="$out_dir/server.csr"
server_crt="$out_dir/server.crt"
server_ext="$out_dir/server.ext"
manifest="$out_dir/manifest.json"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

backup_file() {
  local path="$1"
  if [ "$backup_existing" -eq 1 ] && [ -e "$path" ]; then
    cp -p "$path" "$path.bak.$timestamp"
  fi
}

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^sha256 Fingerprint=//;s/^SHA256 Fingerprint=//'
}

write_server_ext() {
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth"
    if [ -n "$server_san" ]; then
      echo "subjectAltName=$server_san"
    else
      echo "subjectAltName=DNS:$server_cn"
    fi
  } > "$server_ext"
}

write_client_ext() {
  local path="$1"
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=clientAuth"
  } > "$path"
}

if [ "$force_ca" -eq 1 ] || [ ! -s "$ca_key" ] || [ ! -s "$ca_crt" ]; then
  backup_file "$ca_key"
  backup_file "$ca_crt"
  openssl genrsa -out "$ca_key" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days "$ca_days" \
    -subj "/CN=ProvidAPT Local CA" -out "$ca_crt" >/dev/null 2>&1
  echo "generated CA: $ca_crt"
else
  echo "reusing existing CA: $ca_crt"
fi

backup_file "$server_key"
backup_file "$server_crt"
openssl genrsa -out "$server_key" 2048 >/dev/null 2>&1
openssl req -new -key "$server_key" -subj "/CN=$server_cn" -out "$server_csr" >/dev/null 2>&1
write_server_ext
openssl x509 -req -in "$server_csr" -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
  -out "$server_crt" -days "$leaf_days" -sha256 -extfile "$server_ext" >/dev/null 2>&1
rm -f "$server_csr" "$server_ext"
chmod 0644 "$ca_crt" "$server_crt"
chmod 0600 "$ca_key" "$server_key"

agent_entries=""
IFS=',' read -r -a agents <<< "$agent_cn_list"
for raw_agent in "${agents[@]}"; do
  agent_cn="$(echo "$raw_agent" | xargs)"
  [ -n "$agent_cn" ] || continue
  safe_agent="$(printf '%s' "$agent_cn" | tr -c 'A-Za-z0-9_.-' '_')"
  agent_key="$out_dir/${safe_agent}.key"
  agent_csr="$out_dir/${safe_agent}.csr"
  agent_crt="$out_dir/${safe_agent}.crt"
  agent_ext="$out_dir/${safe_agent}.ext"
  backup_file "$agent_key"
  backup_file "$agent_crt"
  openssl genrsa -out "$agent_key" 2048 >/dev/null 2>&1
  openssl req -new -key "$agent_key" -subj "/CN=$agent_cn" -out "$agent_csr" >/dev/null 2>&1
  write_client_ext "$agent_ext"
  openssl x509 -req -in "$agent_csr" -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
    -out "$agent_crt" -days "$leaf_days" -sha256 -extfile "$agent_ext" >/dev/null 2>&1
  rm -f "$agent_csr" "$agent_ext"
  chmod 0644 "$agent_crt"
  chmod 0600 "$agent_key"
  fp="$(fingerprint "$agent_crt")"
  if [ -n "$agent_entries" ]; then
    agent_entries="$agent_entries,"
  fi
  agent_entries="$agent_entries{\"cn\":\"$agent_cn\",\"cert\":\"$agent_crt\",\"key\":\"$agent_key\",\"fingerprint_sha256\":\"$fp\"}"
done

cat > "$manifest" <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ca": {
    "cert": "$ca_crt",
    "key": "$ca_key",
    "fingerprint_sha256": "$(fingerprint "$ca_crt")"
  },
  "server": {
    "cn": "$server_cn",
    "san": "${server_san:-DNS:$server_cn}",
    "cert": "$server_crt",
    "key": "$server_key",
    "fingerprint_sha256": "$(fingerprint "$server_crt")"
  },
  "agents": [$agent_entries]
}
EOF
chmod 0600 "$manifest"

echo "generated server cert: $server_crt"
echo "generated agent certs for: $agent_cn_list"
echo "manifest: $manifest"
echo
echo "Config paths:"
echo "  tls.cert_file: $server_crt"
echo "  tls.key_file:  $server_key"
echo "  tls.ca_file:   $ca_crt"
echo "  telemetry.cert_file: <agent>.crt"
echo "  telemetry.key_file:  <agent>.key"
echo "  telemetry.ca_file:   $ca_crt"
