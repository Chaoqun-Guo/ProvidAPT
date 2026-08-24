#!/bin/bash
# ── ProvidAPT instance bootstrap ──────────────────────────────
set -euo pipefail

# Format and mount the data volume
DATA_DEV="/dev/sdf"
DATA_MOUNT="/var/log/providapt"

if [ -e "${DATA_DEV}" ] && ! mount | grep -q "${DATA_MOUNT}"; then
  mkdir -p "${DATA_MOUNT}"

  # Check if the volume has a filesystem
  if ! blkid "${DATA_DEV}"; then
    mkfs.ext4 "${DATA_DEV}"
  fi

  # Add to fstab for persistence across reboots
  if ! grep -q "${DATA_DEV}" /etc/fstab; then
    echo "${DATA_DEV} ${DATA_MOUNT} ext4 defaults,nofail 0 2" >> /etc/fstab
  fi

  mount "${DATA_MOUNT}"
fi

# Install dependencies
apt-get update -qq
apt-get install -y -qq \
  ca-certificates curl gnupg lsb-release \
  linux-tools-common linux-tools-generic \
  bpfcc-tools

# Install Docker (for container-based deployment)
if ! command -v docker &>/dev/null; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io
  systemctl enable --now docker
fi

# Pull and run ProvidAPT
docker pull ghcr.io/chaoqun-guo/providapt:${providapt_version}

cat > /etc/providapt.toml << 'CONFIG_EOF'
output:
  dir: /var/log/providapt
  format: json
log:
  level: info
  format: json
capture:
  enable_net: true
  enable_file: true
  enable_proc: true
  sensitive_dir: false
api:
  rest: ":8080"
  grpc: ":50051"
  rate_limit_per_sec: 100
  rate_limit_burst: 200
tls:
  enable: ${tls_enabled ? "true" : "false"}
  cert_file: /etc/providapt/certs/server.crt
  key_file: /etc/providapt/certs/server.key
CONFIG_EOF

docker rm -f providapt 2>/dev/null || true

docker run -d \
  --name providapt \
  --restart unless-stopped \
  --privileged \
  --pid host \
  --network host \
  -v /sys:/sys:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf:rw \
  -v /proc:/host/proc:ro \
  -v /lib/modules:/lib/modules:ro \
  -v ${DATA_MOUNT}:${DATA_MOUNT} \
  -v /etc/providapt.toml:/etc/providapt/providapt.toml:ro \
  ghcr.io/chaoqun-guo/providapt:${providapt_version}

# ── Backup cron job ────────────────────────────────────────────
%{ if enable_backup }
cat > /usr/local/bin/providapt-backup.sh << 'BACKUP_SCRIPT'
#!/bin/bash
set -euo pipefail
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_FILE="/tmp/providapt-backup-${TIMESTAMP}.tar.gz"
docker exec providapt providaptctl -backup -backup-out "${BACKUP_FILE}"
aws s3 cp "${BACKUP_FILE}" s3://${backup_bucket}/
rm -f "${BACKUP_FILE}"
BACKUP_SCRIPT

chmod +x /usr/local/bin/providapt-backup.sh

cat > /etc/cron.d/providapt-backup << 'CRON_EOF'
0 3 * * * root /usr/local/bin/providapt-backup.sh
CRON_EOF
%{ endif }

echo "ProvidAPT bootstrap complete"
