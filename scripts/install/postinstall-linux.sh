#!/usr/bin/env bash
set -euo pipefail

if ! getent passwd providapt >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --comment "ProvidAPT daemon user" providapt 2>/dev/null || true
fi

install -d -m 0750 -o providapt -g providapt /var/lib/providapt /var/log/providapt
install -d -m 0750 /etc/providapt /usr/local/lib/providapt/ebpf

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable providapt.service >/dev/null 2>&1 || true
fi

echo "ProvidAPT package installed. Configure /etc/providapt/providapt.toml, then run: systemctl restart providapt.service"
