#!/usr/bin/env bash
set -euo pipefail

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop providapt.service >/dev/null 2>&1 || true
  systemctl disable providapt.service >/dev/null 2>&1 || true
fi
