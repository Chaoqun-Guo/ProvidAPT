#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$project_dir"
make build-core
make install-local
systemctl enable providapt.service
systemctl restart providapt.service
systemctl --no-pager --full status providapt.service
