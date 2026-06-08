#!/usr/bin/env bash
set -euo pipefail

# Example rollback skeleton for ProvidAPT upgrades.
# Adjust paths and service names for your environment before use.

SERVICE_NAME="${SERVICE_NAME:-providaptd}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/providapt}"
INSTALL_DIR="${INSTALL_DIR:-/opt/providapt}"
ROLLBACK_VERSION="${1:-}"

if [[ -z "${ROLLBACK_VERSION}" ]]; then
  echo "usage: $0 <rollback-version>"
  exit 1
fi

ARCHIVE_PATH="${BACKUP_DIR}/providapt-${ROLLBACK_VERSION}.tar.gz"

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  echo "rollback archive not found: ${ARCHIVE_PATH}"
  exit 1
fi

echo "[rollback] stopping ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}"

echo "[rollback] restoring ${ARCHIVE_PATH} into ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
tar -xzf "${ARCHIVE_PATH}" -C "${INSTALL_DIR}"

echo "[rollback] starting ${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

echo "[rollback] completed for version ${ROLLBACK_VERSION}"
