#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: postgres-drill.sh --dsn DSN --out backup.sql [--restore-dsn DSN]

Create a PostgreSQL logical backup with pg_dump. When --restore-dsn is supplied,
restore the dump into a staging database and run a lightweight sanity query.
EOF
}

dsn="${PROVIDAPT_DATABASE_DSN:-}"
out=""
restore_dsn="${PROVIDAPT_RESTORE_DSN:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dsn)
      dsn="${2:-}"
      shift 2
      ;;
    --out)
      out="${2:-}"
      shift 2
      ;;
    --restore-dsn)
      restore_dsn="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$dsn" ] || [ -z "$out" ]; then
  usage >&2
  exit 2
fi

for tool in pg_dump psql; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required" >&2
    exit 2
  fi
done

mkdir -p "$(dirname "$out")"
umask 077
pg_dump "$dsn" > "$out"
bytes="$(wc -c < "$out" | tr -d ' ')"
echo "backup_written path=$out bytes=$bytes"

if [ -n "$restore_dsn" ]; then
  psql "$restore_dsn" -v ON_ERROR_STOP=1 < "$out" >/dev/null
  psql "$restore_dsn" -v ON_ERROR_STOP=1 -c "select now() as restore_checked_at;" >/dev/null
  echo "restore_check=pass"
else
  echo "restore_check=skipped reason=no_restore_dsn"
fi
