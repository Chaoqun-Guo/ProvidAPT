#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: postgres-drill.sh --dsn DSN --out backup.sql [--restore-dsn DSN] [--report-json path] [--report-md path]

Create a PostgreSQL logical backup with pg_dump. When --restore-dsn is supplied,
restore the dump into a staging database and run a lightweight sanity query.
Reports redact passwords from DSNs.
EOF
}

dsn="${PROVIDAPT_DATABASE_DSN:-}"
out=""
restore_dsn="${PROVIDAPT_RESTORE_DSN:-}"
report_json=""
report_md=""
schema_table="providapt_control_plane_ha"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
restore_status="skipped"
restore_message="no_restore_dsn"
schema_status="skipped"
schema_message="restore_dsn_not_supplied"
backup_status="pending"
backup_bytes=0
pg_dump_version=""
psql_version=""

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
    --report-json)
      report_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --schema-table)
      schema_table="${2:-}"
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
if ! [[ "$schema_table" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
  echo "--schema-table must be an unquoted PostgreSQL identifier" >&2
  exit 2
fi

for tool in pg_dump psql; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required" >&2
    exit 2
  fi
done

redact_dsn() {
  printf '%s' "$1" | sed -E 's#(postgres(ql)?://[^:/@]+:)[^@]+@#\1<redacted>@#'
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

write_reports() {
  local completed_at redacted_dsn redacted_restore json_path md_path
  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  redacted_dsn="$(redact_dsn "$dsn")"
  redacted_restore="$(redact_dsn "$restore_dsn")"
  if [ -n "$report_json" ]; then
    json_path="$report_json"
    mkdir -p "$(dirname "$json_path")"
    cat > "$json_path" <<EOF
{
  "schema": "providapt.postgres_drill.v1",
  "started_at": "$started_at",
  "completed_at": "$completed_at",
  "dsn": $(printf '%s' "$redacted_dsn" | json_escape),
  "restore_dsn": $(printf '%s' "$redacted_restore" | json_escape),
  "backup": {
    "status": "$backup_status",
    "path": $(printf '%s' "$out" | json_escape),
    "bytes": $backup_bytes
  },
  "restore": {
    "status": "$restore_status",
    "message": $(printf '%s' "$restore_message" | json_escape)
  },
  "schema_check": {
    "status": "$schema_status",
    "table": $(printf '%s' "$schema_table" | json_escape),
    "message": $(printf '%s' "$schema_message" | json_escape)
  },
  "tools": {
    "pg_dump": $(printf '%s' "$pg_dump_version" | json_escape),
    "psql": $(printf '%s' "$psql_version" | json_escape)
  }
}
EOF
    echo "report_json=$json_path"
  fi
  if [ -n "$report_md" ]; then
    md_path="$report_md"
    mkdir -p "$(dirname "$md_path")"
    cat > "$md_path" <<EOF
# PostgreSQL Drill Report

Started: $started_at
Completed: $completed_at

| Check | Status | Detail |
| --- | --- | --- |
| Backup | $backup_status | $out ($backup_bytes bytes) |
| Restore | $restore_status | $restore_message |
| Schema | $schema_status | $schema_table: $schema_message |

DSN: \`$redacted_dsn\`
Restore DSN: \`$redacted_restore\`

Tools:

- pg_dump: \`$pg_dump_version\`
- psql: \`$psql_version\`
EOF
    echo "report_md=$md_path"
  fi
}

mkdir -p "$(dirname "$out")"
umask 077
pg_dump_version="$(pg_dump --version 2>/dev/null || true)"
psql_version="$(psql --version 2>/dev/null || true)"
pg_dump "$dsn" > "$out"
bytes="$(wc -c < "$out" | tr -d ' ')"
backup_bytes="$bytes"
backup_status="pass"
echo "backup_written path=$out bytes=$bytes"

if [ -n "$restore_dsn" ]; then
  psql "$restore_dsn" -v ON_ERROR_STOP=1 < "$out" >/dev/null
  psql "$restore_dsn" -v ON_ERROR_STOP=1 -c "select now() as restore_checked_at;" >/dev/null
  if psql "$restore_dsn" -v ON_ERROR_STOP=1 -Atc "select to_regclass('${schema_table}');" | grep -q "$schema_table"; then
    schema_status="pass"
    schema_message="table_present"
  else
    schema_status="warn"
    schema_message="table_not_found"
  fi
  restore_status="pass"
  restore_message="restore_query_passed"
  echo "restore_check=pass"
else
  restore_status="skipped"
  restore_message="no_restore_dsn"
  echo "restore_check=skipped reason=no_restore_dsn"
fi

write_reports
