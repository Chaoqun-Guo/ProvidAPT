#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: validate-secret-env.sh secret.env

Validate a ProvidAPT production secret env-file before it is wired into
systemd, Docker Compose, Kubernetes Secret generation, or a customer pipeline.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 1 ]; then
  usage >&2
  exit 2
fi

env_file="$1"
if [ ! -f "$env_file" ]; then
  echo "FAIL missing env file: $env_file" >&2
  exit 1
fi

mode=""
if stat -c '%a' "$env_file" >/dev/null 2>&1; then
  mode="$(stat -c '%a' "$env_file")"
elif stat -f '%Lp' "$env_file" >/dev/null 2>&1; then
  mode="$(stat -f '%Lp' "$env_file")"
fi

failed=0
if [ -n "$mode" ]; then
  case "$mode" in
    600|400|640|440)
      echo "OK permissions $mode $env_file"
      ;;
    *)
      echo "WARN permissions $mode should be 600, 400, 640, or 440"
      if [ "${STRICT_PERMISSIONS:-0}" = "1" ]; then
        failed=1
      fi
      ;;
  esac
fi

required_vars=(
  PROVIDAPT_API_AUTH_KEYS
  PROVIDAPT_POLICY_API_KEY
  PROVIDAPT_SIEM_TOKEN
  PROVIDAPT_NOTIFY_WEBHOOK_SECRET
  PROVIDAPT_DATABASE_DSN
)

recommended_vars=(
  PROVIDAPT_LICENSE_SIGNING_KEY
  PROVIDAPT_UPGRADE_SIGNING_KEY
  PROVIDAPT_NOTIFY_SMTP_PASS
  PROVIDAPT_NOTIFY_TICKET_WEBHOOK_AUTH
  PROVIDAPT_NOTIFY_JIRA_API_TOKEN
  PROVIDAPT_NOTIFY_SERVICENOW_PASS
)

declare -A values=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in
    ""|\#*) continue ;;
  esac
  if [[ "$line" != *=* ]]; then
    echo "FAIL malformed line: $line"
    failed=1
    continue
  fi
  key="${line%%=*}"
  value="${line#*=}"
  key="$(echo "$key" | xargs)"
  value="$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  values["$key"]="$value"
done < "$env_file"

is_placeholder() {
  local value="$1"
  local lower
  lower="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    ""|change_me*|*change_me*|changeme|replace*|*replace-with*|*placeholder*|*example.com*|*'<password>'*)
      return 0
      ;;
  esac
  return 1
}

validate_secret_value() {
  local key="$1"
  local min_len="$2"
  local value="${values[$key]:-}"
  if is_placeholder "$value"; then
    echo "FAIL $key is missing or still contains a placeholder"
    failed=1
    return
  fi
  if [ "${#value}" -lt "$min_len" ]; then
    echo "FAIL $key length ${#value} is below minimum $min_len"
    failed=1
    return
  fi
  echo "OK $key"
}

for key in "${required_vars[@]}"; do
  validate_secret_value "$key" 16
done

for key in "${recommended_vars[@]}"; do
  value="${values[$key]:-}"
  if [ -z "$value" ]; then
    echo "WARN $key is not set; confirm this integration is intentionally disabled"
    continue
  fi
  validate_secret_value "$key" 16
done

dsn="${values[PROVIDAPT_DATABASE_DSN]:-}"
if [[ "$dsn" =~ ^postgres(ql)?:// ]]; then
  password_part="${dsn#*://}"
  password_part="${password_part#*:}"
  password_part="${password_part%@*}"
  if [ "$password_part" = "$dsn" ] || [ -z "$password_part" ] || is_placeholder "$password_part"; then
    echo "FAIL PROVIDAPT_DATABASE_DSN must include a non-placeholder password"
    failed=1
  elif [ "${#password_part}" -lt 12 ]; then
    echo "FAIL PROVIDAPT_DATABASE_DSN password length ${#password_part} is below minimum 12"
    failed=1
  else
    echo "OK PROVIDAPT_DATABASE_DSN password"
  fi
else
  echo "FAIL PROVIDAPT_DATABASE_DSN must use postgres:// or postgresql://"
  failed=1
fi

if [ "$failed" -eq 0 ]; then
  echo "secret env validation passed"
else
  echo "secret env validation failed" >&2
fi
exit "$failed"
