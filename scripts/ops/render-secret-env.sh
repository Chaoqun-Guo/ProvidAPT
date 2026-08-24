#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: render-secret-env.sh [-o output.env]

Generate a production secret environment template for ProvidAPT.
The output intentionally contains placeholders and must be filled by the
operator-approved secret manager or deployment pipeline.
EOF
}

out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output)
      out="${2:-}"
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

content="$(cat <<'EOF'
# ProvidAPT production secret template.
# Replace every CHANGE_ME value through an operator-approved secret manager.

PROVIDAPT_SIEM_TOKEN=CHANGE_ME_SIEM_TOKEN
PROVIDAPT_UPGRADE_SIGNING_KEY=CHANGE_ME_UPGRADE_SIGNING_KEY_OR_USE_PUBLIC_KEY_PATH
PROVIDAPT_NOTIFY_SMTP_PASS=CHANGE_ME_SMTP_PASSWORD
PROVIDAPT_NOTIFY_WEBHOOK_SECRET=CHANGE_ME_WEBHOOK_SECRET
PROVIDAPT_NOTIFY_TICKET_WEBHOOK_AUTH=CHANGE_ME_TICKET_WEBHOOK_AUTH
PROVIDAPT_NOTIFY_JIRA_API_TOKEN=CHANGE_ME_JIRA_API_TOKEN
PROVIDAPT_NOTIFY_SERVICENOW_PASS=CHANGE_ME_SERVICENOW_PASSWORD
PROVIDAPT_DATABASE_DSN=postgres://providapt:CHANGE_ME_POSTGRES_PASSWORD@postgres.example.com:5432/providapt?sslmode=require
EOF
)"

if [ -n "$out" ]; then
  umask 077
  printf '%s\n' "$content" > "$out"
  echo "wrote $out"
else
  printf '%s\n' "$content"
fi
