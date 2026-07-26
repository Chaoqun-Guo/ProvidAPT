#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: check-tls-expiry.sh [-w days] cert.pem [cert2.pem ...]

Fail when a certificate expires within the warning window.
EOF
}

warn_days=30
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--warn-days)
      warn_days="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 2
fi

threshold=$((warn_days * 24 * 60 * 60))
failed=0

for cert in "$@"; do
  if [ ! -f "$cert" ]; then
    echo "MISSING $cert"
    failed=1
    continue
  fi
  subject="$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject=//')"
  enddate="$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')"
  if openssl x509 -in "$cert" -checkend "$threshold" -noout >/dev/null 2>&1; then
    echo "OK $cert expires '$enddate' subject '$subject'"
  else
    echo "WARN $cert expires within ${warn_days}d: '$enddate' subject '$subject'"
    failed=1
  fi
done

exit "$failed"
