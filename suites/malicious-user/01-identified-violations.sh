#!/bin/bash
# Malicious-user: identity-tagged WAF violations
# Drives repeated WAF-blocking attacks (SQLi, XSS, path traversal, command
# injection) all attributed to ONE user identity (X-MUD-User header + x-mud-user
# cookie + mud_user query) so F5 XC Malicious User Detection scores that user's
# threat level and applies the configured mitigation.
# Tools: curl
# Targets: LB-served apps (juice-shop, dvwa, httpbin)
# Estimated duration: 2-4 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-identified-violations.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
USER_ID="${MUD_USER_ID:-mud-attacker-01}"
ITER="${MUD_ITERATIONS:-30}"
ID_ARGS=(-H "X-MUD-User: ${USER_ID}" -b "x-mud-user=${USER_ID}")

echo "[*] Malicious-user WAF violations against ${TARGET} as '${USER_ID}'"

PAYLOADS=(
  "/juice-shop/rest/products/search?q=%27+OR+%271%27%3D%271"
  "/juice-shop/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  "/dvwa/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit"
  "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd"
  "/?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  "/httpbin/get?x=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
)

for _n in $(seq 1 "${ITER}"); do
  for _p in "${PAYLOADS[@]}"; do
    curl -s -o /dev/null -m 5 "${ID_ARGS[@]}" "${BASE}${_p}&mud_user=${USER_ID}" ||
      echo "WARN: request failed for ${_p}"
  done
done

echo "[+] Sent $((ITER * ${#PAYLOADS[@]})) identity-tagged WAF-violating requests as '${USER_ID}'"
