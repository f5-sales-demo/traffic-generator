#!/bin/bash
# Malicious-user: identity-tagged credential stuffing
# Repeated failed logins from ONE identity (X-MUD-User header + x-mud-user cookie +
# mud_user query), an auth-abuse signal that raises the user's threat level for
# Malicious User Detection.
# Tools: curl
# Targets: LB-served app login endpoints (juice-shop, dvwa)
# Estimated duration: 1-3 minutes
set -euo pipefail

TARGET="${1:?Usage: 03-credential-stuffing.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
USER_ID="${MUD_USER_ID:-mud-attacker-01}"
ITER="${MUD_ITERATIONS:-40}"
ID_ARGS=(-H "X-MUD-User: ${USER_ID}" -b "x-mud-user=${USER_ID}")

echo "[*] Malicious-user credential stuffing against ${TARGET} as '${USER_ID}'"

for _n in $(seq 1 "${ITER}"); do
  curl -s -o /dev/null -m 5 "${ID_ARGS[@]}" -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrong-${_n}\"}" \
    "${BASE}/juice-shop/rest/user/login?mud_user=${USER_ID}" ||
    echo "WARN: juice-shop login attempt ${_n} failed to send"
  curl -s -o /dev/null -m 5 "${ID_ARGS[@]}" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=wrong-${_n}" \
    "${BASE}/dvwa/login.php?mud_user=${USER_ID}" ||
    echo "WARN: dvwa login attempt ${_n} failed to send"
done

echo "[+] Sent $((ITER * 2)) identity-tagged failed-login attempts as '${USER_ID}'"
