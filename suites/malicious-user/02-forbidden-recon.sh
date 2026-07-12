#!/bin/bash
# Malicious-user: identity-tagged forbidden-path recon
# Repeated forbidden/sensitive-path probes and 4xx-inducing requests from ONE
# identity (X-MUD-User header + x-mud-user cookie + mud_user query), raising that
# user's threat level via reconnaissance + error-rate signals for Malicious User
# Detection.
# Tools: curl
# Targets: LB-served apps (forbidden paths, httpbin status codes)
# Estimated duration: 1-3 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-forbidden-recon.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
USER_ID="${MUD_USER_ID:-mud-attacker-01}"
ITER="${MUD_ITERATIONS:-30}"
ID_ARGS=(-H "X-MUD-User: ${USER_ID}" -b "x-mud-user=${USER_ID}")

echo "[*] Malicious-user forbidden-path recon against ${TARGET} as '${USER_ID}'"

PATHS=(
  "/admin"
  "/.env"
  "/.git/config"
  "/wp-login.php"
  "/phpmyadmin/"
  "/actuator/env"
  "/api/v1/secrets"
  "/server-status"
  "/httpbin/status/401"
  "/httpbin/status/403"
  "/httpbin/status/404"
)

for _n in $(seq 1 "${ITER}"); do
  for _p in "${PATHS[@]}"; do
    curl -s -o /dev/null -m 5 "${ID_ARGS[@]}" "${BASE}${_p}?mud_user=${USER_ID}" ||
      echo "WARN: request failed for ${_p}"
  done
done

echo "[+] Sent $((ITER * ${#PATHS[@]})) identity-tagged forbidden/recon requests as '${USER_ID}'"
