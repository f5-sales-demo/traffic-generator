#!/bin/bash
# service_policy deny traffic (SPol-5) — hits the path an F5 XC LB service_policy rule_list
# DENY rule targets (default: path prefix /spol-denied), so the LB blocks the request and
# raises a security event (action BLOCK/DENY). Also sends an allowed control request.
# Tools: curl
# Targets: www.<domain> deny path
# Estimated duration: <1 minute
# Marker: User-Agent "spol5-verify".
set -euo pipefail

TARGET="${1:?Usage: 01-service-policy-deny.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
DENY_PATH="${DENY_PATH:-/spol-denied}"
UA="spol5-verify"
CURL=(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -A "$UA" -H "X-SPol5-Verify: deny")

echo "[*] service_policy deny traffic against ${BASE}${DENY_PATH}"
for i in 1 2 3 4 5; do
  echo -n "  [$i] GET ${DENY_PATH} (expect deny/BLOCK) -> "
  "${CURL[@]}" "${BASE}${DENY_PATH}" || true
  echo ""
done

echo -n "  GET / (control, expect allow) -> "
"${CURL[@]}" "${BASE}/" || true
echo ""
echo "[*] service_policy deny traffic complete"
