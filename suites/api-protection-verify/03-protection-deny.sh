#!/bin/bash
# API-protection deny traffic — hits the endpoint(s) an F5 XC LB api_protection_rules
# "deny" rule targets (default SP3 rule: POST /api/admin), so the LB blocks the request
# and raises an API-protection security event (action BLOCK). Also sends an allowed
# control request for contrast.
# Tools: curl
# Targets: api.<domain> protected paths
# Estimated duration: <1 minute
# Marker: User-Agent "sp5-api-verify".
set -euo pipefail

TARGET="${1:?Usage: 03-protection-deny.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
UA="sp5-api-verify"
CURL=(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -A "$UA" -H "X-SP5-Verify: protection-deny")

echo "[*] API-protection deny traffic against ${BASE}"

# The SP3 default api_protection_rules deny target is POST /api/admin. Hit it a few
# times so the block is unambiguous in the event log.
for i in 1 2 3; do
  echo -n "  [$i] POST /api/admin (expect deny/BLOCK) -> "
  "${CURL[@]}" -X POST -H 'Content-Type: application/json' \
    --data '{"op":"escalate"}' "${BASE}/api/admin" || true
  echo ""
done

# Allowed control request (should NOT be blocked) for contrast in the event log.
echo -n "  GET /vampi/ (control, expect allow) -> "
"${CURL[@]}" "${BASE}/vampi/" || true
echo ""

echo "[*] API-protection deny traffic complete"
