#!/bin/bash
# Shadow-API traffic — requests API-looking paths that are NOT in the published
# OpenAPI spec, so F5 XC API Discovery learns/flags them as shadow (undocumented)
# endpoints. Verify by checking the discovered-endpoints inventory / discovery events.
# Tools: curl
# Targets: api.<domain> undocumented paths
# Estimated duration: <1 minute
# Marker: User-Agent "sp5-api-verify".
set -euo pipefail

TARGET="${1:?Usage: 02-shadow-endpoints.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
UA="sp5-api-verify"
CURL=(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -A "$UA" -H "X-SP5-Verify: shadow-endpoint")

echo "[*] Shadow-endpoint traffic against ${BASE}"

# Undocumented / internal-looking API paths (not present in any published spec).
SHADOW=(
  "/crapi/identity/api/v2/admin/users/debug"
  "/crapi/workshop/api/internal/metrics"
  "/vampi/_debug/config"
  "/vampi/users/v1/_internal/dump"
  "/api/internal/healthz-secret"
  "/api/v0/legacy/accounts/export"
)

for path in "${SHADOW[@]}"; do
  echo -n "  GET ${path} -> "
  "${CURL[@]}" "${BASE}${path}" || true
  echo ""
  # A couple of hits each so discovery registers a stable pattern, not a one-off.
  "${CURL[@]}" "${BASE}${path}" >/dev/null || true
done

echo "[*] Shadow-endpoint traffic complete"
