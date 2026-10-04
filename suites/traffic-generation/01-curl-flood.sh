#!/bin/bash
# Rapid HTTP request flood using wrk (event-driven, ~10x more CPU-efficient than curl+xargs)
# Tools: native wrk
# Targets: Multiple endpoints at 100 concurrent connections
# Estimated duration: ~30 seconds per endpoint
set -euo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v wrk >/dev/null || {
  echo "[FAIL] Required native wrk missing" >&2
  exit 1
}

TARGET="${1:?Usage: 01-curl-flood.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

CONCURRENCY="${TGEN_CONCURRENCY:-100}"
DURATION="${TGEN_DURATION:-30}"

echo "[*] Curl flood against ${TARGET}"
echo "    Concurrency: ${CONCURRENCY}"
echo "    Duration: ${DURATION}s per endpoint"
echo ""

# Endpoints to flood
ENDPOINTS=(
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=test"
  "/juice-shop/api/Products/"
  "/dvwa/"
  "/dvwa/login.php"
  "/vampi/"
  "/vampi/users/v1"
)

START=$(date +%s)

echo "[+] Using wrk (event-driven engine)"
echo ""

THREADS=$(nproc 2>/dev/null || echo 2)

for endpoint in "${ENDPOINTS[@]}"; do
  echo "  wrk: ${endpoint}"
  wrk -t"${THREADS}" -c"${CONCURRENCY}" -d"${DURATION}s" "${BASE}${endpoint}" 2>&1 |
    grep -E "(Requests/sec|Latency|Transfer|Socket)" |
    while IFS= read -r line; do
      echo "    ${line}"
    done
  echo ""
done

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo "[*] Curl flood complete"
echo "    Duration: ${ELAPSED}s"
