#!/bin/bash
# CDN Scenario 4: Thundering herd / cache stampede test
# Tools: hey, curl
# Targets: Cold-cache URLs hit with 500+ concurrent requests simultaneously
# Estimated duration: 2-3 minutes
set -uo pipefail
. "$(dirname "$0")/_lib.sh"

CONCURRENCY="${TGEN_CONCURRENCY:-500}"
REQUESTS="${TGEN_REQUESTS:-5000}"

echo "[*] CDN Thundering Herd / Cache Stampede Test"
echo "[*] Target: $BASE"
echo "[*] Config: $REQUESTS requests, $CONCURRENCY concurrent per endpoint"
echo ""

if ! command -v hey >/dev/null 2>&1; then
  echo "[FAIL] hey not installed — required for stampede test"
  exit 1
fi

STAMPEDE_ENDPOINTS=(
  "/httpbin/get"
  "/juice-shop/"
  "/whoami/"
)

for ep in "${STAMPEDE_ENDPOINTS[@]}"; do
  # Generate unique query string for guaranteed cold cache
  STAMP="stampede-$(date +%s%N)-${RANDOM}"
  URL="${BASE}${ep}?${STAMP}"

  echo "[+] Stampede: ${ep}?${STAMP}"
  echo "    Firing $REQUESTS requests at $CONCURRENCY concurrency..."

  TMPFILE="/tmp/hey-stampede-$$.txt"
  hey -n "$REQUESTS" -c "$CONCURRENCY" -t 10 "$URL" >"$TMPFILE" 2>&1

  # Parse results
  TOTAL=$(grep "requests in" "$TMPFILE" | awk '{print $1}' || echo "$REQUESTS")
  RPS=$(grep "Requests/sec" "$TMPFILE" | awk '{print $2}')
  STATUS_200=$(grep -E "^\s+\[200\]" "$TMPFILE" | awk '{print $2}' || echo "0")
  STATUS_502=$(grep -E "^\s+\[502\]" "$TMPFILE" | awk '{print $2}' || echo "0")
  STATUS_503=$(grep -E "^\s+\[503\]" "$TMPFILE" | awk '{print $2}' || echo "0")
  ERRORS=$(grep "Error distribution" -A 50 "$TMPFILE" | grep -v "Error distribution" | grep -c "." || echo "0")

  echo "    Requests/sec: ${RPS:-N/A}"
  echo "    Status 200: ${STATUS_200:-all}"
  echo "    Status 502: ${STATUS_502:-0}"
  echo "    Status 503: ${STATUS_503:-0}"
  echo "    Errors: ${ERRORS:-0}"

  # Verify post-stampede: URL should now be cached
  sleep 0.5
  POST_STATUS=$(check_cache_status "$URL")
  echo "    Post-stampede cache: $POST_STATUS"

  if [ "${STATUS_502:-0}" = "0" ] && [ "${STATUS_503:-0}" = "0" ]; then
    pass "${ep} stampede: $REQUESTS requests, 0 errors, 0 502s"
  else
    fail "${ep} stampede: 502s=${STATUS_502:-0} 503s=${STATUS_503:-0} errors=${ERRORS:-0}"
  fi

  if [ "$POST_STATUS" = "HIT" ]; then
    pass "${ep} post-stampede: cached (X-Cache-Status: HIT)"
  else
    fail "${ep} post-stampede: not cached ($POST_STATUS)"
  fi

  rm -f "$TMPFILE"
  echo ""
done

summary
