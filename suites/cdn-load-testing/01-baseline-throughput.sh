#!/bin/bash
# CDN Scenario 1: Baseline throughput with deep path randomization
# Tools: wrk, curl
# Targets: All 7 CDN endpoints with randomized sub-paths, XFF, Accept-Encoding
# Estimated duration: 3-5 minutes
set -uo pipefail
. "$(dirname "$0")/_lib.sh"

DURATION="${TGEN_DURATION:-${2:-60}}"
THREADS=4
CONNS="${TGEN_CONCURRENCY:-500}"
LUA_SCRIPT="$(dirname "$0")/_baseline.lua"

echo "[*] CDN Baseline Throughput — deep path randomization"
echo "[*] Target: $BASE"
echo "[*] Config: ${THREADS}t/${CONNS}c/${DURATION}s per endpoint + combined"
echo ""

ENDPOINTS=(
  "/juice-shop/"
  "/whoami/"
  "/httpbin/get"
  "/dvwa/login.php"
  "/vampi/users/v1"
  "/csd-demo/health"
  "/health"
)

# Phase 1: Per-endpoint throughput with static paths (baseline measurement)
echo "[+] Phase 1: Per-endpoint baseline throughput"
echo ""
for ep in "${ENDPOINTS[@]}"; do
  echo "  --- $ep ---"
  if command -v wrk >/dev/null 2>&1; then
    wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --timeout 10s \
      -H "X-Forwarded-For: $(rand_ip)" \
      -H "Accept-Encoding: $(rand_encoding)" \
      "${BASE}${ep}" 2>&1 | grep -E "Requests/sec|Latency|Transfer" | sed 's/^/    /'
  else
    echo "    [SKIP] wrk not available"
  fi
  echo ""
done

# Phase 2: Combined randomized throughput (all paths, all headers randomized)
echo "[+] Phase 2: Combined randomized throughput (Lua script)"
if command -v wrk >/dev/null 2>&1 && [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" 2>&1 | grep -E "Requests/sec|Latency|Transfer|Socket" | sed 's/^/    /'
else
  echo "    [SKIP] wrk or Lua script not available"
fi
echo ""

# Phase 3: Cache status verification
echo "[+] Phase 3: Cache status verification (post-warmup)"
for ep in "${ENDPOINTS[@]}"; do
  # Prime the cache
  curl -sf -o /dev/null --max-time 5 "${BASE}${ep}" 2>/dev/null
  sleep 0.1
  # Check cache status
  STATUS=$(check_cache_status "${BASE}${ep}")
  if [ "$STATUS" = "HIT" ]; then
    pass "$ep → X-Cache-Status: $STATUS"
  elif [ "$STATUS" = "MISS" ] || [ "$STATUS" = "NONE" ]; then
    fail "$ep → X-Cache-Status: $STATUS (expected HIT after warmup)"
  else
    pass "$ep → X-Cache-Status: $STATUS (STALE/UPDATING acceptable)"
  fi
done

summary
