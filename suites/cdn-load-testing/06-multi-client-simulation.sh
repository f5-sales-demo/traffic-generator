#!/bin/bash
# CDN Scenario 6: Multi-client IP simulation via X-Forwarded-For
# Tools: wrk (Lua), curl
# Targets: All endpoints with 768 unique IPs, correlated CDN vendor headers
# Estimated duration: 3-5 minutes
set -uo pipefail
. "$(dirname "$0")/_lib.sh"

DURATION="${TGEN_DURATION:-${2:-60}}"
THREADS=4
CONNS="${TGEN_CONCURRENCY:-400}"
LUA_SCRIPT="$(dirname "$0")/_multi-client.lua"

echo "[*] CDN Multi-Client IP Simulation"
echo "[*] Target: $BASE"
echo "[*] Source IPs: 768 unique (3x RFC 5737 /24 test-net ranges)"
echo "[*] Constraint: single source IP, diversity via X-Forwarded-For + vendor headers"
echo ""

# Phase 1: Verify XFF header passthrough
echo "[+] Phase 1: Verify CDN header passthrough via /httpbin/headers"
for i in $(seq 1 5); do
  IP=$(rand_ip)
  BODY=$(curl -sf --max-time 5 \
    -H "X-Forwarded-For: $IP" \
    -H "True-Client-IP: $IP" \
    -H "CF-Connecting-IP: $IP" \
    -H "Fastly-Client-IP: $IP" \
    "${BASE}/httpbin/headers" 2>/dev/null)

  XFF_ECHO=$(echo "$BODY" | grep -o "X-Forwarded-For[^\"]*\"[^\"]*\"" | head -1 || echo "")
  if echo "$XFF_ECHO" | grep -q "$IP"; then
    pass "XFF $IP echoed correctly"
  else
    fail "XFF $IP not found in response"
  fi
done
echo ""

# Phase 2: Per-thread cookie jar isolation
echo "[+] Phase 2: Independent session isolation (200 parallel curl workers)"
WORKER_COUNT="${TGEN_CONCURRENCY:-200}"
REQUESTS_PER_WORKER="${TGEN_REQUESTS_PER_WORKER:-50}"
TOTAL_EXPECTED=$((WORKER_COUNT * REQUESTS_PER_WORKER))

TMPDIR="/tmp/cdn-multi-client-$$"
mkdir -p "$TMPDIR"

START_TIME=$(date +%s)
for w in $(seq 1 "$WORKER_COUNT"); do
  (
    JAR="$TMPDIR/jar-${w}.txt"
    IP=$(rand_ip)
    SUCCESS=0
    for r in $(seq 1 "$REQUESTS_PER_WORKER"); do
      PATH_CHOICE=$(rand_any_path)
      HTTP_CODE=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 \
        -b "$JAR" -c "$JAR" \
        -H "X-Forwarded-For: $IP" \
        -H "True-Client-IP: $IP" \
        -H "CF-Connecting-IP: $IP" \
        -H "User-Agent: $(rand_ua)" \
        -H "Accept-Encoding: $(rand_encoding)" \
        "${BASE}${PATH_CHOICE}" 2>/dev/null || echo "000")
      if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 500 ] 2>/dev/null; then
        SUCCESS=$((SUCCESS + 1))
      fi
    done
    echo "$SUCCESS" >"$TMPDIR/result-${w}.txt"
    rm -f "$JAR"
  ) &

  # Rate-limit worker spawning to avoid fork bomb
  if [ $((w % 50)) -eq 0 ]; then
    wait
  fi
done
wait
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Aggregate results
TOTAL_SUCCESS=0
for f in "$TMPDIR"/result-*.txt; do
  [ -f "$f" ] && TOTAL_SUCCESS=$((TOTAL_SUCCESS + $(cat "$f")))
done

echo "    Workers: $WORKER_COUNT"
echo "    Requests per worker: $REQUESTS_PER_WORKER"
echo "    Total attempted: $TOTAL_EXPECTED"
echo "    Total successful: $TOTAL_SUCCESS"
echo "    Duration: ${ELAPSED}s"
if [ "$ELAPSED" -gt 0 ]; then
  echo "    Effective rate: $((TOTAL_SUCCESS / ELAPSED)) req/s"
fi

SUCCESS_RATE=$((TOTAL_SUCCESS * 100 / TOTAL_EXPECTED))
if [ "$SUCCESS_RATE" -ge 90 ]; then
  pass "Multi-client isolation: ${SUCCESS_RATE}% success rate"
else
  fail "Multi-client isolation: ${SUCCESS_RATE}% success rate (expected >=90%)"
fi

rm -rf "$TMPDIR"
echo ""

# Phase 3: wrk with multi-client Lua (high throughput + header diversity)
echo "[+] Phase 3: High-throughput multi-client simulation (wrk + Lua)"
if command -v wrk >/dev/null 2>&1 && [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" 2>&1 | grep -E "Requests/sec|Latency|Transfer|Socket" | sed 's/^/    /'
  pass "wrk multi-client Lua completed (${THREADS}t/${CONNS}c/${DURATION}s)"
else
  fail "wrk or Lua script not available"
fi

summary
