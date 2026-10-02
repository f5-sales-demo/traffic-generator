#!/bin/bash
# Sustained load test — continuous traffic for a fixed duration
# Tools: wrk (primary), curl+xargs (fallback)
# Measures: throughput stability over time, error rate trend, latency degradation
# Estimated duration: 2 minutes (configurable)
set -uo pipefail

TARGET="${1:?Usage: 03-sustained-load.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

DURATION_SECS="${TGEN_DURATION:-120}"
CONCURRENCY="${TGEN_CONCURRENCY:-50}"
INTERVAL=10

ENDPOINTS=(
  "/health"
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=test"
  "/vampi/users/v1"
  "/httpbin/get"
  "/whoami/"
  "/csd-demo/health"
  "/dvwa/login.php"
)

echo "[*] Sustained load test against ${TARGET}"
echo "    Duration: ${DURATION_SECS}s"
echo "    Concurrency: ${CONCURRENCY}"
echo "    Sample interval: ${INTERVAL}s"
echo ""

USE_WRK=false
if command -v wrk &>/dev/null; then
  USE_WRK=true
  echo "[+] Using wrk (event-driven engine)"
else
  echo "[+] wrk not found — falling back to curl+xargs"
fi
echo ""

printf "%6s %6s %6s %6s %8s %8s %8s\n" \
  "Time" "Sent" "OK" "Fail" "Avg(s)" "P99(s)" "Req/s"
echo "------ ------ ------ ------ -------- -------- --------"

elapsed=0
total_sent=0
total_ok=0
total_fail=0
THREADS=$(nproc 2>/dev/null || echo 2)

while [[ $elapsed -lt $DURATION_SECS ]]; do
  endpoint="${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}"
  url="${BASE}${endpoint}"

  if [[ "$USE_WRK" == "true" ]]; then
    # Use wrk for this interval — duration-based, no manual batching needed
    wrk_output=$(wrk -t"${THREADS}" -c"${CONCURRENCY}" -d"${INTERVAL}s" "${url}" 2>&1)

    # Parse wrk output
    rps=$(echo "$wrk_output" | grep "Requests/sec" | awk '{print $2}')
    latency_avg=$(echo "$wrk_output" | grep "Latency" | awk '{print $2}')
    # Convert wrk latency (e.g., "12.34ms" or "1.23s") to seconds
    if echo "$latency_avg" | grep -q "ms$"; then
      avg=$(echo "$latency_avg" | sed 's/ms$//' | awk '{printf "%.3f", $1/1000}')
    elif echo "$latency_avg" | grep -q "us$"; then
      avg=$(echo "$latency_avg" | sed 's/us$//' | awk '{printf "%.6f", $1/1000000}')
    else
      avg=$(echo "$latency_avg" | sed 's/s$//')
    fi

    # wrk reports total requests and errors
    requests_line=$(echo "$wrk_output" | grep "requests in")
    sent=$(echo "$requests_line" | awk '{print $1}')
    [[ -z "$sent" ]] && sent=0

    socket_errors=$(echo "$wrk_output" | grep "Socket errors" || true)
    if [[ -n "$socket_errors" ]]; then
      err_connect=$(echo "$socket_errors" | awk -F'connect ' '{print $2}' | awk -F',' '{print $1}')
      err_read=$(echo "$socket_errors" | awk -F'read ' '{print $2}' | awk -F',' '{print $1}')
      err_write=$(echo "$socket_errors" | awk -F'write ' '{print $2}' | awk -F',' '{print $1}')
      err_timeout=$(echo "$socket_errors" | awk -F'timeout ' '{print $2}')
      fail=$((${err_connect:-0} + ${err_read:-0} + ${err_write:-0} + ${err_timeout:-0}))
    else
      fail=0
    fi
    non_2xx=$(echo "$wrk_output" | grep "Non-2xx" | awk '{print $NF}' || true)
    [[ -n "$non_2xx" ]] && fail=$((fail + non_2xx))

    ok=$((sent - fail))
    [[ "$ok" -lt 0 ]] && ok=0
    # wrk doesn't output p99 by default; use "N/A"
    p99="N/A"

  else
    requests_this_interval=$((CONCURRENCY * 2))
    start_ns=$(date +%s%N)

    for i in $(seq "$requests_this_interval"); do
      ep="${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}"
      echo "${BASE}${ep}"
    done | xargs -P"$CONCURRENCY" -I{} \
      curl -sf -o /dev/null -w "%{http_code} %{time_total}\n" \
      --max-time 10 --connect-timeout 5 {} 2>/dev/null >/tmp/sustained-results-$$.txt

    end_ns=$(date +%s%N)
    wall_ms=$(((end_ns - start_ns) / 1000000))

    results=$(cat /tmp/sustained-results-$$.txt)
    sent=$(echo "$results" | grep -c . || echo 0)
    ok=$(echo "$results" | grep -c '^[23]0[0-9] ' || true)
    fail=$((sent - ok))

    avg=$(echo "$results" | awk '{sum+=$2; n++} END {if(n>0) printf "%.3f", sum/n; else print "0"}')
    p99=$(echo "$results" | awk '{print $2}' | sort -n | awk -v p=99 'BEGIN{c=0} {a[c++]=$1} END{idx=int(c*p/100); if(idx>=c)idx=c-1; printf "%.3f", a[idx]}')
    rps=$(awk "BEGIN {if($wall_ms>0) printf \"%.1f\", $sent / ($wall_ms / 1000.0); else print \"N/A\"}")
  fi

  total_sent=$((total_sent + sent))
  total_ok=$((total_ok + ok))
  total_fail=$((total_fail + fail))

  flag=""
  if [[ "$fail" -gt 0 ]]; then flag=" !!"; fi

  printf "%5ds %6d %6d %6d %8s %8s %8s%s\n" \
    "$elapsed" "$sent" "$ok" "$fail" "${avg:-N/A}" "${p99:-N/A}" "${rps:-N/A}" "$flag"

  # wrk already consumes the interval duration; for curl fallback, sleep
  if [[ "$USE_WRK" != "true" ]]; then
    sleep "$INTERVAL"
  fi
  elapsed=$((elapsed + INTERVAL))
done

[[ -f /tmp/sustained-results-$$.txt ]] && rm -f /tmp/sustained-results-$$.txt

echo ""
echo "[*] Sustained load test complete"
echo "    Total sent:    ${total_sent}"
echo "    Total OK:      ${total_ok}"
echo "    Total failed:  ${total_fail}"
success_pct=$((total_ok * 100 / (total_sent > 0 ? total_sent : 1)))
echo "    Success rate:  ${success_pct}%"

if [[ "$total_fail" -gt 0 ]]; then
  echo "    ** BOTTLENECK: ${total_fail} failures during sustained load **"
fi
