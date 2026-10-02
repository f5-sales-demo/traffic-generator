#!/bin/bash
# vegeta constant-rate attack — measures how the origin handles sustained req/s
# Tools: vegeta
# Unlike wrk (max throughput), vegeta sends at a FIXED rate and measures degradation
# Estimated duration: 3 minutes
set -uo pipefail

TARGET="${1:?Usage: 11-vegeta-constant-rate.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

if ! command -v vegeta &>/dev/null; then
  echo "FAIL: vegeta not installed"
  exit 1
fi

DURATION="${TGEN_DURATION:-20}"s

RATES=(5 10 "${TGEN_ATTACK_RATE:-20}")

TARGETS_FILE=$(mktemp)
cat >"$TARGETS_FILE" <<EOF
GET ${BASE}/health
GET ${BASE}/juice-shop/
GET ${BASE}/juice-shop/rest/products/search?q=test
GET ${BASE}/vampi/users/v1
GET ${BASE}/httpbin/get
GET ${BASE}/whoami/
GET ${BASE}/csd-demo/health
GET ${BASE}/dvwa/login.php
EOF

echo "[*] vegeta constant-rate attack against ${TARGET}"
echo "    Duration per rate: ${DURATION}"
echo "    Endpoints: $(wc -l <"$TARGETS_FILE")"
echo ""
printf "  %-8s %8s %8s %8s %8s %10s %8s %8s\n" \
  "Rate" "OK" "Errors" "Avg" "P50" "P99" "Max" "Bytes/s"
echo "  -------- -------- -------- -------- -------- ---------- -------- --------"

for rate in "${RATES[@]}"; do
  result=$(vegeta attack -targets="$TARGETS_FILE" -rate="$rate" -duration="$DURATION" -timeout=30s 2>/dev/null |
    vegeta report -type=text 2>/dev/null)

  rps=$(echo "$result" | grep 'Requests' | head -1 | awk '{print $3}')
  ok=$(echo "$result" | grep '200' | awk '{print $2}' | head -1)
  errs=$(echo "$result" | grep 'Error Set' -A100 | grep -v 'Error Set' | head -3 | tr '\n' ' ')
  status_line=$(echo "$result" | grep 'Status Codes')
  ok_count=$(echo "$status_line" | grep -oP '\[200\]\s+\K\d+' || echo "0")
  total_count=$(echo "$result" | grep 'Requests' | head -1 | awk '{print $3}' | sed 's/,//')

  avg=$(echo "$result" | grep 'mean' | head -1 | awk '{print $2}')
  p50=$(echo "$result" | grep '50th' | awk '{print $2}')
  p99=$(echo "$result" | grep '99th' | awk '{print $2}')
  max=$(echo "$result" | grep 'max' | head -1 | awk '{print $2}')
  bytes=$(echo "$result" | grep 'Bytes In' | awk '{print $4}')

  err_count=0
  if echo "$result" | grep -q 'Error Set'; then
    err_count=$(echo "$result" | grep -cE '^\s+[a-z]' || echo "0")
  fi

  flag=""
  if [[ "$err_count" -gt 0 ]]; then flag=" **"; fi

  printf "  %-8s %8s %8s %8s %8s %10s %8s %8s%s\n" \
    "${rate}/s" "${ok_count:-?}" "${err_count}" "${avg:-N/A}" "${p50:-N/A}" "${p99:-N/A}" "${max:-N/A}" "${bytes:-N/A}" "$flag"
done

rm -f "$TARGETS_FILE"

echo ""
echo "  ** = errors detected (origin or network saturated at this rate)"
echo ""
echo "[*] vegeta constant-rate attack complete"
echo ""
echo "Interpretation:"
echo "  - First rate with errors = origin's sustainable throughput ceiling"
echo "  - P99 spike without errors = queuing (still processing, just slow)"
echo "  - Bytes/s drop = responses getting smaller (error pages vs full responses)"
