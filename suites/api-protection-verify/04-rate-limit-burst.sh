#!/bin/bash
# Rate-limit burst traffic — sends a rapid burst to a single path so an F5 XC LB with
# rate_limit configured (SP3 rate_limit_choice=rate_limit) throttles the excess and
# returns 429, raising rate-limit events. Count/rate are set well above a typical
# per-minute limit; tune BURST via env if the configured limit differs.
# Tools: curl
# Targets: api.<domain> a single hot path
# Estimated duration: <1 minute
# Marker: User-Agent "sp5-api-verify".
set -euo pipefail

TARGET="${1:?Usage: 04-rate-limit-burst.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
UA="sp5-api-verify"
BURST="${BURST:-120}"
HOT_PATH="${HOT_PATH:-/vampi/users/v1}"

echo "[*] Rate-limit burst against ${BASE}${HOT_PATH} (${BURST} requests)"

throttled=0
ok=0
for ((i = 1; i <= BURST; i++)); do
  code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' -A "$UA" \
    -H "X-SP5-Verify: rate-limit" "${BASE}${HOT_PATH}" || echo "000")
  case "$code" in
  429) throttled=$((throttled + 1)) ;;
  2* | 3* | 4*) ok=$((ok + 1)) ;;
  esac
done

echo "  sent=${BURST} throttled(429)=${throttled} other=${ok}"
if [ "$throttled" -gt 0 ]; then
  echo "  => rate limiting OBSERVED (${throttled} x 429)"
else
  echo "  => no 429 seen (limit may be higher than BURST=${BURST}, or rate_limit disabled)"
fi

echo "[*] Rate-limit burst complete"
