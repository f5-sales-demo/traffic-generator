#!/bin/bash
# Mixed attack + legitimate traffic load test
# Tools: curl, xargs
# Simulates realistic traffic: 70% legitimate, 30% attack payloads
# Measures how attack traffic impacts legitimate request latency
# Note: kept as curl+xargs because attack URLs contain payloads that wrk/hey
#       cannot easily parameterise per-request. Reduced concurrency and added
#       --max-time 30 to limit runaway processes.
# Estimated duration: 2 minutes
set -uo pipefail

TARGET="${1:?Usage: 05-mixed-attack-load.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

CONCURRENCY="${TGEN_CONCURRENCY:-25}"
TOTAL_REQUESTS="${TGEN_REQUESTS:-300}"

LEGIT_URLS=(
  "${BASE}/health"
  "${BASE}/juice-shop/"
  "${BASE}/juice-shop/rest/products/search?q=apple"
  "${BASE}/vampi/users/v1"
  "${BASE}/httpbin/get"
  "${BASE}/whoami/"
  "${BASE}/csd-demo/"
  "${BASE}/csd-demo/health"
)

ATTACK_URLS=(
  "${BASE}/juice-shop/rest/products/search?q=%27+OR+1%3D1--"
  "${BASE}/juice-shop/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  "${BASE}/dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1--&Submit=Submit"
  "${BASE}/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bcat+/etc/passwd&Submit=Submit"
  "${BASE}/vampi/users/v1/../../../etc/passwd"
  "${BASE}/httpbin/get?url=http://169.254.169.254/latest/meta-data/"
  "${BASE}/juice-shop/rest/products/search?q=%27%20UNION%20SELECT%20NULL--"
)

echo "[*] Mixed attack + legitimate load test against ${TARGET}"
echo "    Concurrency: ${CONCURRENCY} (reduced from 50 to limit fork overhead)"
echo "    Total requests: ${TOTAL_REQUESTS}"
echo "    Mix: ~70% legitimate, ~30% attack"
echo ""

url_file=$(mktemp)
for _ in $(seq "$TOTAL_REQUESTS"); do
  if ((RANDOM % 100 < 70)); then
    echo "${LEGIT_URLS[$((RANDOM % ${#LEGIT_URLS[@]}))]}"
  else
    echo "${ATTACK_URLS[$((RANDOM % ${#ATTACK_URLS[@]}))]}"
  fi
done >"$url_file"

legit_count=$(grep -cvE '(OR+1|script|passwd|sqli|exec|meta-data|UNION)' "$url_file" || true)
attack_count=$(grep -cE '(OR+1|script|passwd|sqli|exec|meta-data|UNION)' "$url_file" || true)
echo "    Actual mix: ${legit_count} legitimate, ${attack_count} attack"
echo ""

start_ns=$(date +%s%N)

results=$(cat "$url_file" | xargs -P"$CONCURRENCY" -I{} \
  curl -sf -o /dev/null -w "%{http_code} %{time_total} %{url_effective}\n" \
  --max-time 30 --connect-timeout 5 {} 2>/dev/null)

end_ns=$(date +%s%N)
wall_ms=$(((end_ns - start_ns) / 1000000))

rm -f "$url_file"

total=$(echo "$results" | grep -c . || echo 0)
ok=$(echo "$results" | grep -c '^[23]0[0-9] ' || true)
fail=$((total - ok))
rps=$(awk "BEGIN {printf \"%.1f\", $total / ($wall_ms / 1000.0)}")

legit_results=$(echo "$results" | grep -vE '(OR%2B1|script|passwd|sqli|exec|meta-data|UNION)')
attack_results=$(echo "$results" | grep -E '(OR%2B1|script|passwd|sqli|exec|meta-data|UNION)')

legit_avg=$(echo "$legit_results" | awk '{sum+=$2; n++} END {if(n>0) printf "%.3f", sum/n; else print "N/A"}')
attack_avg=$(echo "$attack_results" | awk '{sum+=$2; n++} END {if(n>0) printf "%.3f", sum/n; else print "N/A"}')

legit_ok=$(echo "$legit_results" | grep -c '^[23]0[0-9] ' || true)
legit_total=$(echo "$legit_results" | grep -c . || echo 0)
attack_ok=$(echo "$attack_results" | grep -c '^[23]0[0-9] ' || true)
attack_total=$(echo "$attack_results" | grep -c . || echo 0)

echo "=== Overall ==="
printf "  Total:       %d requests in %dms (%s req/s)\n" "$total" "$wall_ms" "$rps"
printf "  Success:     %d/%d (%d%%)\n" "$ok" "$total" "$((ok * 100 / (total > 0 ? total : 1)))"
printf "  Failures:    %d\n" "$fail"
echo ""

echo "=== Legitimate traffic ==="
printf "  Success:     %d/%d\n" "$legit_ok" "$legit_total"
printf "  Avg latency: %ss\n" "$legit_avg"
echo ""

echo "=== Attack traffic ==="
printf "  Success:     %d/%d (200 = passed through, 403 = WAF blocked, 500 = app error)\n" "$attack_ok" "$attack_total"
printf "  Avg latency: %ss\n" "$attack_avg"
echo ""

if [[ "$fail" -gt $((total / 20)) ]]; then
  echo "** BOTTLENECK: >5% failure rate under mixed load — attack traffic may be saturating origin **"
fi

echo "[*] Mixed attack + legitimate load test complete"
