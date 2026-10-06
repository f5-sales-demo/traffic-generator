#!/bin/bash
set -uo pipefail

########################################################################
# 06-sqlmap-comprehensive.sh — SQLMap Deep Scan
#
# Runs SQLMap against known injectable endpoints in Juice Shop, DVWA,
# and VAmPI with aggressive settings.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " SQLMap Comprehensive Scan"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

SQLMAP_OUTPUT_DIR="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-output"
SQLMAP_COMMON="--batch --timeout=15 --retries=2 --output-dir=$SQLMAP_OUTPUT_DIR"
FINDINGS=0

########################################################################
# Helper: Run sqlmap and count findings
########################################################################
run_sqlmap() {
  local label="$1"
  shift
  echo "----------------------------------------"
  echo "[*] ${label}"
  echo "    Command: sqlmap $*"
  echo "----------------------------------------"
  local output
  output=$(sqlmap "$@" 2>&1) || true
  echo "${output}"

  # Count injectable parameters
  local injectable
  injectable=$(echo "${output}" | grep -c "is vulnerable" 2>/dev/null || true)
  FINDINGS=$((FINDINGS + injectable))

  echo ""
  echo "    Injectable parameters found: ${injectable}"
  echo ""
}

########################################################################
# Phase 1: Juice Shop
########################################################################
echo "[*] Phase 1: Juice Shop Endpoints"
echo "========================================"

run_sqlmap "Juice Shop — Product Search" \
  -u "${BASE}/juice-shop/rest/products/search?q=test" \
  --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" --threads=4 \
  ${SQLMAP_COMMON}

run_sqlmap "Juice Shop — Login Endpoint" \
  -u "${BASE}/juice-shop/rest/user/login" \
  --method=POST --data='{"email":"test@example.com","password":"test"}' \
  --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" --threads=4 \
  ${SQLMAP_COMMON}

########################################################################
# Phase 2: DVWA (requires authentication)
########################################################################
echo "[*] Phase 2: DVWA Endpoints"
echo "========================================"

# Require the actual seeded origin-authenticated session; never invent a cookie.
if [[ -z "${TGEN_FIXTURES:-}" ]]; then
  echo "[FAIL] Native DVWA fixture required" >&2
  exit 1
fi
PHPSESSID=$(python3 -c 'import json,os;d=json.load(open(os.environ["TGEN_FIXTURES"]));print(d["dvwa_sessions"][os.environ["TARGET_FQDN"]])') || exit 1
[[ -n "$PHPSESSID" ]] || exit 1
DVWA_COOKIE="PHPSESSID=${PHPSESSID};security=low"

run_sqlmap "DVWA — SQL Injection (GET)" \
  -u "${BASE}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="${DVWA_COOKIE}" \
  --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" --dump \
  ${SQLMAP_COMMON}

run_sqlmap "DVWA — Blind SQL Injection" \
  -u "${BASE}/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="${DVWA_COOKIE}" \
  --technique=BT --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" \
  ${SQLMAP_COMMON}

########################################################################
# Phase 3: VAmPI
########################################################################
echo "[*] Phase 3: VAmPI Endpoints"
echo "========================================"

run_sqlmap "VAmPI — User Lookup" \
  -u "${BASE}/vampi/users/v1/test" \
  --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" \
  ${SQLMAP_COMMON}

run_sqlmap "VAmPI — Login" \
  -u "${BASE}/vampi/users/v1/login" \
  --method=POST --data='{"username":"test","password":"test"}' \
  --level="${TGEN_SQLMAP_LEVEL:-1}" --risk="${TGEN_SQLMAP_RISK:-1}" \
  ${SQLMAP_COMMON}

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " SQLMap Scan Summary"
echo "========================================"
echo "  Total injectable parameters found: ${FINDINGS}"
echo "  Output directory: $SQLMAP_OUTPUT_DIR/"
echo ""
echo "[*] SQLMap comprehensive scan finished."
