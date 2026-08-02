#!/bin/bash
set -uo pipefail

########################################################################
# 09-arjun-param-discovery.sh — Hidden Parameter Discovery
#
# Uses Arjun to discover hidden or undocumented parameters on key
# endpoints across all applications.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " Arjun Hidden Parameter Discovery"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

OUTPUT_DIR="/tmp/arjun"
mkdir -p "${OUTPUT_DIR}"
TOTAL_PARAMS=0

########################################################################
# Helper: Run arjun and report findings
########################################################################
run_arjun() {
  local label="$1"
  local url="$2"
  local method="${3:-GET}"
  local normalized_label output_file
  normalized_label=$(printf '%s' "${label}" | tr ' /' '-' | tr '[:upper:]' '[:lower:]')
  output_file="${OUTPUT_DIR}/arjun-${normalized_label}.json"

  echo "----------------------------------------"
  echo "[*] ${label}"
  echo "    URL: ${url}"
  echo "    Method: ${method}"
  echo "----------------------------------------"

  local output
  output=$(arjun -u "${url}" -m "${method}" -oJ "${output_file}" --stable 2>&1) || true
  echo "${output}"

  # Count discovered parameters
  local count=0
  if [[ -f "${output_file}" ]]; then
    count=$(python3 -c "
import json, sys
try:
    with open('${output_file}') as f:
        data = json.load(f)
    params = 0
    if isinstance(data, dict):
        for url_key, methods in data.items():
            if isinstance(methods, dict):
                for method_key, param_list in methods.items():
                    if isinstance(param_list, list):
                        params += len(param_list)
            elif isinstance(methods, list):
                params += len(methods)
    elif isinstance(data, list):
        params = len(data)
    print(params)
except:
    print(0)
" 2>/dev/null || echo "0")
  fi

  TOTAL_PARAMS=$((TOTAL_PARAMS + count))
  echo ""
  echo "    Parameters discovered: ${count}"

  if [[ -f "${output_file}" && "${count}" -gt 0 ]]; then
    echo "    Details:"
    python3 -c "
import json
try:
    with open('${output_file}') as f:
        data = json.load(f)
    if isinstance(data, dict):
        for url_key, methods in data.items():
            if isinstance(methods, dict):
                for method_key, param_list in methods.items():
                    if isinstance(param_list, list):
                        for p in param_list:
                            print(f'      [{method_key}] {p}')
            elif isinstance(methods, list):
                for p in methods:
                    print(f'      {p}')
    elif isinstance(data, list):
        for p in data:
            print(f'      {p}')
except:
    pass
" 2>/dev/null || true
  fi
  echo ""
}

########################################################################
# Phase 1: Juice Shop endpoints
########################################################################
echo "[*] Phase 1: Juice Shop Parameter Discovery"
echo "========================================"

run_arjun "Juice Shop — Login (POST)" \
  "${BASE}/juice-shop/rest/user/login" "POST"

run_arjun "Juice Shop — Product Search (GET)" \
  "${BASE}/juice-shop/rest/products/search" "GET"

run_arjun "Juice Shop — User Register (POST)" \
  "${BASE}/juice-shop/api/Users/" "POST"

run_arjun "Juice Shop — Feedback (POST)" \
  "${BASE}/juice-shop/api/Feedbacks/" "POST"

########################################################################
# Phase 2: VAmPI endpoints
########################################################################
echo "[*] Phase 2: VAmPI Parameter Discovery"
echo "========================================"

run_arjun "VAmPI — Login (POST)" \
  "${BASE}/vampi/users/v1/login" "POST"

run_arjun "VAmPI — Register (POST)" \
  "${BASE}/vampi/users/v1/register" "POST"

run_arjun "VAmPI — Users List (GET)" \
  "${BASE}/vampi/users/v1" "GET"

########################################################################
# Phase 3: DVWA endpoints
########################################################################
echo "[*] Phase 3: DVWA Parameter Discovery"
echo "========================================"

run_arjun "DVWA — Login (POST)" \
  "${BASE}/dvwa/login.php" "POST"

run_arjun "DVWA — Setup (GET)" \
  "${BASE}/dvwa/setup.php" "GET"

run_arjun "DVWA — Security Settings (POST)" \
  "${BASE}/dvwa/security.php" "POST"

########################################################################
# Phase 4: HTTPBin and CSD Demo
########################################################################
echo "[*] Phase 4: Additional Endpoint Discovery"
echo "========================================"

run_arjun "HTTPBin — Root (GET)" \
  "${BASE}/httpbin/get" "GET"

run_arjun "CSD Demo — Root (GET)" \
  "${BASE}/csd-demo/" "GET"

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " Arjun Parameter Discovery Summary"
echo "========================================"
echo "  Total hidden parameters discovered: ${TOTAL_PARAMS}"
echo "  Output directory: ${OUTPUT_DIR}/"
echo ""
echo "  Output files:"
for f in "${OUTPUT_DIR}"/arjun-*.json; do
  if [[ -f "${f}" ]]; then
    echo "    ${f}"
  fi
done
echo ""
echo "[*] Arjun parameter discovery finished."
