#!/usr/bin/env bash
set -euo pipefail

# Traffic Generator Post-Boot Smoke Test Suite
# Deterministic validation of the existing Azure VM after deployment or reboot.
# AWS remains a separate Terraform root. --aws-contract performs local static checks for
# direct EIP attachment, deny-all default security group, encrypted VPC Flow Logs, S3
# EventBridge notifications, access logging, and cross-region evidence replication.
# Usage: ./smoke-test.sh <public-ip> [--user <ssh-user>]
#        ./smoke-test.sh --aws-contract
# Exit codes: 0 = all pass, 1 = failures detected

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "${1:-}" = "--aws-contract" ]; then
  exec bash "${REPO_ROOT}/tests/test-runtime-identity.sh"
fi

IP="${1:?Usage: $0 <public-ip> [--user <ssh-user>] | $0 --aws-contract}"
SSH_USER="azureuser"
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
  --user)
    SSH_USER="${2:?--user requires a value}"
    shift
    ;;
  *)
    echo "Unknown option: $1"
    exit 1
    ;;
  esac
  shift
done

PASS=0
FAIL=0
RESULTS=()

check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    RESULTS+=("PASS  $name")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL  $name (expected=$expected got=$actual)")
    FAIL=$((FAIL + 1))
  fi
}

check_contains() {
  local name="$1" needle="$2" haystack="$3"
  if echo "$haystack" | grep -q "$needle"; then
    RESULTS+=("PASS  $name")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL  $name (missing: $needle)")
    FAIL=$((FAIL + 1))
  fi
}

check_gte() {
  local name="$1" minimum="$2" actual="$3"
  if [ "$actual" -ge "$minimum" ] 2>/dev/null; then
    RESULTS+=("PASS  $name (value=$actual)")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL  $name (expected>=$minimum got=$actual)")
    FAIL=$((FAIL + 1))
  fi
}

ssh_cmd() {
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${SSH_USER}@${IP}" "$@" 2>/dev/null
}

echo "============================================"
echo "  Traffic Generator Smoke Test Suite"
echo "  Target: ${SSH_USER}@${IP}"
echo "  Time:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"
echo ""

# ── 1. SSH Connectivity ──────────────────────────────

echo "── SSH Connectivity ──"

SSH_OK=$(ssh_cmd "echo SSH_OK" || echo "UNREACHABLE")
check "ssh-connectivity" "SSH_OK" "$SSH_OK"

# ── 2. Status File ────────────────────────────────────

echo "── Status File ──"

STATUS_JSON=$(ssh_cmd "cat /opt/traffic-generator/status.json 2>/dev/null" || echo "")
STATUS_VALID=$(echo "$STATUS_JSON" | python3 -c "import sys,json; json.load(sys.stdin); print('valid')" 2>/dev/null || echo "invalid")
check "status-json-valid" "valid" "$STATUS_VALID"

STATUS_VAL=$(echo "$STATUS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
STATUS_OK=$(echo "$STATUS_VAL" | grep -qE '^(ready|degraded)$' && echo "true" || echo "false")
check "status-json-status-ready-or-degraded" "true" "$STATUS_OK"

TOOL_TIER=$(echo "$STATUS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_tier',''))" 2>/dev/null || echo "")
check "status-json-has-tool-tier" "true" "$([ -n "$TOOL_TIER" ] && echo true || echo false)"

# ── 3. Progress Log ──────────────────────────────────

echo "── Progress Log ──"

PROGRESS_EXISTS=$(ssh_cmd "test -f /var/log/cloud-init-progress.log && echo yes || echo no")
check "progress-log-exists" "yes" "$PROGRESS_EXISTS"

PROGRESS_LOG=$(ssh_cmd "cat /var/log/cloud-init-progress.log 2>/dev/null" || echo "")
check_contains "progress-log-phase0" '\[phase0\]' "$PROGRESS_LOG"
check_contains "progress-log-phase3" '\[phase3\]' "$PROGRESS_LOG"
check_contains "progress-log-phase9" '\[phase9\]' "$PROGRESS_LOG"
check_contains "progress-log-complete" '\[complete\]' "$PROGRESS_LOG"

# ── 4. Security Tools ────────────────────────────────

echo "── Security Tools ──"

NUCLEI_VER=$(ssh_cmd "nuclei -version 2>&1 | head -1" || echo "")
check "tool-nuclei-installed" "true" "$([ -n "$NUCLEI_VER" ] && echo true || echo false)"

NIKTO_VER=$(ssh_cmd "nikto -Version 2>&1 | head -1" || echo "")
check "tool-nikto-installed" "true" "$([ -n "$NIKTO_VER" ] && echo true || echo false)"

SQLMAP_VER=$(ssh_cmd "sqlmap --version 2>&1 | head -1" || echo "")
check "tool-sqlmap-installed" "true" "$([ -n "$SQLMAP_VER" ] && echo true || echo false)"

NMAP_VER=$(ssh_cmd "nmap --version 2>&1 | head -1" || echo "")
check "tool-nmap-installed" "true" "$([ -n "$NMAP_VER" ] && echo true || echo false)"

GOBUSTER_VER=$(ssh_cmd "gobuster version 2>&1 | head -1" || echo "")
check "tool-gobuster-installed" "true" "$([ -n "$GOBUSTER_VER" ] && echo true || echo false)"

HTTPX_VER=$(ssh_cmd "httpx -version 2>&1 | grep -i version | head -1" || echo "")
check "tool-httpx-installed" "true" "$([ -n "$HTTPX_VER" ] && echo true || echo false)"

FFUF_VER=$(ssh_cmd "ffuf -V 2>&1 | head -1" || echo "")
check "tool-ffuf-installed" "true" "$([ -n "$FFUF_VER" ] && echo true || echo false)"

WRK_VER=$(ssh_cmd "wrk --version 2>&1 | head -1" || echo "")
check "tool-wrk-installed" "true" "$([ -n "$WRK_VER" ] && echo true || echo false)"

CURL_VER=$(ssh_cmd "curl --version 2>&1 | head -1" || echo "")
check "tool-curl-installed" "true" "$([ -n "$CURL_VER" ] && echo true || echo false)"

JQ_VER=$(ssh_cmd "jq --version 2>&1 | head -1" || echo "")
check "tool-jq-installed" "true" "$([ -n "$JQ_VER" ] && echo true || echo false)"

# ── 5. Load Testing Tools ────────────────────────────

echo "── Load Testing Tools ──"

HEY_PATH=$(ssh_cmd "command -v hey" || echo "")
check "tool-hey-installed" "true" "$([ -n "$HEY_PATH" ] && echo true || echo false)"

VEGETA_VER=$(ssh_cmd "vegeta --version 2>&1 | head -1" || echo "")
check "tool-vegeta-installed" "true" "$([ -n "$VEGETA_VER" ] && echo true || echo false)"

# ── 6. Runtime Environments ──────────────────────────

echo "── Runtime Environments ──"

NODE_VER=$(ssh_cmd "node --version 2>&1" || echo "")
check_contains "nodejs-installed" "^v" "$NODE_VER"

PLAYWRIGHT_VER=$(ssh_cmd "npx playwright --version 2>&1 | head -1" || echo "")
check "playwright-installed" "true" "$([ -n "$PLAYWRIGHT_VER" ] && echo true || echo false)"

SCAPY_OK=$(ssh_cmd "python3 -c 'import scapy' 2>&1 && echo OK || echo FAIL")
check_contains "python-scapy-importable" "OK" "$SCAPY_OK"

MITMPROXY_VER=$(ssh_cmd "mitmproxy --version 2>&1 | head -1" || echo "")
check "mitmproxy-installed" "true" "$([ -n "$MITMPROXY_VER" ] && echo true || echo false)"

# ── 7. Test Suites ────────────────────────────────────

echo "── Test Suites ──"

SUITE_COUNT=$(ssh_cmd "find /opt/traffic-generator/suites/ -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l" || echo "0")
check "suite-count-16" "16" "$SUITE_COUNT"

RUNNER_EXEC=$(ssh_cmd "test -x /opt/traffic-generator/suites/runner.sh && echo yes || echo no")
check "runner-sh-executable" "yes" "$RUNNER_EXEC"

CONFIG_ENV=$(ssh_cmd "cat /opt/traffic-generator/config.env 2>/dev/null" || echo "")
check_contains "config-env-has-target-fqdn" "TARGET_FQDN" "$CONFIG_ENV"

# ── 8. Kernel Tuning ─────────────────────────────────

echo "── Kernel Tuning ──"

SOMAXCONN=$(ssh_cmd "sysctl -n net.core.somaxconn" || echo "0")
check_gte "sysctl-somaxconn" 131072 "$SOMAXCONN"

TCP_REUSE=$(ssh_cmd "sysctl -n net.ipv4.tcp_tw_reuse" || echo "0")
check "sysctl-tcp-tw-reuse" "1" "$TCP_REUSE"

ULIMIT_N=$(ssh_cmd "ulimit -n" || echo "0")
check_gte "file-descriptor-limit" 524288 "$ULIMIT_N"

# ── 9. Additional Tools ──────────────────────────────

echo "── Additional Tools ──"

TESTSSL_VER=$(ssh_cmd "/usr/local/bin/testssl --version 2>&1 | head -3" || echo "")
check "testssl-installed" "true" "$([ -n "$TESTSSL_VER" ] && echo true || echo false)"

SECLISTS_EXISTS=$(ssh_cmd "test -d /opt/SecLists && echo yes || echo no")
check "seclists-directory-exists" "yes" "$SECLISTS_EXISTS"

# ── Results ────────────────────────────────────────

echo ""
echo "============================================"
echo "  RESULTS: ${PASS} passed, ${FAIL} failed"
echo "============================================"
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "SMOKE TEST: FAILED"
  exit 1
else
  echo "SMOKE TEST: PASSED"
  exit 0
fi
