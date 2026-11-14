#!/bin/bash
set -uo pipefail

########################################################################
# 10-full-owasp-report.sh — Aggregate OWASP Report Generator
#
# Collects results from all previous scans and produces a summary
# organized by OWASP Top 10 (2021) categories and severity levels.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " OWASP Top 10 Aggregate Report"
echo "========================================"
echo " Target:  ${BASE}"
echo " Date:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo " Scanner: OWASP Scanning Suite v1.0"
echo "========================================"
echo ""

########################################################################
# Gather raw data from scan outputs
########################################################################

# ZAP reports
ZAP_BASELINE="/tmp/zap-baseline-report.html"
ZAP_ACTIVE="/tmp/zap-active-scan-report.html"

# SQLMap output
SQLMAP_DIR="/tmp/sqlmap-output"

# DalFox output
DALFOX_DIR="/tmp/dalfox"

# Arjun output
ARJUN_DIR="/tmp/arjun"
if [[ -n "${TGEN_RESULTS_DIR:-}" ]]; then
  PASS_DIR=$(dirname "$TGEN_RESULTS_DIR")
  ZAP_BASELINE="$PASS_DIR/owasp-scanning--01-zap-baseline/zap-baseline-report.html"
  ZAP_ACTIVE="$PASS_DIR/owasp-scanning--02-zap-active-scan/zap-active-scan-report.html"
  SQLMAP_DIR="$PASS_DIR/owasp-scanning--06-sqlmap-comprehensive/sqlmap-output"
  DALFOX_DIR="$PASS_DIR/owasp-scanning--08-dalfox-xss-scan"
  ARJUN_DIR="$PASS_DIR/owasp-scanning--09-arjun-param-discovery"
  for scenario in 01-zap-baseline 02-zap-active-scan 06-sqlmap-comprehensive 08-dalfox-xss-scan 09-arjun-param-discovery; do
    [[ -f "$PASS_DIR/owasp-scanning--$scenario/receipt.json" ]] || {
      echo "[FAIL] Missing prerequisite scanner receipt: $scenario" >&2
      exit 1
    }
  done
fi

########################################################################
# Count available results
########################################################################
echo "[*] Checking available scan results..."
echo ""

SCAN_RESULTS=()

if [[ -f "${ZAP_BASELINE}" ]]; then
  echo "    [OK] ZAP Baseline report found"
  SCAN_RESULTS+=("zap-baseline")
else
  echo "    [--] ZAP Baseline report not found"
fi

if [[ -f "${ZAP_ACTIVE}" ]]; then
  echo "    [OK] ZAP Active Scan report found"
  SCAN_RESULTS+=("zap-active")
else
  echo "    [--] ZAP Active Scan report not found"
fi

if [[ -d "${SQLMAP_DIR}" ]]; then
  SQLMAP_COUNT=$(find "${SQLMAP_DIR}" -name "*.csv" -o -name "*.txt" -o -name "log" 2>/dev/null | wc -l)
  echo "    [OK] SQLMap output found (${SQLMAP_COUNT} files)"
  SCAN_RESULTS+=("sqlmap")
else
  echo "    [--] SQLMap output not found"
fi

if [[ -d "${DALFOX_DIR}" ]]; then
  DALFOX_TOTAL=0
  for f in "${DALFOX_DIR}"/dalfox-*.txt; do
    if [[ -f "${f}" ]]; then
      c=$(wc -l <"${f}" 2>/dev/null || echo "0")
      DALFOX_TOTAL=$((DALFOX_TOTAL + c))
    fi
  done
  echo "    [OK] DalFox output found (${DALFOX_TOTAL} XSS vectors)"
  SCAN_RESULTS+=("dalfox")
else
  echo "    [--] DalFox output not found"
fi

if [[ -d "${ARJUN_DIR}" ]]; then
  echo "    [OK] Arjun output found"
  SCAN_RESULTS+=("arjun")
else
  echo "    [--] Arjun output not found"
fi

echo ""
echo "  Scans with results: ${#SCAN_RESULTS[@]} / 5"
echo ""

########################################################################
# OWASP Top 10 (2021) Category Report
########################################################################

python3 - "${ZAP_BASELINE}" "${ZAP_ACTIVE}" "${SQLMAP_DIR}" "${DALFOX_DIR}" "${ARJUN_DIR}" <<'PYREPORT'
import os
import sys
import re
import json
from html.parser import HTMLParser
from collections import defaultdict

zap_baseline = sys.argv[1]
zap_active = sys.argv[2]
sqlmap_dir = sys.argv[3]
dalfox_dir = sys.argv[4]
arjun_dir = sys.argv[5]

# OWASP Top 10 (2021) categories
OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Severity counters
severity_counts = defaultdict(int)

# OWASP category findings
owasp_findings = defaultdict(list)

# Keywords to map findings to OWASP categories
CATEGORY_KEYWORDS = {
    "A01": ["access control", "authorization", "idor", "privilege", "cors",
            "directory traversal", "path traversal", "forced browsing",
            "insecure direct object", "missing access"],
    "A02": ["crypto", "ssl", "tls", "certificate", "cipher", "encryption",
            "hsts", "cleartext", "plaintext", "weak hash", "sha1", "md5",
            "cookie without secure", "insecure transport"],
    "A03": ["injection", "sqli", "sql injection", "xss", "cross-site scripting",
            "command injection", "ldap injection", "xpath", "nosql",
            "code injection", "template injection", "ssti", "crlf",
            "header injection", "os command"],
    "A04": ["insecure design", "business logic", "race condition",
            "insufficient anti-automation", "missing rate limit"],
    "A05": ["misconfiguration", "default", "directory listing", "backup",
            "stack trace", "error message", "debug", "verbose error",
            "server header", "x-powered-by", "information disclosure",
            "security header", "content-type", "x-frame-options",
            "clickjacking", "csp", "permissions-policy", "referrer-policy"],
    "A06": ["vulnerable component", "outdated", "cve-", "known vulnerability",
            "end of life", "eol", "version", "jquery", "angular", "bootstrap"],
    "A07": ["authentication", "login", "password", "session", "credential",
            "brute force", "session fixation", "session management",
            "weak password", "cookie without httponly"],
    "A08": ["integrity", "deserialization", "ci/cd", "unsigned", "untrusted",
            "subresource integrity", "sri"],
    "A09": ["logging", "monitoring", "audit", "log"],
    "A10": ["ssrf", "server-side request forgery", "url redirect",
            "open redirect"],
}

def categorize_finding(description):
    """Map a finding description to an OWASP category."""
    desc_lower = description.lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                return cat
    return "A05"  # default to misconfiguration

def map_severity(risk_str):
    """Normalize severity strings."""
    risk_lower = risk_str.lower().strip()
    if risk_lower in ("critical", "high"):
        return "Critical" if "critical" in risk_lower else "High"
    elif risk_lower == "medium":
        return "Medium"
    elif risk_lower == "low":
        return "Low"
    else:
        return "Info"

# ------------------------------------------------------------------
# Parse ZAP HTML reports (basic extraction)
# ------------------------------------------------------------------
def parse_zap_html(filepath):
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        # Look for alert patterns in ZAP HTML reports
        # ZAP typically has risk level and alert name in the report
        risk_pattern = re.findall(
            r'(High|Medium|Low|Informational)\s*(?:</[^>]+>)?\s*(?:<[^>]+>)?\s*([^<]{5,100})',
            content, re.IGNORECASE
        )
        for risk, alert in risk_pattern:
            sev = map_severity(risk)
            severity_counts[sev] += 1
            cat = categorize_finding(alert)
            owasp_findings[cat].append({
                "tool": "ZAP",
                "severity": sev,
                "finding": alert.strip()[:120],
            })
    except Exception:
        pass
    return findings

parse_zap_html(zap_baseline)
parse_zap_html(zap_active)

# ------------------------------------------------------------------
# Parse SQLMap results
# ------------------------------------------------------------------
if os.path.isdir(sqlmap_dir):
    for root, dirs, files in os.walk(sqlmap_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read()
                if "is vulnerable" in content or "injectable" in content.lower():
                    severity_counts["High"] += 1
                    owasp_findings["A03"].append({
                        "tool": "SQLMap",
                        "severity": "High",
                        "finding": f"SQL Injection found ({fname})",
                    })
                if "retrieved:" in content.lower() or "dumped" in content.lower():
                    severity_counts["Critical"] += 1
                    owasp_findings["A03"].append({
                        "tool": "SQLMap",
                        "severity": "Critical",
                        "finding": f"Data extraction successful ({fname})",
                    })
            except Exception:
                pass

# ------------------------------------------------------------------
# Parse DalFox results
# ------------------------------------------------------------------
if os.path.isdir(dalfox_dir):
    for fname in os.listdir(dalfox_dir):
        if fname.endswith('.txt'):
            fpath = os.path.join(dalfox_dir, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip()]
                for line in lines:
                    severity_counts["High"] += 1
                    owasp_findings["A03"].append({
                        "tool": "DalFox",
                        "severity": "High",
                        "finding": f"XSS: {line[:100]}",
                    })
            except Exception:
                pass

# ------------------------------------------------------------------
# Parse Arjun results
# ------------------------------------------------------------------
if os.path.isdir(arjun_dir):
    for fname in os.listdir(arjun_dir):
        if fname.endswith('.json'):
            fpath = os.path.join(arjun_dir, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    data = json.load(f)
                param_count = 0
                if isinstance(data, dict):
                    for url_key, methods in data.items():
                        if isinstance(methods, dict):
                            for m, params in methods.items():
                                if isinstance(params, list):
                                    param_count += len(params)
                        elif isinstance(methods, list):
                            param_count += len(methods)
                if param_count > 0:
                    severity_counts["Info"] += param_count
                    owasp_findings["A05"].append({
                        "tool": "Arjun",
                        "severity": "Info",
                        "finding": f"Hidden parameters discovered: {param_count} in {fname}",
                    })
            except Exception:
                pass

# ------------------------------------------------------------------
# Print OWASP Top 10 Report
# ------------------------------------------------------------------
print("=" * 56)
print(" OWASP Top 10 (2021) Findings Summary")
print("=" * 56)
print()

total_findings = sum(severity_counts.values())

for cat_id in sorted(OWASP_TOP10.keys()):
    cat_name = OWASP_TOP10[cat_id]
    findings = owasp_findings.get(cat_id, [])

    if findings:
        print(f"  {cat_id}: {cat_name}")
        print(f"  {'─' * 50}")

        # Deduplicate
        seen = set()
        deduped = []
        for f in findings:
            key = f"{f['tool']}:{f['finding']}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Group by severity
        by_sev = defaultdict(list)
        for f in deduped:
            by_sev[f["severity"]].append(f)

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            items = by_sev.get(sev, [])
            if items:
                for item in items:
                    print(f"    [{sev:8s}] [{item['tool']:8s}] {item['finding']}")
        print()
    else:
        print(f"  {cat_id}: {cat_name}")
        print(f"  {'─' * 50}")
        print(f"    No findings.")
        print()

# ------------------------------------------------------------------
# Severity Summary
# ------------------------------------------------------------------
print("=" * 56)
print(" Findings by Severity")
print("=" * 56)
print()
for sev in ["Critical", "High", "Medium", "Low", "Info"]:
    count = severity_counts.get(sev, 0)
    bar = "█" * min(count, 50)
    print(f"  {sev:12s}: {count:5d}  {bar}")
print(f"  {'─' * 30}")
print(f"  {'Total':12s}: {total_findings:5d}")
print()

# ------------------------------------------------------------------
# Scan Coverage
# ------------------------------------------------------------------
print("=" * 56)
print(" Scan Coverage")
print("=" * 56)
print()

tools_used = set()
for findings in owasp_findings.values():
    for f in findings:
        tools_used.add(f["tool"])

all_tools = ["ZAP", "Nikto", "Nuclei", "Nmap", "SQLMap", "FFUF", "DalFox", "Arjun"]
for tool in all_tools:
    status = "Results found" if tool in tools_used else "No results / Not run"
    marker = "OK" if tool in tools_used else "--"
    print(f"  [{marker}] {tool:10s} — {status}")

print()
print("=" * 56)
print(" Report Complete")
print("=" * 56)

PYREPORT

echo ""
echo "========================================"
echo " Report Artifacts"
echo "========================================"
echo ""
echo "  ZAP Reports:"
[[ -f "${ZAP_BASELINE}" ]] && echo "    ${ZAP_BASELINE}" || echo "    (not available)"
[[ -f "${ZAP_ACTIVE}" ]] && echo "    ${ZAP_ACTIVE}" || echo "    (not available)"
echo ""
echo "  SQLMap Output: ${SQLMAP_DIR}/"
echo "  DalFox Output: ${DALFOX_DIR}/"
echo "  Arjun Output:  ${ARJUN_DIR}/"
echo ""
echo "[*] OWASP full report generation finished."
