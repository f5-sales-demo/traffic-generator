#!/bin/bash
# MITRE ATT&CK: Reconnaissance (TA0043)
# Techniques: T1595 Active Scanning, T1592 Gather Victim Host Info,
#             T1590 Gather Victim Network Info, T1589 Gather Victim Identity Info
# Tools: nmap, masscan, ffuf, gobuster, arjun, subfinder, whatweb
set -uo pipefail

TARGET="${1:?Usage: 01-reconnaissance.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0043: Reconnaissance against ${TARGET}"
echo ""

echo "=== T1595.001: Active Scanning — Port Scan ==="
echo "    Technique: Scanning IP for open ports and services"
if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
  echo "[CATALOG] Paced HTTP service assessment; TCP/TLS port scans run in the connection catalog"
  for path in / /health /httpbin/headers; do
    curl -skI --max-time 15 "${BASE}${path}" | head -12
  done
else
  nmap -sV --max-rate "${TGEN_CONNECTION_RATE:-20}" -p 80,443 -Pn "$TARGET" 2>/dev/null | grep -E "(open|filtered|closed)" | head -20
fi
echo ""

echo "=== T1595.002: Active Scanning — Vulnerability Scan ==="
echo "    Technique: Scanning for known vulnerabilities"
nikto -h "$BASE" -maxtime "${TGEN_SCANNER_SECONDS:-60}s" 2>&1 | grep -E "^\+" | head -15
echo ""

echo "=== T1595.003: Active Scanning — Wordlist Scan ==="
echo "    Technique: Brute-force directory/file enumeration"
ffuf -u "${BASE}/FUZZ" -w "${TGEN_DISCOVERY_WORDLIST:-/opt/seclists/Discovery/Web-Content/common.txt}" \
  -mc 200,301,302,401,403 -t 50 -timeout 10 -s 2>/dev/null | head -20
echo ""

echo "=== T1592: Gather Victim Host Information ==="
echo "    Technique: Server technology fingerprinting"
curl -sf -I "$BASE" 2>/dev/null | grep -iE "(server|x-powered|x-aspnet|x-framework|content-type)"
whatweb --color=never -q "$BASE" 2>/dev/null | head -5
echo ""

echo "=== T1589: Gather Victim Identity Information ==="
echo "    Technique: User enumeration via API"
echo "  Juice Shop user list:"
curl -sf "${BASE}/juice-shop/api/Users" 2>/dev/null | jq -r '.data[]?.email' 2>/dev/null | head -10
echo "  VAmPI user list:"
curl -sf "${BASE}/vampi/users/v1" 2>/dev/null | jq -r '.users[]?.username' 2>/dev/null | head -10
echo ""

echo "=== T1590: Gather Victim Network Information ==="
echo "    Technique: Discover internal network topology"
curl -sf "${BASE}/whoami/" 2>/dev/null | head -10
echo ""

echo "[*] TA0043 Reconnaissance complete"
