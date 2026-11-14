#!/bin/bash
# User-Agent rotation requests using hey (goroutine-based, ~10x more CPU-efficient than curl)
# Tools: native hey
# Targets: Various endpoints with rotating user agents
# Estimated duration: 1-2 minutes
set -euo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v hey >/dev/null || {
  echo "[FAIL] Required native hey missing" >&2
  exit 1
}

TARGET="${1:?Usage: 04-ua-rotation.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] User-Agent rotation requests against ${TARGET}"
echo ""

USER_AGENTS=(
  # Browsers
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
  # Search engine bots
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
  "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
  "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
  # CLI tools and libraries
  "curl/8.0.0"
  "Wget/1.21"
  "python-requests/2.31.0"
  "Go-http-client/2.0"
  "Java/17.0.1"
  "axios/1.6.0"
  "httpx/0.25.0"
  "Apache-HttpClient/4.5.14"
  "okhttp/4.12.0"
  # Scrapers and automation
  "Scrapy/2.11"
  "PhantomJS/2.1.1"
  "HeadlessChrome/120.0.0.0"
  "Selenium/4.15.0"
  # Vulnerability scanners
  "Nikto/2.5.0"
  "sqlmap/1.7"
  "Nmap Scripting Engine"
  "WPScan v3.8.0"
  "Nuclei v3.0.0"
  # Suspicious / empty
  ""
  "-"
  "Mozilla/4.0"
  "test"
  "\\x00"
)

ENDPOINTS=(
  "/juice-shop/"
  "/dvwa/"
  "/vampi/"
  "/juice-shop/rest/products/search?q=test"
)

echo "[+] Using hey (goroutine-based engine)"
echo ""

for ua in "${USER_AGENTS[@]}"; do
  ua_display="${ua}"
  [[ -z "$ua" ]] && ua_display="(empty)"
  echo "[+] UA: ${ua_display:0:60}"

  for endpoint in "${ENDPOINTS[@]}"; do
    echo "    ${endpoint}:"
    hey -n "${TGEN_UA_REQUESTS:-100}" -c "${TGEN_UA_CONCURRENCY:-20}" -t 10 -H "User-Agent: ${ua}" "${BASE}${endpoint}" 2>&1 |
      grep -E "(Requests/sec|Average|Status)" |
      while IFS= read -r line; do
        echo "      ${line}"
      done
  done
  echo ""
done

echo "[*] User-Agent rotation complete"
