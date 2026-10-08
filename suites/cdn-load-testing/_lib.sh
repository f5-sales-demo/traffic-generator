#!/bin/bash
# Shared library for CDN load testing suite
# Source this file: . "$(dirname "$0")/_lib.sh"

TARGET="${1:-${TARGET_FQDN:?TARGET_FQDN required}}"
PROTOCOL="${TARGET_PROTOCOL:-http}"
BASE="${PROTOCOL}://${TARGET}"

# --- RFC 5737 test-net IP ranges (768 unique IPs) ---
TEST_NETS=("192.0.2" "198.51.100" "203.0.113")

rand_ip() {
  local net="${TEST_NETS[$((RANDOM % 3))]}"
  echo "${net}.$((RANDOM % 256))"
}

# --- Accept-Encoding rotation ---
ENCODINGS=("gzip" "br" "gzip, deflate" "gzip, deflate, br" "identity")

rand_encoding() {
  echo "${ENCODINGS[$((RANDOM % ${#ENCODINGS[@]}))]}"
}

# --- User-Agent pool (50 real browser UAs) ---
UA_POOL=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
  "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0"
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Vivaldi/6.8"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Brave/1.67"
  "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
  "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
  "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
  "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
  "Twitterbot/1.0"
  "LinkedInBot/1.0 (compatible; Mozilla/5.0)"
  "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
  "Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
  "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15"
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
  "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
  "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  "curl/8.7.1"
  "Wget/1.21.4"
  "python-requests/2.31.0"
  "Go-http-client/2.0"
  "Apache-HttpClient/4.5.14 (Java/17.0.11)"
  "okhttp/4.12.0"
  "axios/1.7.2"
  "node-fetch/3.3.2"
  "PostmanRuntime/7.39.0"
  "HTTPie/3.2.2"
  "Scrapy/2.11.2"
  "Playwright/1.45.0"
  "HeadlessChrome/125.0.0.0"
  "PhantomJS/2.1.1"
)

rand_ua() {
  echo "${UA_POOL[$((RANDOM % ${#UA_POOL[@]}))]}"
}

# --- Per-app path catalogs ---
SEARCH_WORDS=("apple" "banana" "cherry" "orange" "lemon" "melon" "grape" "mango" "peach" "berry" "juice" "water" "milk" "coffee" "tea" "beer" "wine" "soda" "cake" "bread" "rice" "fish" "meat" "egg" "salt" "sugar" "pepper" "olive" "onion" "garlic")
USER_NAMES=("alice" "bob" "charlie" "dave" "eve" "frank" "grace" "heidi" "ivan" "judy" "karl" "laura" "mike" "nancy" "oscar" "pat" "quinn" "rachel" "steve" "tina")

rand_juice_shop_path() {
  local paths=(
    "/"
    "/rest/products/search?q=${SEARCH_WORDS[$((RANDOM % ${#SEARCH_WORDS[@]}))]}"
    "/api/Products/$((RANDOM % 50 + 1))"
    "/api/Challenges/"
    "/api/SecurityQuestions/"
    "/api/Quantitys/"
    "/ftp/"
    "/rest/admin/application-configuration"
    "/rest/languages"
    "/assets/public/images/products/apple_juice.jpg"
    "/assets/public/images/products/apple_pressings.jpg"
    "/assets/public/images/products/banana_juice.jpg"
    "/assets/public/images/products/orange_juice.jpg"
    "/assets/public/images/products/lemon_juice.jpg"
    "/"
  )
  echo "/juice-shop${paths[$((RANDOM % ${#paths[@]}))]}"
}

rand_dvwa_path() {
  local paths=(
    "/login.php"
    "/vulnerabilities/"
    "/vulnerabilities/sqli/"
    "/vulnerabilities/xss_r/"
    "/vulnerabilities/xss_s/"
    "/vulnerabilities/fi/"
    "/vulnerabilities/upload/"
    "/vulnerabilities/csrf/"
    "/vulnerabilities/brute/"
    "/vulnerabilities/exec/"
    "/setup.php"
    "/security.php"
    "/login.php"
  )
  echo "/dvwa${paths[$((RANDOM % ${#paths[@]}))]}"
}

rand_vampi_path() {
  local paths=(
    "/"
    "/users/v1"
    "/posts/v1"
    "/users/v1/_default_admin/posts"
    "/"
    "/users/v1"
  )
  echo "/vampi${paths[$((RANDOM % ${#paths[@]}))]}"
}

rand_httpbin_path() {
  local names=("${USER_NAMES[@]}")
  local statuses=(200 201 204 301 302 400 401 403 404 500)
  local paths=(
    "/get"
    "/get?user=${names[$((RANDOM % ${#names[@]}))]}"
    "/get?ts=$(date +%s)&r=$((RANDOM))"
    "/headers"
    "/ip"
    "/user-agent"
    "/status/${statuses[$((RANDOM % ${#statuses[@]}))]}"
    "/anything"
    "/anything/${names[$((RANDOM % ${#names[@]}))]}"
    "/response-headers?X-Test=$((RANDOM))"
    "/delay/0"
    "/get"
    "/headers"
  )
  echo "/httpbin${paths[$((RANDOM % ${#paths[@]}))]}"
}

rand_csd_demo_path() {
  local paths=("/" "/health" "/" "/health" "/")
  echo "/csd-demo${paths[$((RANDOM % ${#paths[@]}))]}"
}

rand_any_path() {
  local app=$((RANDOM % 7))
  case $app in
  0) rand_juice_shop_path ;;
  1) rand_dvwa_path ;;
  2) rand_vampi_path ;;
  3) rand_httpbin_path ;;
  4) rand_csd_demo_path ;;
  5) echo "/whoami/" ;;
  6) echo "/health" ;;
  esac
}

# --- CDN vendor header injection ---
cdn_headers() {
  local ip
  ip=$(rand_ip)
  echo "-H \"X-Forwarded-For: $ip\" -H \"True-Client-IP: $ip\" -H \"CF-Connecting-IP: $ip\" -H \"Fastly-Client-IP: $ip\""
}

cdn_headers_for_curl() {
  local ip
  ip=$(rand_ip)
  echo "-H X-Forwarded-For:${ip} -H True-Client-IP:${ip} -H CF-Connecting-IP:${ip} -H Fastly-Client-IP:${ip}"
}

# --- X-Cache-Status checker ---
check_cache_status() {
  local url="$1"
  local status headers
  headers=$(curl -sf -o /dev/null -D - --max-time 5 -H "X-TGen-Monitor: cache-status" "$url" 2>/dev/null) || return 1
  status=$(printf '%s\n' "$headers" | awk 'tolower($1)=="x-cache-status:" {gsub(/\r/, "", $2); print $2; exit}')
  echo "${status:-NONE}"
}

# --- Cookie jar management ---
COOKIE_JARS=()

new_cookie_jar() {
  local thread_id="${1:-0}"
  local jar="/tmp/cdn-jar-$$-${thread_id}.txt"
  COOKIE_JARS+=("$jar")
  echo "$jar"
}

cleanup_jars() {
  for jar in "${COOKIE_JARS[@]}"; do
    rm -f "$jar" 2>/dev/null
  done
  rm -f /tmp/cdn-jar-$$-*.txt 2>/dev/null
}
trap cleanup_jars EXIT

# --- Reporting helpers ---
PASS_COUNT=0
FAIL_COUNT=0
VULN_COUNT=0

pass() {
  echo "    [PASS] $*"
  PASS_COUNT=$((PASS_COUNT + 1))
}
fail() {
  echo "    [FAIL] $*"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}
vuln() {
  echo "    [VULN] $*"
  VULN_COUNT=$((VULN_COUNT + 1))
}

summary() {
  echo ""
  echo "[*] Results: $PASS_COUNT pass, $FAIL_COUNT fail, $VULN_COUNT vulns"
  ((FAIL_COUNT == 0))
}
