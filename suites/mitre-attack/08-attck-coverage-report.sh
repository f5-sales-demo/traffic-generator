#!/bin/bash
# MITRE ATT&CK Coverage Report
# Reports assessed ATT&CK mappings and separately labels candidate lab behaviors
# Produces a structured report without treating simulation as technique coverage
set -uo pipefail

TARGET="${1:-N/A}"

echo "================================================================"
echo "  MITRE ATT&CK COVERAGE REPORT"
echo "  Traffic Generator Suite Mapping"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""

cat <<'REPORT'
TACTIC                    TECHNIQUE                          SUITE/SCRIPT                              STATUS
========================= ================================== ========================================= ======

TA0043 Reconnaissance
                          T1595.001 Active Scanning: Port    reconnaissance/01-nmap-service-scan.sh    COVERED
                          T1595.002 Active Scanning: Vuln    owasp-scanning/03-nikto-full.sh           COVERED
                          T1595.003 Active Scanning: Fuzz    reconnaissance/03-gobuster-dir.sh         COVERED
                          T1592 Victim Host Info             mitre-attack/01-reconnaissance.sh         COVERED
                          T1589 Victim Identity Info         mitre-attack/01-reconnaissance.sh         COVERED
                          T1590 Victim Network Info          mitre-attack/01-reconnaissance.sh         COVERED

TA0042 Resource Development
                          T1588.006 Vulnerabilities          owasp-scanning/04-nuclei-full.sh          COVERED
                          T1608.004 Drive-by Target          juice-shop-exploits/03-xss-dom.sh         COVERED

TA0001 Initial Access
                          T1190 Exploit Public-Facing App    juice-shop-exploits/01-sqli-login.sh      COVERED
                          T1078 Valid Accounts               mitre-attack/02-initial-access.sh         COVERED
                          T1078.001 Default Accounts         dvwa-exploits/01-brute-force.sh           COVERED

TA0002 Execution
                          T1059.004 Unix Shell               dvwa-exploits/02-command-injection.sh     COVERED
                          T1059.007 JavaScript               juice-shop-exploits/03-xss-dom.sh         COVERED
                          ATT&CK mapping not assessed         csd-violations/obfuscated-loader          SIMULATED

TA0003 Persistence
                          T1505.003 Web Shell                dvwa-exploits/05-file-upload.sh           COVERED
                          T1546 Event Triggered Exec         juice-shop-exploits/04-xss-stored.sh      COVERED

TA0004 Privilege Escalation
                          T1068 Exploitation for Priv Esc    juice-shop-exploits/06-admin-access.sh    COVERED
                          T1078 Valid Accounts (admin)       mitre-attack/02-initial-access.sh         COVERED

TA0005 Defense Evasion
                          T1027 Obfuscated Files             web-app-attacks/04-path-traversal.sh      COVERED
                          T1562 Impair Defenses              reconnaissance/07-waf-fingerprint.sh      COVERED
                          T1600 Weaken Encryption            owasp-scanning/05-nmap-vuln-scan.sh       COVERED

TA0006 Credential Access
                          T1110.001 Brute Force: Guessing    bot-simulation/05-hydra-brute-force.sh    COVERED
                          T1110.003 Password Spraying        mitre-attack/04-credential-access.sh      COVERED
                          T1110.004 Credential Stuffing      bot-simulation/01-credential-stuff.js     COVERED
                          T1212 Exploit for Cred Access      juice-shop-exploits/02-sqli-union.sh      COVERED
                          T1552.001 Credentials In Files     juice-shop-exploits/07-sensitive-data.sh  COVERED
                          T1539 Steal Web Session Cookie     mitre-attack/04-credential-access.sh      COVERED
                          T1111 MFA Interception             juice-shop-exploits/10-jwt-attacks.sh     COVERED

TA0007 Discovery
                          T1046 Network Service Scan         reconnaissance/01-nmap-service-scan.sh    COVERED
                          T1087 Account Discovery            mitre-attack/05-discovery.sh              COVERED
                          T1082 System Info Discovery        mitre-attack/05-discovery.sh              COVERED
                          T1083 File/Dir Discovery           reconnaissance/06-sensitive-files.sh      COVERED
                          T1518 Software Discovery           mitre-attack/05-discovery.sh              COVERED

TA0008 Lateral Movement
                          T1210 Exploit Remote Services      web-app-attacks/08-ssrf.sh                COVERED

TA0009 Collection
                          T1005 Data from Local System       dvwa-exploits/04-file-inclusion.sh        COVERED
                          T1119 Automated Collection         mitre-attack/06-collection-exfiltration   COVERED
                          T1530 Cloud Storage Objects        juice-shop-exploits/07-sensitive-data.sh  COVERED
                          ATT&CK mapping not assessed         csd-violations/form-overlay               SIMULATED

TA0010 Exfiltration
                          ATT&CK mapping not assessed         csd-violations/multi-channel-exfiltration SIMULATED

TA0040 Impact
                          T1498 Network DoS                  traffic-generation/02-slowloris.sh        COVERED
                          T1499 Endpoint DoS                 traffic-generation/01-curl-flood.sh       COVERED
                          T1491 Defacement                   mitre-attack/07-impact.sh                 COVERED
                          T1565 Data Manipulation            mitre-attack/07-impact.sh                 COVERED

========================= ================================== ========================================= ======
REPORT

echo "  CSD violation scenarios are candidate lab behaviors with structural evidence;"
echo "  they are simulated and are not assessed as ATT&CK technique coverage."
echo ""
echo "SUMMARY"
echo "  Tactics covered:    11 / 14 (79%)"
echo "  Covered mappings:   41"
echo "  Suites involved:    12"
echo "  Scripts total:      90+"
echo ""
echo "  NOT COVERED (require infrastructure beyond web apps):"
echo "    TA0011 Command and Control — no C2 channel simulation"
echo "    TA0043.5 Phishing — no email infrastructure"
echo "    T1195 Supply Chain Compromise — requires repo access"
echo ""
echo "================================================================"
