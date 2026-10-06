# DVWA payload scenario mapping

The former `demoapp-attacks` suite is now `dvwa-payloads`. The two scenario IDs remain stable for receipt history:

| Scenario ID | Published endpoint | Payload corpus |
| --- | --- | --- |
| `demoapp-attacks/01-sqli-waf-endpoint` | `/dvwa/vulnerabilities/sqli/` | All 15 original SQLi payloads |
| `demoapp-attacks/02-xss-waf-endpoint` | `/dvwa/vulnerabilities/xss_r/` | All 18 original XSS payloads |

Origin-issued synthetic sessions and the low-security fixture are prerequisites. Missing sessions fail the scenario before execution. Mitigation candidates need independent WAAP control attribution. Synthetic `/WAF/SQL` and `/WAF/XSS` responses do not establish application coverage.
