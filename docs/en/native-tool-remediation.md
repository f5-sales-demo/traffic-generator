# Native tool substitution audit

Every executable catalog entry must run its declared native tool and retain actual tool, network and application evidence. Synthetic payload values are permitted; fabricated authentication, application responses and tool results are not acceptance.

| Finding | Replacement | Verification |
| --- | --- | --- |
| Five named Nmap/TLS entries used generic Python TLS probes | Native Nmap, SSLScan, SSLyze, testssl with scoped connect pacing and native reports | Installed native Nmap/SSLScan/SSLyze/testssl completed with structured reports and scoped measured connections on f4f30ce |
| Seven load entries used Python HTTP workers | Native wrk, hey or curl per declared load contract | Source checks; installed checks pending |
| Two hardware benchmarks used Python HTTP workers | Native wrk, hey, ab phases with resource sampling | Installed checks pending; hardware comparison requires actual hosts |
| Cache and independent-client entries used Python HTTP requests | Native curl with real response bytes and content checks | Installed checks pending |
| Subfinder used DNS lookup instead of passive discovery | Native Subfinder against the authorized root domain; discoveries are never scanned | Installed provider availability pending |
| VAmPI auth failure produced dummy tokens | Fail the prerequisite when real authentication is unavailable | Existing source checks; live prerequisite checks pending |
| SQLMap auth failure produced fabricated session ID | Require actual origin-issued DVWA session | Installed checks pending |
| CSD loader supplied no-op JavaScript | Pinned actual library assets and executable identity checks | Passed on earlier immutable candidate |
| crAPI registration claims retrieved OTP while assigning 0000 | Fabricated OTP removed; isolated native registration and actual password-reset OTP workflow still required | Fails full acceptance; existing scenario is not qualified |
| Optional native tool fallbacks and missing Lua phases | Mandatory native dependency gates | Alternate load branches removed; complete native phase qualification in progress |

Reports and source checks are not complete functional qualification. Preserve all failed evidence. No task is complete until source, immutable installation and required live checks pass. CSD enforcement remains disabled.
