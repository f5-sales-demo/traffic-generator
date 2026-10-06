# Native tool substitution audit

Every executable catalog entry must run its declared native tool and retain actual tool, network and application evidence. Synthetic payload values are permitted; fabricated authentication, application responses and tool results are not acceptance.

| Finding | Replacement | Verification |
| --- | --- | --- |
| Five named Nmap/TLS entries used generic Python TLS probes | Native Nmap, SSLScan, SSLyze, testssl with scoped connect pacing and native reports | Installed native Nmap/SSLScan/SSLyze/testssl completed on f4f30ce; stricter SSLyze all-plugin and observed cleanup checks passed on both domains on 799e360 |
| Seven load entries used Python HTTP workers | Native wrk, hey or cURL per declared load contract | Installed hey ramp and cURL churn reports passed; complete content qualification pending |
| Two hardware benchmarks used Python HTTP workers | Native wrk, hey, Vegeta, ab and Lua phases with resource sampling | Native wrk/hey/Vegeta/ab/Lua reports pass; connection-mode dispatch correction in progress; hardware comparison requires actual hosts |
| Cache and independent-client entries used Python HTTP requests | Native cURL with real response bytes and content checks | Installed checks pending |
| Subfinder used DNS lookup instead of passive discovery | Native Subfinder against the authorized root domain; discoveries are never scanned | Native Subfinder returned four real provider discoveries; corrected native receipt passed |
| VAmPI auth failure produced dummy tokens | Fail the prerequisite when real authentication is unavailable | Existing source checks; live prerequisite checks pending |
| SQLMap auth failure produced fabricated session ID | Require actual origin-issued DVWA session | Installed checks pending |
| CSD loader supplied no-op JavaScript | Pinned actual library assets and executable identity checks | Passed on earlier immutable candidate |
| crAPI registration claims retrieved OTP while assigning 0000 | Native isolated registration, authentication, vehicle and reset OTP workflow | `6aa8bbc` installed slice passed with exact account, vehicle and mail cleanup; broader catalog acceptance pending |
| Optional native tool fallbacks and missing Lua phases | Mandatory native dependency gates | Alternate load branches removed; complete native phase qualification in progress |

Reports and source checks are not complete functional qualification. Preserve all failed evidence. No task is complete until source, immutable installation and required live checks pass. CSD enforcement remains disabled.

The CSD browser now requests actual owned endpoints directly; response interception and implicit endpoint fallback are removed. RESTaurant escalation chains cannot substitute a seeded privileged identity. Native scanner and load report failures remain failed evidence.

Slow-header catalog execution now launches actual OpenSSL clients instead of the Python TLS substitute. All five named scanner catalog entries invoke their native binaries. Python workload and benchmark executable engines are retired.

The stricter SSLyze check requires all 18 declared plugins to be scheduled, completed and free of plugin errors. Both domains passed with 602 measured connection attempts each, zero transport failures and no surviving native process group. The partial-plugin candidate remains failed evidence. Source receipts now bind the Python adapter, C pacer and cleanup verifier separately.

The shared crAPI setup helper no longer treats signup welcome mail as a verification OTP. Native
MIME parsing requires an exact recipient, the `crAPI OTP` subject and the labeled OTP body; welcome
mail requires the actual VIN. The parser passed against 17 actual MailHog messages covering both
kinds. This is parser qualification, not complete signup/reset scenario acceptance: isolated actors,
native reset postconditions and scoped recovery remain open.

Two crAPI upload scenarios previously emitted only MP4 header bytes. They now call native FFmpeg to encode one second of synthetic video and native FFprobe to verify the codec and dimensions. FFmpeg and FFprobe are mandatory dependencies. Native encode/decode passed on the workstation; installed upload/conversion acceptance remains pending.

On installed generator `312f665`, keepalive and VM benchmark adapters completed 17 and 33 native workers with
observed process cleanup, zero transport failures and zero cancellations. Both receipts remain functionally
unqualified because full phase, content and host comparison contracts are incomplete. Private receipt:
`resume-native-followups/pass-focused-1791121335656328761/receipt.json`.

Source-bound functional checks now reject unexpected statuses, absent upstream dispatch, generic denial bodies and unobserved recovery. Nested child receipts carry functional results, and aggregate reports recompute dependency qualification from current-pass installed source/artifact evidence. The full catalog remains unqualified.
