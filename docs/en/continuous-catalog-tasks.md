# Continuous catalog delivery tasks

## Current snapshot — 2026-10-05

[Issue #711](https://github.com/f5-sales-demo/traffic-generator/issues/711) and [draft PR
 #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) implement generator
`6aa8bbc6ef87494ded8fc7756878962bb4d67b8c`, with origin [PR
 #711](https://github.com/f5-sales-demo/origin-server/pull/711) and WAAP [PR
 #554](https://github.com/f5-sales-demo/webapp-api-protection/pull/554). That revision is installed from a verified full-commit archive; further discovery and CI repairs are under validation. It is not a complete catalog acceptance receipt.

The source has 164 scenarios across 22 suites: 151 numbered entrypoints, eleven CSD browser scenarios and two benchmarks. All have execution contracts. 
Source at `6aa8bbc` declares 129 native functional contracts; 35 lack them and 36 mutation declarations deliberately fail pending no-change or restoration proof. Declaration does not imply live qualification. Stable DVWA IDs retain 15 SQLi/18 XSS payload mappings.

| Task | Status | Dependencies | Evidence / revision | Remaining acceptance |
| --- | --- | --- | --- | --- |
| Catalog inventory/discovery | Source implemented | Manifest | `6aa8bbc`; 164/22 and read-only dry-run | Exact-head installed inventory and complete passes |
| Native tools and shared pacing | In progress | Prerequisites | `799e360` SSLyze all-plugin slice; actual Nmap/TLS/Masscan/OpenSSL/load tools | Complete native phases/content/connections, sustained rate and observed cleanup |
| Real actor fixtures | In progress | Origin installer | `6aa8bbc` native signup/reset slice with exact account, vehicle and mail cleanup | Recurring signup/vehicle/reset ownership; broad and interrupted exact restoration |
| Functional contracts | In progress | Native application evidence | 129 declared on `6aa8bbc`; unexpected statuses, unattributed denials and absent restoration fail | Remaining contracts, mutation recovery and current-source installed qualification |
| Rendered application matrix | Agent review complete | Origin `77340fd` | 78 checks/315 screenshots across native/nginx/published layers; private source-bound visual receipt | Human acceptance and merged-source installation |
| Benchmarks and media | Unqualified | Actual tools/fixtures | `312f665`: 17/33 workers; actual FFmpeg media dispatch | Full phase/content/host comparison and native media postconditions |
| CI/docs build/review | In progress | Exact committed PR head | `6aa8bbc`: 187 Python tests/9 subtests pass; CI lint repair in progress | New documentation checks, governed builder and rendered navigation/LLM review |
| Merge and immutable installation | Open | Complete implementation acceptance | Draft #713, origin #711 | Merge upstream; verify archive/install digests and installed behavior |
| WAAP T15/T16 | Open | Merged upstream installation | WAAP #553/#554 | Preserved clean rebuild, two accepted passes, 200 RPS ±5%, >=99% benign success, zero transport failures, attributed controls, restart/reboot and zero-change apply |

Private receipt IDs include `resume-native-followups/pass-focused-1791121335656328761/receipt.json` and
`resume-native-functional-both-domains/pass-focused-1791079166467472534/receipt.json`. They qualify only their
recorded slices/candidates. Benchmark/video dispatch is unqualified. Source tests may use doubles; they do not
prove installed/native behavior. Failed transport, browser, descriptor, schema, tool, timeout and CI
iterations remain failed in the [historical tracker](../archive/continuous-catalog-history/) and
[native audit](../native-tool-remediation/).

CSD remains disabled (`csd_enabled=false`), with display-only execution/cleanup. Application rejection is
separate from attributed mitigation. Keep operational identities, credentials, state, raw reports and
screenshots private. [WAAP's current T01–T16
tracker](https://f5-sales-demo.github.io/webapp-api-protection/en/origin-traffic-remediation-tasks/) governs
final showcase acceptance. No complete current catalog or final showcase acceptance is claimed.

On `6aa8bbc`, fresh signup completed native authentication/reset and exact account, vehicle and mail cleanup with zero transport failures. The interrupted older pass remains incomplete. Continuous traffic restarted after readiness on `6aa8bbc`; no accepted full pass is recorded. GitGuardian historical findings remain open for individual review and dashboard classification.
