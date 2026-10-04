# Continuous catalog delivery tasks

## Current snapshot — 2026-10-04

[Issue #711](https://github.com/f5-sales-demo/traffic-generator/issues/711) and [draft PR
 #713](https://github.com/f5-sales-demo/traffic-generator/pull/713) implement generator
`4c2f5287f52d01284418bc5c497d0eea058ead2c`, with origin [PR
 #711](https://github.com/f5-sales-demo/origin-server/pull/711) and WAAP [PR
 #554](https://github.com/f5-sales-demo/webapp-api-protection/pull/554). This is the source inspected before
documentation reconciliation, not a current installed acceptance receipt.

The source has 164 scenarios across 22 suites: 151 numbered entrypoints, eleven CSD browser scenarios and two benchmarks. All have execution contracts. Fourteen have declared native functional contracts and 150 lack them; declaration does not imply live qualification. Stable DVWA IDs retain 15 SQLi/18 XSS payload mappings.

| Task | Status | Dependencies | Evidence / revision | Remaining acceptance |
| --- | --- | --- | --- | --- |
| Catalog inventory/discovery | Source implemented | Manifest | `4c2f528`; 164/22 and read-only dry-run | Exact-head installed inventory and complete passes |
| Native tools and shared pacing | In progress | Prerequisites | `799e360` SSLyze all-plugin slice; actual Nmap/TLS/Masscan/OpenSSL/load tools | Complete native phases/content/connections, sustained rate and observed cleanup |
| Real actor fixtures | In progress | Origin installer | `88010ad` bounded native OTP slice on both domains | Recurring signup/vehicle/reset ownership; broad and interrupted exact restoration |
| Functional contracts | In progress | Native application evidence | Fourteen declared on `4c2f528`; earlier focused receipts in archive/audit | Remaining 150 contracts and all current-source installed qualification |
| Rendered application matrix | Open | Origin final source | Earlier `dc99bef`: 66 receipts/315 screenshots | Current source and every native/nginx/published layer with manual review |
| Benchmarks and media | Unqualified | Actual tools/fixtures | `312f665`: 17/33 workers; actual FFmpeg media dispatch | Full phase/content/host comparison and native media postconditions |
| CI/docs build/review | In progress | Exact committed PR head | Candidate-specific required CI | New documentation checks, governed builder and rendered navigation/LLM review |
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
