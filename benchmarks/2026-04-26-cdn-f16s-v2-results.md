# VM Benchmark Results — CDN on F16s_v2

**Date**: 2026-04-26
**CDN Simulator**: 20.65.90.112 (F16s_v2, 16 vCPU)
**Traffic Generator**: 20.114.199.194 (varied per test)

---

## Round 1: Non-Keepalive (original benchmark)

### Test A: D8s_v3 (8 vCPU, 32 GiB, Xeon 8370C @ 2.80 GHz)

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 149,678 req/s |
| T2 wrk Lua randomized | 68,126 req/s |
| T3 hey goroutine (4 ep) | 14,641 req/s |
| T5 kraken combined | 92,597 req/s |
| Peak CPU | 64.44 (8x oversubscribed) |
| Peak RAM | 1,268 MB / 32 GiB (4%) |

### Test B: F16s_v2 (16 vCPU, 32 GiB, Xeon 8272CL @ 2.60 GHz)

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 243,530 req/s |
| T2 wrk Lua randomized | 118,002 req/s |
| T3 hey goroutine (4 ep) | 52,465 req/s |
| T5 kraken combined | 153,948 req/s |
| Peak CPU | 56.90 (3.6x oversubscribed) |
| Peak RAM | 2,360 MB / 32 GiB (7%) |

### Test C: F32s_v2 (32 vCPU, 64 GiB, Xeon 8272CL @ 2.60 GHz)

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 219,581 req/s |
| T2 wrk Lua randomized | 160,823 req/s |
| T3 hey goroutine (4 ep) | 85,465 req/s |
| T5 kraken combined | 161,326 req/s |
| Peak CPU | 29.85 (0.9x — under capacity) |
| Peak RAM | 3,262 MB / 64 GiB (5%) |

### Test D: D16s_v3 (16 vCPU, 64 GiB, Xeon 8272CL @ 2.60 GHz)

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 224,699 req/s |
| T2 wrk Lua randomized | 117,142 req/s |
| T3 hey goroutine (4 ep) | 47,019 req/s |
| T5 kraken combined | 148,877 req/s |
| Peak CPU | 68.77 (4.3x oversubscribed) |
| Peak RAM | 2,633 MB / 64 GiB (4%) |

### Round 1 Analysis

- Generator was CPU-bound on D8s_v3 (64x load on 8 cores)
- F16s_v2 → F32s_v2 gave only +5% kraken combined — CDN was the ceiling
- D16s_v3 ≈ F16s_v2 (same Xeon 8272CL in eastus2 region)
- F32s_v2 T1 static actually dropped 10% from thread-to-NIC-queue contention

---

## Round 2: Keepalive-Optimized (CDN team recommendation)

CDN team identified that 65-72% of CDN CPU was spent on TCP connection setup/teardown.
Redesigned benchmark: fewer persistent connections, explicit keepalive, no cURL loops.

### Test A: F16s_v2 Keepalive (16 vCPU, 32 GiB)

Kernel tuning: somaxconn=131072, tw_buckets=4M, file-max=4M
RPS/RFS: mask=ffff on eth0 (16 queues), ring buf rx=18139 tx=2560, THP=always
Test params: wrk 16t/256c/ep, hey 192c/ep, ~3,072 total persistent connections

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 205,169 req/s (avg lat 8.9ms) |
| T2 wrk Lua randomized | 36,576 req/s (avg lat 575ms) |
| T3 hey goroutine (4 ep) | 123,497 req/s (avg lat 17ms) |
| T5 kraken combined | 156,659 req/s |
| Peak CPU | 61.38 (3.8x oversubscribed) |
| Peak RAM | 1,134 MB / 32 GiB (3.5%) |
| TIME_WAIT post-T1 | 345 (95% reduction from non-keepalive) |

### Test B: F32s_v2 Keepalive (32 vCPU, 64 GiB, Xeon 8370C @ 2.80 GHz)

Kernel tuning: somaxconn=131072, tw_buckets=8M, file-max=8M
RPS/RFS: mask=ffffffff on eth0 (16 queues), ring buf rx=18139 tx=2560, THP=always
Test params: wrk 32t/512c/ep, hey 384c/ep, ~5,920 total persistent connections

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 208,884 req/s (avg lat 17.5ms) |
| T2 wrk Lua randomized | 53,537 req/s (avg lat 638ms) |
| T3 hey goroutine (4 ep) | 167,745 req/s (avg lat 34ms) |
| T5 kraken combined | 131,606 req/s |
| Peak CPU | 18.57 (0.6x — barely loaded) |
| Peak RAM | 1,453 MB / 64 GiB (2%) |
| TIME_WAIT post-T1 | 122 |

### Round 2 Analysis

- **Keepalive was the real win**: hey went from 52K to 123K (+135%) on F16s_v2
- **CDN was the ceiling**: F32s_v2 at 18.57 CPU (0.6x) couldn't push more than F16s_v2
- **Kraken combined went DOWN on F32s_v2** (131K vs 156K) — more connections meant more CDN overhead for diminishing returns
- **F16s_v2 declared winner** at half the cost of F32s_v2

### Key finding

The CDN simulator on F16s_v2 maxed out at ~29K req/s per endpoint regardless of generator size. This was the server-side ceiling. Upgrading CDN to F32s_v2 should raise this ceiling significantly.

---

## Pending: Round 3 — CDN on F32s_v2

CDN team deploying F32s_v2 (32 vCPU). Expected to raise the per-endpoint ceiling.
Will re-run F16s_v2 vs F32s_v2 generator comparison against the larger CDN.
If CDN ceiling doubles, the F32s_v2 generator may now show proportional gains.
