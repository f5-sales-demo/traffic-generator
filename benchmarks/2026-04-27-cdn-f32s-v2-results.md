# VM Benchmark Results — CDN on F32s_v2

**Date**: 2026-04-27
**CDN Simulator**: 20.65.90.112 (F32s_v2, 32 vCPU)
**Traffic Generator**: 20.114.199.194 (varied per test)
**Benchmark**: bench-keepalive.sh (all persistent connections, no cURL loops, no thundering herd)

---

## Test A: Generator F16s_v2 → CDN F32s_v2

**Generator**: F16s_v2 (16 vCPU, 32 GiB, Xeon 8272CL @ 2.60 GHz)
**Kernel tuning**: somaxconn=131072, tw_buckets=4M, file-max=4M, RPS mask=ffff, THP=always
**Test params**: wrk 16t/256c/ep, hey 192c/ep, ~3,072 total persistent connections

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 350,718 req/s (avg lat 5.2-6.9ms) |
| T2 wrk Lua randomized | 35,708 req/s (avg lat 591ms) |
| T3 hey goroutine (4 ep) | 158,378 req/s (avg lat 17ms) |
| T4 vegeta max | 25,600 rps @ 100% success |
| T5 kraken combined | 224,646 req/s |
| Peak CPU | 84.90 (5.3x oversubscribed) |
| Peak RAM | 1,045 MB / 32 GiB (3%) |
| TIME_WAIT post-T1 | 253 |
| Kraken ESTAB | ~6,651 |

## Test B: Generator F32s_v2 → CDN F32s_v2

**Generator**: F32s_v2 (32 vCPU, 64 GiB, Xeon 8272CL @ 2.60 GHz)
**Kernel tuning**: somaxconn=131072, tw_buckets=8M, file-max=8M, RPS mask=ffffffff, THP=always
**Test params**: wrk 32t/512c/ep, hey 384c/ep, ~5,920 total persistent connections

| Test | Result |
| ------ | -------- |
| T1 wrk static (7 ep) | 330,266 req/s (avg lat 11.4-12.6ms) |
| T2 wrk Lua randomized | 53,156 req/s (avg lat 637ms) |
| T3 hey goroutine (4 ep) | 233,037 req/s (avg lat 34ms) |
| T4 vegeta max | 51,200 rps @ 100% success |
| T5 kraken combined | 152,404 req/s |
| Peak CPU | 47.24 (1.5x — massive headroom) |
| Peak RAM | 1,542 MB / 64 GiB (2%) |
| TIME_WAIT post-T1 | 218 |
| Kraken ESTAB | ~13,477 |

---

## Head-to-Head Comparison

### Individual Tests (tool running alone)

| Test | F16s_v2 (16c) | F32s_v2 (32c) | Delta | Winner |
| ------ | --------------- | --------------- | ------- | -------- |
| T1 wrk static | 350,718 | 330,266 | -6% | F16s_v2 |
| T2 wrk Lua | 35,708 | 53,156 | **+49%** | F32s_v2 |
| T3 hey goroutine | 158,378 | 233,037 | **+47%** | F32s_v2 |
| T4 vegeta ceiling | 25,600 rps | 51,200 rps | +100% | F32s_v2 |

### Combined Kraken (all tools simultaneous)

| Metric | F16s_v2 (16c) | F32s_v2 (32c) | Delta |
| -------- | --------------- | --------------- | ------- |
| **Kraken combined** | **224,646** | **152,404** | **-32%** |
| Kraken wrk | 188,013 | 115,637 | -38% |
| Kraken hey | 30,209 | 33,306 | +10% |
| Kraken ab | 6,424 | 3,461 | -46% |
| Peak CPU | 84.90 | 47.24 | F32 barely loaded |
| Total connections | ~3,072 | ~5,920 | +93% |

---

## Analysis

### Why F32s_v2 wins individual tests but loses combined kraken

1. **Connection count is the key variable.** F32s_v2 opens ~5,920 persistent connections (scaled to 32 cores) vs F16s_v2's ~3,072. When running individually, the CDN handles this fine. When ALL tools run simultaneously, 5,920 connections competing for CDN resources creates more overhead per connection.

2. **The CDN has a connection-serving ceiling.** At ~50K req/s per endpoint for static wrk, both generators hit the same CDN ceiling. Adding more connections doesn't raise that ceiling — it just spreads CDN CPU across more connection state management.

3. **F16s_v2 gets more req/connection.** With 3,072 connections pushing 224K req/s = ~73 req/s per connection. F32s_v2 with 5,920 connections pushing 152K req/s = ~26 req/s per connection. The CDN is more efficient serving fewer, busier connections.

4. **F32s_v2's CPU headroom is wasted.** At 47.24 peak CPU on 32 cores, the generator has massive unused capacity. But throwing more connections at the CDN doesn't help — it hurts.

### The optimization gap

F32s_v2 should be run with F16s_v2's connection count (3,072) but 32 wrk threads. This would give double the request generation CPU per connection without adding CDN connection overhead. The current benchmark scales connections linearly with cores — which is wrong for keepalive workloads.

---

## Comparison Across CDN Sizes

| Generator → CDN | T1 wrk static | T3 hey | T5 kraken | Generator CPU |
| ----------------- | --------------- | -------- | ----------- | --------------- |
| F16 → CDN F16 | 205,169 | 123,497 | 156,659 | 61.38 |
| F32 → CDN F16 | 208,884 | 167,745 | 131,606 | 18.57 |
| **F16 → CDN F32** | **350,718** | **158,378** | **224,646** | **84.90** |
| F32 → CDN F32 | 330,266 | 233,037 | 152,404 | 47.24 |

### Key takeaway

The single biggest throughput improvement came from **upgrading the CDN** (F16→F32), not the generator. F16 generator against CDN F32 produced 224K kraken — the highest combined throughput across all tests. The generator was CPU-saturated (84.90) but the CDN had enough capacity to serve every request efficiently with only 3,072 connections.

---

## Recommendation

**For maximum combined throughput: F16s_v2 generator + F32s_v2 CDN.**

The F16s_v2 generator at ~$0.677/hr delivers the highest kraken combined (224K) because it opens the right number of connections for the CDN to serve efficiently. F32s_v2 generator at ~$1.353/hr opens too many connections and gets 32% less combined throughput.

**However**, if the workload is single-tool (not combined kraken), F32s_v2 generator delivers +47-49% more on hey/Lua tests. For specialized load testing rather than combined stress testing, F32s_v2 has merit.

**Next optimization**: Run F32s_v2 generator with connection counts capped at F16s_v2 levels (3,072 total) to isolate whether the issue is connection count or something else.
