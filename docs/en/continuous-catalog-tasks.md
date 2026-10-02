# Continuous catalog delivery tasks

- [x] Explicit ordered catalog: 151 numbered entrypoints, eleven browser scenarios, two benchmarks.
- [x] Read-only suite dry-run, missing dependency failure, structured configuration.
- [x] Shared HTTP dispatch clock, fail-closed destination boundary, bounded stress configuration.
- [x] Scenario deadline and process-group cleanup; private receipts and bounded retention.
- [x] Azure browser launcher sharing the AWS engine; CSD stays disabled.
- [x] Initial failure tests: catalog (5), runtime (6), installer (2), proxy (1), Azure guard (1).
- [ ] Complete fixture/prerequisite recovery and meaningful-launch assertions.
- [ ] Complete installed namespace/browser/scanner pacing, cleanup and restart checks.
- [ ] Required static checks and credential-free Terraform checks.
- [ ] Linked PR, green required CI and confirmed merge.
- [ ] Pin immutable merged artifact in WAAP #552 and complete live acceptance there.

Source tests establish local contracts only. No complete live catalog pass, 200 requests/sec
acceptance, or WAAP protection acceptance is claimed by this task state.
