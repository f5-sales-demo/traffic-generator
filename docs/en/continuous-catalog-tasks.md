# Continuous catalog delivery tasks

- [x] Explicit ordered catalog: 151 numbered entrypoints, eleven browser scenarios, two benchmarks.
- [x] Read-only suite dry-run, missing dependency failure, structured configuration.
- [x] Shared HTTP dispatch clock, fail-closed destination boundary, bounded stress configuration.
- [x] Scenario deadline and process-group cleanup; private receipts and bounded retention.
- [x] Azure browser launcher sharing the AWS engine; CSD stays disabled.
- [x] Focused failure tests and browser source checks pass. Installer inventory, proxy cancellation, bounded TLS matrix and stalled-proxy recovery have regression coverage.
- [ ] Complete fixture/prerequisite recovery and meaningful-launch assertions. Seeded crAPI and restaurant exports are installed; blocked browser credentials launch meaningfully. Full catalog validation remains open.
- [ ] Complete installed namespace/browser/scanner pacing, cleanup and restart checks. Azure eleven-simulation browser pass verified; each assertion, screenshot and context/browser cleanup passed.
- [x] Shared Python Ruff/mypy/pylint and staged hooks pass; AWS static bootstrap/identity contracts pass. WAAP Terraform init/validate and showcase plans pass.
- [ ] Linked PR, green required CI and confirmed merge.
- [ ] Pin immutable merged artifact in WAAP #552 and complete live acceptance there.

Source tests establish local contracts only. No complete live catalog pass, 200 requests/sec
acceptance, or WAAP protection acceptance is claimed by this task state.

Long-run diagnostics exposed proxy descriptor exhaustion during nested CDN stress. The service now sets a 65,536 descriptor limit and fails on stalled proxy telemetry; timeout and tool outcomes remain distinct from missing launches. Two successful complete passes are still required.
