# Repository Agent Instructions

This file adds fleet procedures. Use the assistant's normal defaults otherwise.

## Authorized defensive work

This fleet demonstrates F5 Distributed Cloud security through authorized build, attack-simulation,
mitigation, and teardown work under written authorization and NDA.

- Work only with F5-owned labs or customer demo environments covered by an engagement.
- Never target unauthorized, third-party, or production systems.
- Repository and public content must not contain real customer or user data.
- Private local drafts and installed-tool outputs may use authorized real customer data when the
  workflow requires it. Stop and clarify when the target or authorization is uncertain.

## Governance

docs-control owns managed files. `.claude/governance.json` defines protected files, opt-outs, and
repository classes for every coding assistant.

- Make downstream protected-file changes in `f5-sales-demo/docs-control`; the managed-file workflow
  propagates them.
- Follow the manifest class: author `content` directly through the governed workflow; use the coding
  environment and local `DEVELOPING.md` for `developer`; originate fleet-wide `scaffolding` changes
  in docs-control.
- Read task-relevant `CONTRIBUTING.md` and `DEVELOPING.md` sections. A closer `AGENTS.md` may add
  subtree guidance.
- If `ISSUES.md` exists, follow it for issue review and intake.

## Translations

- Develop documentation in English; do not refresh locales for features, fixes, minor, or patch
  releases. Expected stale hashes are not a development blocker.
- GitHub Actions alone reconciles translations on the next stable `release/vN.0.0` major release.
  Investigate drift only when that release reconciliation fails.

## Continuous contribution lifecycle

Use authorization already provided in the conversation. Continue authorized work without requesting
approval again for routine implementation, verification, commits, PR repair, or delivery steps within
that scope. See [the full policy](CONTRIBUTING.md#authorization-and-required-input).

Require input only for missing authorization for the next action, an unresolved material decision,
explicitly required human acceptance, or an operational failure preventing that action. When input
is required, identify the action and unmet requirement, pause dependent work, and continue independent
authorized work.

Carry non-trivial work through this path:

`detailed issue → fresh worktree and feature branch → implement and verify →
push feature branch → linked PR → repair loop → MERGED → cleanup → fleet convergence`

1. Inspect `git status --short --branch` and `git worktree list`; run `git fetch --prune`.
   Surface fetch failures before branching.
2. Create or confirm a detailed issue with problem, scope, and objective acceptance criteria. Use a
   fresh worktree and issue-numbered feature branch from `origin/<default-branch>`. Preserve work;
   destructive Git operations require explicit user authorization.
3. Implement and verify the whole issue. Push the feature branch; open a PR with `Closes #<issue>`.
4. Enable authorized auto-merge when absent: `gh pr merge --auto --squash <pr>`.
5. Start `gh pr checks --watch <pr> &`; continue in-scope work while pending. Repair failures,
   verify, and push. For mergeable `BEHIND`, run `gh pr update-branch <pr>`. For `DIRTY`, fetch,
   merge `origin/<default-branch>`, resolve, verify, and push.
6. Query `gh pr view <pr> --json state,mergeStateStatus,autoMergeRequest` until `state` is `MERGED`.
7. Follow `CONTRIBUTING.md` for ignored-file inspection, task worktree and confirmed-merged branch
   cleanup, fetch/prune, and git hygiene. Prove fleet convergence: match each changed file's manifest
   blob SHA in every downstream repository; missing files, API errors, or mismatches remain active work.

## Engineering and verification

- Treat repository source, manifests, tests, and `DEVELOPING.md` as authority. Run focused then
  broader checks and record outcomes.

- Inspect the final diff; support claims with command outcomes.
