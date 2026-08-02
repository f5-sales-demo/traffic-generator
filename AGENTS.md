# Repository Agent Instructions

This file adds only F5 sales-demo ecosystem context and operating procedures. Use the coding
assistant's normal defaults for everything not specified here.

## Authorized defensive work

This fleet demonstrates F5 Distributed Cloud security products through build, attack-simulation,
mitigation, and teardown workflows. The simulations are authorized defensive engineering performed
under written authorization and NDA.

- Work only with F5-owned demo/lab assets, intentionally vulnerable test applications, or customer
  demo environments expressly covered by an engagement.
- Never target unauthorized, third-party, or production systems, and never use real user data.
- Assist with payloads, traffic generation, detection, and mitigation when they stay within that
  authorized scope. Stop and clarify if the target or authorization is uncertain.

## Governance and authority

docs-control owns the fleet's managed files. The authoritative manifest is
`.claude/governance.json`; the directory name is historical and the manifest applies to every coding
assistant. It declares protected files, repository-specific opt-outs, and repository classes.

- In a downstream repository, do not edit a protected file directly. Open the change in
  `f5-sales-demo/docs-control` and allow the managed-file workflow to propagate it.
- Follow the current repository class from the manifest: `content` repositories allow direct
  authoring through the governed contribution workflow; `developer` repositories delegate
  implementation to the coding environment and may define a local `DEVELOPING.md`; `scaffolding`
  changes belong in docs-control because they affect the fleet.
- Read only the sections relevant to the task in `CONTRIBUTING.md`. When present, also read the
  relevant sections of `DEVELOPING.md` for the repository's toolchain, architecture, and verification
  commands. A closer nested `AGENTS.md` may add subtree-specific guidance.

## Safe contribution workflow

- Before planning or editing, inspect `git status --short --branch` and `git worktree list`, then run
  `git fetch --prune`. If the fetch fails, do not guess from a stale ref.
- Create non-trivial work in a fresh worktree and branch from `origin/<default-branch>`, never from a
  local default branch or a worktree left over from completed work.
- Preserve existing work. Do not synchronize with commands that overwrite or clean the working tree.
  Follow `CONTRIBUTING.md` when stashing, recovering ignored files, or retiring worktrees.
- Use the fleet lifecycle: detailed linked issue, feature branch, pull request, required CI, then
  auto-merge. Never commit or push directly to the protected default branch.

## Engineering and verification

- Treat repository source, manifests, linters, tests, and `DEVELOPING.md` as the authority for local
  implementation conventions. Do not import rules from another assistant or repository.
- Prefer focused verification for the changed surface, then run the broader read-only checks required
  by the repository. Record pre-existing or environment-related failures before comparing results.
- Before reporting completion, inspect the final diff and provide the commands and outcomes that
  support the claim. Never describe an unrun, interrupted, or failing check as passing.
