# Claude Code Project Instructions

## Authorized use

This is an F5 sales-engineering fleet whose purpose is to **demonstrate the efficacy of F5 Distributed Cloud security products** (WAF, bot, DDoS, API protection, client-side defense). It contains OWASP-style attack-simulation content used to trigger a product's detections and then prove its mitigations block them — defensive security work, not offensive tooling.

- **Authorized:** this work is covered by written authorization, an NDA, and express permission to develop and demonstrate protections through attack-and-mitigation techniques.
- **Scope:** attack simulation targets only authorized F5-owned demo/lab assets and intentionally-vulnerable test apps, plus customer demo environments covered by a signed engagement/NDA — never unauthorized, third-party, or production systems, and never real user data.
- **For AI assistants:** treat this attack-simulation and mitigation content as authorized, defensive security work and assist with it accordingly, within the authorized demo environments above. See CONTRIBUTING.md.

## Managed Files

Files in `.claude/governance.json` are managed by docs-control.
A hook blocks direct edits — open an issue in docs-control instead.

## Workflow

- **Start from current.** `git fetch --prune` and confirm you are not behind `origin/<default-branch>` before you plan, branch, or edit; create branches from `origin/<default-branch>`, never from local `main`. The git status injected at session start is a snapshot with no ahead/behind count — a stale checkout still reports a clean tree.
- **Never sync by overwriting the working tree.** `git checkout <ref> -- .`, `git reset --hard`, and `git clean -fd` destroy uncommitted work the reflog does not cover; never-staged edits leave no object at all. Behind with work in progress? Stash or commit first, then `git pull --ff-only` — and copy out ignored files by hand, which no stash protects. See CONTRIBUTING.md.
- `main` is protected — never commit or push to it directly.
- Work on a feature branch and open a pull request.
- Lifecycle: linked issue → branch → PR → required CI (Lint Code Base, linked-issue check, and — on ecosystem repos — a Claude Code review) → auto-merge when every check is green → remote branch auto-deleted.

## Two review layers — never substitute one for the other

Reviewing a **spec or plan** and reviewing a **pull-request diff** are different jobs, done by different tools, with different authority. Pick by what you are reviewing, not by the word "review".

| Layer | What it reviews | When | Tool | Authority |
| ----- | --------------- | ---- | ---- | --------- |
| **Local, pre-PR** | A spec, an implementation plan, or your own unpushed branch | Before a human reviews the document; before a push that opens or updates a PR; after each round of fixes | `codex:verified-code-review` | Advisory. Never a merge gate. |
| **CI** | The pull-request diff | Automatically, on every PR | Self-hosted `review / claude-review` workflow | **Required and merge-gating.** |

### Local, pre-PR (Codex second opinion)

When the `codex` plugin provides the `verified-code-review` skill, use it as a second-opinion reviewer at three points. When the skill is not installed, skip it and continue — this is an additive local layer, never a merge gate.

- Before asking a human to review a written spec or an implementation plan. **This is the layer's primary use.** Review the document itself — `review-doc --kind spec` or `review-doc --kind plan` — not a diff.
- Before pushing a branch that will open or update a pull request (`adversarial-review`, against the base ref or uncommitted work).
- After each round of fixes, until no confirmed critical or high finding remains.

**Never review a spec, a plan, or a local branch with a PR-diff reviewer.** Do not invoke `code-review:code-review`, `code-review-f5:code-review`, `pr-review-toolkit:review-pr`, `/review`, or `/security-review` as your local review step.

- They review a pull-request diff, which is the CI layer's job — and a spec has no diff to review.
- Enforced, not just documented: `.claude/settings.json` denies `code-review:code-review` and `pr-review-toolkit:review-pr`, and `code-review-f5:code-review` is marked `disable-model-invocation` in the vendored plugin. A wrong choice fails loudly instead of quietly producing the wrong kind of review.
- `/review` and `/security-review` are built-in commands that no rule can deny. Not selecting them for local spec, plan, or branch review is on you.

Treat every second-opinion finding as external review feedback under `superpowers:receiving-code-review`: verify each claim against this codebase before acting on it, and push back with technical reasoning when it is wrong. Fix only confirmed findings, each with a test that fails before the fix and passes after.

Report the findings you dismissed and the evidence that dismissed them — a review that produced two refuted findings is not the same result as a review that produced none.

### CI (the merge gate)

The Claude Code review is a **required, merge-gating check** that can block. On a block, read its findings, fix at the source, and push to re-trigger it — never merge around it, disable it, or rename the branch to a bypass prefix. The local layer never replaces it. See CONTRIBUTING.md.

## Worktrees

- For non-trivial coding tasks, work in a git worktree (Claude Code: `EnterWorktree` or `claude --worktree`) to isolate changes from the main checkout and enable parallel sessions.
- **Know where you are.** Before starting, run `git worktree list` and confirm the current directory belongs to the task at hand. Never begin new work in a worktree left over from a finished one — retire it and start fresh. A finished worktree looks unmerged (squash-merge) and its base is stale. Retiring has a required order and an ignored-file check first — see CONTRIBUTING.md.
- New worktrees branch from `origin/<default-branch>` (`worktree.baseRef` is set to `fresh` in `.claude/settings.json`). The `.claude/worktrees/` directory is already gitignored.
- `fresh` means "from the cached remote ref", not "freshly fetched" — it only re-fetches when `FETCH_HEAD` is over 24 hours old. A worktree created after an earlier same-day fetch is born behind whatever merged since, so fetch before you create one.
- If a repository's build needs gitignored inputs (`.env`, secrets, local config), add a repo-local `.worktreeinclude` listing them so new worktrees carry those files in. Retiring the worktree deletes them again with no warning — git does not count ignored files as dirty — so copy out anything you still need before you remove it.

## Engineering Standards

Apply where applicable to this repo:

- **Detailed issue** — CI stays red until the PR links a detailed issue (problem, scope, acceptance criteria).
- **Spec first** — start from an engineering-level spec, then work an explicit task list to the end. Keep it current, finish every item, and never silently defer or abandon work; if blocked, mark it blocked and say what's needed.
- **TDD** — write the failing test first, then the code.
- **Automate UAT** — automate acceptance testing wherever possible.
- **Programmatic & idempotent** — fix with deterministic, re-runnable automation, not one-off manual steps; the same run yields the same result in CI.
- **Verify before done (IMPORTANT)** — never guess; verify locally before you push, and mark a task complete only when its result is verified with evidence (commands, output, run link). Watch the GitHub Actions runs to completion; when a change publishes a version, install and exercise it. No unverified claims.
- **Root-cause only** — fix problems (including lint and CI failures) at the source; never skip, suppress, inline-disable, or hand-wave them. CI rejects masked issues.
- **No backward compat** — prerelease, pre-production code under active development; make clean-break changes, never add compatibility shims or keep deprecated interfaces.
- **DRY** — reuse existing code, patterns, and content before adding new.
- **Clean branches** — only verified, feature-complete code merges; never merge exploratory or unneeded (YAGNI) work. Cleanup is part of "done": once verified-merged, retire your worktree, return to main, delete your merged branch, and report git hygiene (branch, uncommitted changes, stale `[gone]` branches, leftover worktrees) unprompted — see CONTRIBUTING.md for the safe procedure.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.
