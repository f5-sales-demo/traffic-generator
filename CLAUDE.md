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
- Lifecycle: linked issue → branch → PR → required CI (Lint Code Base, linked-issue check) → auto-merge when every check is green → remote branch auto-deleted. The Claude Code review is **suspended**, and the translation-freshness audit still runs but no longer gates a merge — see CONTRIBUTING.md.

## Two review layers

Reviewing a **spec or plan** is not reviewing a **pull-request diff**. Pick by what you are reviewing, not by the word "review". Full detail: CONTRIBUTING.md, "Automated code review".

- **Local, pre-PR — advisory, never a gate.** When installed, use `codex:verified-code-review` before a human reviews a spec or plan (`review-doc --kind spec|plan`, its primary use), before a push that opens or updates a PR (`adversarial-review`), and after each round of fixes. When absent, skip it — never substitute a PR-diff reviewer. Confirm findings here before acting; report those you dismissed.
- **Never** use a PR-diff reviewer for a spec, plan, or local branch. `.claude/settings.json` denies `code-review:code-review` and `pr-review-toolkit:review-pr`; `code-review-f5:code-review` is marked `disable-model-invocation`. The built-ins `/review` and `/security-review` cannot be denied — not selecting them is on you.
- **CI** — the `review / claude-review` diff reviewer is **suspended**: not running, not required. Do not wait for it, and do not re-enable it outside REVIEWER-SPEC.md.

## Worktrees

- For non-trivial coding tasks, **the main session** works in a git worktree (Claude Code: `EnterWorktree` or `claude --worktree`) to isolate changes from the main checkout and enable parallel sessions. A subagent never creates one: spawned with `isolation: "worktree"` it already has one, and `EnterWorktree` refuses from a pinned cwd. Grant isolation at spawn, never from inside.
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
- **Report outcomes** — lead with what happened. Show the command and its output as evidence, and say plainly what is done and what is not.
- **Root-cause only** — fix problems (including lint and CI failures) at the source; never skip, suppress, inline-disable, or hand-wave them. CI rejects masked issues.
- **No backward compat** — prerelease, pre-production code under active development; make clean-break changes, never add compatibility shims or keep deprecated interfaces.
- **DRY** — reuse existing code, patterns, and content before adding new.
- **Documentation style** — published content (guides, product documentation, READMEs) follows `STYLE_GUIDE.md`: documentation-reserved example values only (RFC 5737 addresses, `example.com`, RFC 5398 ASNs), never ACME, no credential material even if revoked, no real customer data, and sanitized screenshots. Run its pre-publish checklist before opening a documentation PR.
- **Clean branches** — only verified, feature-complete code merges; never merge exploratory or unneeded (YAGNI) work. Cleanup is part of "done": once verified-merged, retire your worktree, return to main, delete your merged branch, and report git hygiene (branch, uncommitted changes, stale `[gone]` branches, leftover worktrees) unprompted — see CONTRIBUTING.md for the safe procedure.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.

## Communication

Keep responses focused, brief, and concise; spend most of the response on the main answer. Before your first tool call, say in one sentence what you are about to do. While working, give a brief update only when you find something important or change direction. When you finish, lead with the outcome — your first sentence answers "what happened" — with supporting detail after it.

Match written documents (issues, PR bodies, specs) to what the task needs. Do not pad with filler sections, redundant summaries, or boilerplate.
