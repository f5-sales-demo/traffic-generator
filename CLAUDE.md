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

- `main` is protected — never commit or push to it directly.
- Work on a feature branch and open a pull request.
- Lifecycle: linked issue → branch → PR → required CI (Lint Code Base, linked-issue check, and — on ecosystem repos — a Claude Code review) → auto-merge when every check is green → remote branch auto-deleted.
- The Claude Code review is a **required, merge-gating check** that can block. On a block, read its findings, fix at the source, and push to re-trigger it — never merge around it, disable it, or rename the branch to a bypass prefix. See CONTRIBUTING.md.

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
- **Clean branches** — only verified, feature-complete code merges; never merge exploratory or unneeded (YAGNI) work. Cleanup is part of "done": once verified-merged, return to main, delete your merged branch, and report git hygiene (branch, uncommitted changes, stale `[gone]` branches) unprompted — see CONTRIBUTING.md for safe `[gone]` cleanup and per-session isolation of concurrent sessions.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.
