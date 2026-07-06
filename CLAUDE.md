# Claude Code Project Instructions

## Managed Files

Files in `.claude/governance.json` are managed by docs-control.
A hook blocks direct edits — open an issue in docs-control instead.

## Workflow

- `main` is protected — never commit or push to it directly.
- Work on a feature branch and open a pull request.
- Every PR must reference a detailed GitHub issue (CI enforces this).

## Engineering Standards

Apply where applicable to this repo:

- **Detailed issue** — CI stays red until the PR links a detailed issue (problem, scope, acceptance criteria).
- **Spec first** — start from an engineering-level spec, then work a task/todo list.
- **TDD** — write the failing test first, then the code.
- **Automate UAT** — automate acceptance testing wherever possible.
- **Verify before done** — back every "done" claim with passing tests or reproducible output.
- **Root-cause only** — never skip, silence, patch over, or band-aid a problem; CI rejects masked issues.
- **No backward compat** — prerelease code; make clean-break changes, no shims or deprecated interfaces.
- **DRY** — reuse existing code, patterns, and content before adding new.
- **Clean branches** — experiment freely, but never commit broken or unneeded (YAGNI) code.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.
