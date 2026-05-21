# CLAUDE.md — sandtrace

## Remotes

- `origin` → `https://github.com/cc-consulting-nv/sandtrace.git` (private staging fork)
- `upstream` → `https://github.com/sandtrace/sandtrace.git` (canonical public)

All day-to-day work happens on `origin`. Issues are tracked on `origin`. Upstream is the published artifact.

## Auth

Use cccnv account for both remotes:

```bash
GH_TOKEN=$(gh auth token -u cccnv) git push origin <branch>
GH_TOKEN=$(gh auth token -u cccnv) git push upstream <branch>
GH_TOKEN=$(gh auth token -u cccnv) gh issue create --repo cc-consulting-nv/sandtrace ...
GH_TOKEN=$(gh auth token -u cccnv) gh pr create --repo cc-consulting-nv/sandtrace ...
```

Never `unset GH_TOKEN` — always inline.

## Daily workflow

1. Branch from `origin/main`: `git checkout -b feat/foo origin/main`
2. Commit, push to `origin`: `GH_TOKEN=$(gh auth token -u cccnv) git push -u origin feat/foo`
3. Open PR on `cc-consulting-nv/sandtrace`. Review. Merge into `origin/main`.
4. Issues stay on `cc-consulting-nv/sandtrace`.

## Promoting to upstream (manual gate only)

Never auto-mirrored. Manual command after explicit human approval:

```bash
# Sync origin main first
git checkout main
GH_TOKEN=$(gh auth token -u cccnv) git pull origin main

# Promote to upstream
GH_TOKEN=$(gh auth token -u cccnv) git push upstream main
GH_TOKEN=$(gh auth token -u cccnv) git push upstream --tags  # if releasing
```

Same rule as global CLAUDE.md: **STOP before push to upstream main without explicit human approval for that specific promotion**.

## Pulling upstream changes

If upstream advances independently:

```bash
git fetch upstream
git checkout main
git merge upstream/main           # or rebase if origin main is clean
GH_TOKEN=$(gh auth token -u cccnv) git push origin main
```

## Issue tracking

- File issues on `cc-consulting-nv/sandtrace`.
- Reference upstream sandtrace/sandtrace issue numbers in body when relevant (cross-repo link with `sandtrace/sandtrace#NNN`).
- Don't file issues directly on `sandtrace/sandtrace` unless deliberately public.

## Commit messages

No Claude Code attribution. No `Co-Authored-By: Claude` trailer. No `🤖 Generated with Claude Code` footer. Clean human-authored commits only (matches global CLAUDE.md).
