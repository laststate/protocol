# Protocol — Cloud Deployment Plan

**Status:** Local changes complete. Pending approval to push.

## Repository Settings

### Visibility
- [ ] Change from private to **public**

### Default branch
- [ ] Set `main` as default branch (already in place)

### Repository topics
- [ ] Add topics: `protocol`, `lep`, `firmware`, `diagnostics`, `embedded`, `open-source`, `apache-2.0`

## Branch Protection (main)

Enable branch protection on `main`:

- [ ] **Require pull request reviews before merging** — 1 approver minimum
- [ ] **Dismiss stale pull request approvals when new commits are pushed**
- [ ] **Require review from Code Owners** — CODEOWNERS file already configured
- [ ] **Require status checks to pass before merging**
  - [ ] `CI` (must pass)
  - [ ] `codeql` (warning-level is acceptable)
- [ ] **Require linear history** — optional, depends on team preference
- [ ] **Include administrators** — recommend yes for this repo
- [ ] **Restrict who can push to matching branches** — @TheusHen only

## Tags

Tag policy:
- [ ] Tags must follow `v<major>.<minor>.<patch>` format
- [ ] Tags must be annotated (not lightweight)
- [ ] Tags must point to a commit reachable from `main`
- [ ] Tag creation restricted to maintainers

## Issue Configuration

Already configured locally:
- [x] `blank_issues_enabled: false`
- [x] Contact links: Discussions, Security advisory, Contributing guide
- [x] Issue templates: bug.yml, feature.yml

## Pull Request Configuration

Already configured locally:
- [x] Pull request template with compatibility, validation, and data handling checks
- [x] Required status checks: `CI`

## Automation

Already configured locally:
- [x] Dependabot: gomod + github-actions, weekly
- [x] Labeler: spec, registry, codec, conformance, vectors, ci, documentation, security
- [x] CODEOWNERS: spec/ and registry/ require maintainer review
- [x] Stale bot: 60 days issues, 45 days PRs
- [x] CodeQL: weekly scan on main + PR checks (Go + Python)
- [x] Release workflow: validates VERSION matches tag, runs conformance

## GitHub Discussions

- [ ] Enable GitHub Discussions for the repository
- [ ] Configure discussion categories:
  - `proposal` — wire-format proposals
  - `question` — integration questions
  - `show-and-tell` — implementations using LEP

## Security

- [ ] Enable GitHub Secret Scanning
- [ ] Enable Dependabot security updates (already configured)
- [ ] Configure security policy URL (already set in SECURITY.md)
- [ ] Enable private vulnerability reporting (already configured)

## Actions

Recommended actions to pin (already using pinned versions in workflows):
- `actions/checkout@v7` (3d3c42e5aac5ba805825da76410c181273ba90b1)
- `actions/setup-go@v5`
- `actions/setup-python@v7` (5fda3b95a4ea91299a34e894583c3862153e4b97)
- `actions/stale@v11` (4391f3da665fdf50b6810c1a66712fb9ba21aa93)
- `github/codeql-action@v3`

## Pre-Push Checklist

Before making the repo public:

- [ ] All secrets removed from git history (`git log -p` search for keys, tokens, endpoints)
- [ ] `.gitignore` is comprehensive (already in place)
- [ ] No production captures in `test-vectors/`
- [ ] No private Relay internals documented
- [ ] LICENSE file present and correct (Apache-2.0, already present)
- [ ] All documentation files review for sensitive content
- [ ] Branch protection rules drafted and ready to apply
