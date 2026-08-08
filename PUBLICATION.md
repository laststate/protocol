# Public repository checklist

Complete these GitHub settings immediately before changing repository
visibility:

- Enable private vulnerability reporting, Dependabot alerts, secret scanning,
  and push protection.
- Enable Code Scanning; the checked-in CodeQL workflow runs automatically once
  the repository is public.
- Require pull-request review and successful CI for `main`; restrict direct
  pushes and force pushes.
- Confirm that the repository description, topics, default branch, and issue
  tracker are intentional and that Actions are limited to trusted workflows.
- Review commit authorship and git history for information that should not be
  public. Rewriting published history requires explicit maintainer approval.

Before the change, run the checks in [CONTRIBUTING.md](CONTRIBUTING.md) from a
fresh clone and verify that [SECURITY.md](SECURITY.md) links to an enabled
private reporting channel.
