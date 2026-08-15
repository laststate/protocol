# Contributing to LEP

Thank you for helping make firmware diagnostics interoperable. Contributions do
not need to be large: a new golden vector, a clearer spec note, a conformance
fix, or a focused cross-language validation can be more valuable than a new
feature.

## Find a useful first contribution

- Browse [`good first issue`](https://github.com/laststate/protocol/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for work that should not
  require understanding the whole wire format.
- Browse [`help wanted`](https://github.com/laststate/protocol/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) for codec, conformance, and
  registry work where outside experience is especially useful.
- Use [GitHub Discussions](https://github.com/laststate/protocol/discussions) for integration questions or an early design proposal.
- Open an issue directly for a small bug or documentation gap.

Comment on an issue before starting substantial work so contributors do not
duplicate effort. For wire-format, registry, or crypto changes, start a
discussion first.

## AI-assisted contributions

AI-assisted work is welcome when it is focused, reviewable, and held to the
same evidence standard as any other contribution. Before editing, read the
tool-neutral [agent guide](AGENT.md) and the scoped `AGENTS.md` instructions in
the directories you touch. The guide is available through the native entry
points for Codex, Claude, Gemini, and GitHub Copilot.

AI assistance does not substitute for contributor or maintainer judgment. Do
not claim a version as released or compatible without a passing conformance run
and an updated vector. Do not expose keys, memory captures, private collector
details, endpoints, credentials, or proprietary firmware. The reusable task
brief and review material is in [docs/ai/](docs/ai/README.md) (when available).

## Maintainer response target

We aim to acknowledge new issues and pull requests within 72 hours and provide
an initial triage within seven days. This is a maintainer target, not an SLA.
If there is no response after seven days, one friendly ping is welcome.

## Development setup

You need Go 1.22+ and Python 3.10+. Build and validate the complete portable
suite:

```sh
cd implementations/go && go vet ./... && go test ./...
python conformance/runner/run.py
```

Use the narrowest useful loop while developing:

| Change | Fast validation |
|---|---|
| Documentation | Factual cross-checks against the current spec and registry. |
| TLV or header change | `python conformance/runner/run.py` and the reference codec tests. |
| Go codec | `go vet ./...` and `go test ./...` in `implementations/go/`. |
| Conformance runner | All vectors under `test-vectors/`. |
| CI or release automation | Local `actionlint` when available. |

## Invariants that changes must preserve

- The 24-byte header, magic bytes `LSTP`, and little-endian ordering remain
  stable for the 1.x line.
- Unknown TLV types are always length-skipped; unknown flag bits are always
  rejected.
- CRC validates integrity; authenticity requires HMAC or AEAD with the matching
  flag.
- All length fields are validated before allocation, decompression, or copy.
- Security-sensitive data is minimized and redacted before capture, not only
  before transport.
- AI-generated or human-authored changes use the same focused review, test,
  and evidence requirements.

Do not include device secrets, production keys, captured customer memory,
private endpoints, or proprietary firmware in vectors, fixtures, issues, or
pull requests. Report vulnerabilities privately through the process in
[SECURITY.md](SECURITY.md).

## Pull requests

1. Fork the repository and branch from the current default branch.
2. Keep the change focused. Separate wire-format changes from unrelated cleanup
   when practical.
3. Update the registry in `registry/tlv-types.md` before changing vectors or
   implementation.
4. Add or update golden vectors under `test-vectors/` for any wire behavior
   change.
5. Run the conformance runner and the reference codec tests; include the
   results in the pull request description.
6. Add an entry to [CHANGELOG.md](CHANGELOG.md) when the change affects
   adopters.
7. Fill in the pull request template, including compatibility impact.
8. Resolve review threads and keep the branch current before merge.

Draft pull requests are welcome for early technical feedback. No Contributor
License Agreement is required; contributions are accepted under the
repository's Apache-2.0 license.

Repeated contributors who review changes, help with triage, or own a registry
area can be invited into the maintainer workflow as the community grows.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
