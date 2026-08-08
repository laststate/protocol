# Contributing

Thanks for improving LEP. By contributing, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening a pull request

1. Discuss a new wire assignment or incompatible proposal in an issue first.
2. Put wire-format changes in `spec/` and `registry/` before implementation.
3. Add or update golden vectors under `test-vectors/`.
4. Keep `implementations/go` matching valid vectors.
5. Do not include device captures, credentials, private keys, or customer data.
6. Run the checks below and describe compatibility impact in the pull request.

```bash
cd implementations/go && go vet ./... && go test ./...
python conformance/runner/run.py
```

## Compatibility expectations

LEP v1 additions must preserve the fixed header and existing field semantics.
Unknown TLVs are length-skipped; unknown header flag bits are rejected. See
[spec/compatibility.md](spec/compatibility.md) before allocating a type or flag.

## Reporting a security issue

Do not use a public issue for vulnerabilities. Follow the
[security policy](SECURITY.md) instead.
