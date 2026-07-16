# Contributing

1. Wire changes go in `spec/` and `registry/` first.
2. Add or update golden vectors under `test-vectors/`.
3. Keep `implementations/go` matching valid vectors.
4. Run `go test ./...` in `implementations/go` and `python conformance/runner/run.py`.
