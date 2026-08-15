## What changed

Describe the behavior changed and why.

Closes #

## Compatibility

- [ ] This does not change existing LEP v1 field semantics or vector layouts.
- [ ] Registry changes in `registry/tlv-types.md` precede vector or implementation changes.
- [ ] New wire behavior has a golden vector under `test-vectors/`.
- [ ] Unknown TLV types and flag bits remain length-skippable / rejectable.

## Validation

- [ ] `cd implementations/go && go vet ./... && go test ./...`
- [ ] `python conformance/runner/run.py`
- [ ] All existing vectors still pass

## Data handling

- [ ] This pull request contains no credentials, private keys, production
      captures, or personal data.

## Risk

Describe compatibility, security, or cross-language consumer impact. Write
`none` when not applicable.
