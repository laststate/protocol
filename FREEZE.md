# LEP v2.0.0 — Frozen (reference, not a product)

> Decision 2026-08-26: LEP is a reference contract. Latch 1.0 is the product. Relay/Trace are reference gateway/cloud that consume LEP, not SKUs.

- **Version:** `VERSION` = 2.0.0 (see `spec/lep-v2.md`, `spec/lep-v1.md`)
- **Rule:** no breaking changes without ADR + major bump. Golden hex in `test-vectors/` runs on every CI (`conformance/runner/run.py`, `implementations/go`).
- **Publishing:** LEP has no registry — `latch/library.json:5` and `idf_component.yml:4` publish Latch (which implements LEP), not the standalone protocol.
- **Next:** LEP v2.x only with additive TLVs (skippable). Any new TLV is documented in `spec/registry/tlv-types.md` first.
