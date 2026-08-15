# LEP instructions for GitHub Copilot

The complete, tool-neutral guide is [AGENT.md](../AGENT.md). Apply it together
with the nearest scoped `AGENTS.md` file before proposing or editing code.

- LEP is the binary contract between Latch devices, Relay gateways, and Trace
  backends. Treat the header, TLV registry, and golden vectors as compatibility
  contracts. Validate hostile input before access.
- Unknown TLV types are length-skipped; unknown flag bits are rejected. CRC
  detects corruption, not adversaries — authenticity requires HMAC or AEAD.
- Never include device keys, production captures, credentials, or customer data
  in vectors, fixtures, or issues.
- Add a golden vector for every new TLV or flag behavior. Run the conformance
  suite and report what was actually checked.
- Preserve unrelated work, avoid generated output, use the configured human Git
  identity, and never use an `agent/` branch prefix.
- Read [SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md),
  and [`spec/compatibility.md`](../spec/compatibility.md) before proposing wire
  changes.
