# LEP v2.0.0 — Congelado (reference, não produto)

> Decisão 2026-08-26: LEP é contrato reference. Latch 1.0 é o produto. Relay/Trace são reference gateway/cloud que consomem LEP, não SKUs.

- **Versão:** `VERSION` = 2.0.0 (ver `spec/lep-v2.md`, `spec/lep-v1.md`)
- **Regra:** sem breaking changes sem ADR + major bump. Golden hex em `test-vectors/` roda em todo CI (`conformance/runner/run.py`, `implementations/go`).
- **Publicação:** LEP não tem registry — `latch/library.json:5` e `idf_component.yml:4` publicam Latch (que implementa LEP), não o protocolo isolado.
- **Próximo:** LEP v2.x só com additive TLVs (skippable). Qualquer TLV novo documenta-se em `spec/registry/tlv-types.md` primeiro.
