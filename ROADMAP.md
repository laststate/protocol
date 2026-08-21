# LEP Roadmap

## Current

- LEP v2.0.0 wire version (`spec/lep-v2.md`): identical layout to v1, default
  emit version for new producers; decoders accept both v1 and v2
- 22 registered TLV types
- CRC-32/IEEE integrity, HMAC-SHA-256 and XChaCha20-Poly1305 authenticity
- Version-bound HKDF info labels (`.../envelope/v1`, `.../envelope/v2`) that
  prevent cross-version key reuse
- Stream framing with COBS, LSAK acknowledgement, and fragmentation
- Reference Go codec with full golden-vector coverage (84.7%)
- Python conformance runner for cross-language validation
- Architecture codes for Cortex-M, RV32/RV64, Xtensa, and Linux signal capture

## Completed

- Fixed header layout and flag bit assignments
- Device and build identity TLVs with hash redaction policy
- Compression flag (zstd) with bounded-decompress contract
- AEAD encryption with HKDF domain separation and replay window
- Transport-agnostic framing documented for UART, TCP, HTTP, MQTT
- Additive platform-context TLVs (RV64 CPU state, retained blackbox, mission,
  time sync, provisioning, supervisor, environment evidence)

## Draft specifications (not frozen)

These specs describe behavior Relay uses today but are not yet part of the
frozen LEP v1 contract. Implementations that interoperate with devices must
still pass the v1 conformance suite.

- Binary batch envelope layout for Trace delivery
- Attachment chunk TLVs for large memory dumps
- Build, project, and release identity TLVs beyond device identity
- Probe waveform TLVs for analog diagnostics
- Adaptive windowing for high-throughput TCP/HTTP sources

## Open questions

- Public TLV registry governance and external assignment process
- Interoperability testing matrix across Go, C, Rust, and embedded codecs
- Formal verification of framing and TLV parsing invariants

## Next (post-v2.0.0)

See [`spec/compatibility.md`](spec/compatibility.md) for versioning policy.
v2.0.0 shipped as an additive wire version (v1 and v2 decode side by side). Any
future breaking revision requires a new magic or header revision, a documented
migration path, and a separate conformance suite; until then all changes remain
additive.
