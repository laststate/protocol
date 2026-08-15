# LEP Roadmap

## Current

- LEP v1.0.0 wire format with 22 registered TLV types
- CRC-32/IEEE integrity, HMAC-SHA-256 and XChaCha20-Poly1305 authenticity
- Stream framing with COBS, LSAK acknowledgement, and fragmentation
- Reference Go codec with full golden-vector coverage
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

- LEP v2 planning: how to evolve without breaking v1 conformance
- Public TLV registry governance and external assignment process
- Interoperability testing matrix across Go, C, Rust, and embedded codecs
- Formal verification of framing and TLV parsing invariants

## v2.0.0 (planned)

See [`spec/compatibility.md`](spec/compatibility.md) for versioning policy.
A v2 release requires: a new magic or header revision, a documented migration
path from v1, and a separate conformance suite. Until then, all changes extend
v1 additively.
