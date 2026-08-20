# Changelog

All notable changes to the Last State Protocol (LEP).

## [1.1.0] — 2026-08-15

### Added
- **Binary batch envelope** — draft spec for Trace delivery batching
- **Attachment chunk TLVs** — draft spec for large memory dumps
- **Build/project/release identity TLVs** — enhanced device identity beyond device TLV
- **Probe waveform TLVs** — draft spec for analog diagnostics
- **Adaptive windowing** — draft spec for high-throughput TCP/HTTP sources
- **Python conformance runner** — cross-language validation

### Changed
- Registry: 22 registered TLV types (was 18)
- Spec: compression flag (zstd) with bounded-decompress contract
- Go codec: renamed TLV type constants to match the registry names (e.g. `TLVSource`→`TLVIdentity`, `TLVHeartbeat`→`TLVFault`) — values unchanged
- Spec: documented architecture code `5 = riscv64` (was unallocated)
- Added `.gitattributes` enforcing LF line endings

## [1.0.0] — 2026-07-29

### Added
- Fixed header layout and flag bit assignments
- Device and build identity TLVs with hash redaction policy
- Compression flag (zstd) with bounded-decompress contract
- AEAD encryption with HKDF domain separation and replay window
- Transport-agnostic framing documented for UART, TCP, HTTP, MQTT
- Additive platform-context TLVs (RV64 CPU state, retained blackbox, mission, time sync, provisioning, supervisor, environment evidence)
- Architecture codes for Cortex-M, RV32/RV64, Xtensa, and Linux signal capture
- Reference Go codec with full golden-vector coverage
