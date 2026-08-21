# Changelog

All notable changes to the Last State Protocol (LEP).

## [Unreleased]

### Added
- **Cross-repo consumer certification gate** — `tools/verify_vendored.py` checks
  any checked-out Relay/Trace vendored vectors against `test-vectors/manifest.json`
  (SKIPs repos that are not checked out; best-effort because consumers are private).
  CI runs it via `.github/workflows/consumer-vectors.yml`.

## [2.0.0] — 2026-08-20

### Added
- **LEP v2 wire version** (`spec/lep-v2.md`): identical layout to v1, default
  emit version for new producers. Encoders emit v2; decoders accept v1 and v2.
- **Version-bound HKDF info labels**: `laststate/latch/envelope/v2` for v2
  envelopes. Prevents cross-version key reuse (a v1 seal can never verify as v2).
- **Reproducible crypto goldens**: `crypto/aead-xchacha-v{1,2}.hex` and
  `crypto/hmac-auth-only-v{1,2}.hex` now use documented test-only keys and
  fixed nonces recorded in `test-vectors/manifest.json`.
- **Manifest kinds**: valid/invalid/crypto-aead/crypto-hmac/stream/lsak plus a
  `keys` section; Python runner validates structurally, Go reference tests
  verify AEAD/HMAC tags cryptographically.
- **Go reference tests**: golden AEAD/HMAC/stream/LSAK verification, tamper
  rejection, version domain-separation proof, zstd compression round-trip,
  Latch Stream resync recovery, replay/error-path coverage. Coverage 64.8% → 84.7%.

### Fixed
- **LSAK status encoding bug**: `LSAckStored` and friends were `iota`-based and
  started at 6; they now match `spec/framing.md` (1 = ACK_STORED … 8 = NACK_INTERNAL).
  Goldens regenerated.

### Changed
- `Encode` defaults `version = 2` when unset; `Validate`/`Open` accept v1 and v2.
- `Seal` → `SealWithNonce` for deterministic nonce in goldens; `Seal` keeps
  CSPRNG behavior.
- Removed dead `auth`/`stream` HKDF label vars (only the envelope label is used).

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
