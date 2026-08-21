# Encryption and Authentication (v2.0)

**Status:** Frozen — device path (Latch) is normative for all producers.
Applies to wire versions 1 and 2; the HKDF info label is bound to the
envelope's `version` byte (§6.4 of [`lep-v2.md`](lep-v2.md)).

## Flags

| Flag | Bit | Role |
|------|----:|------|
| AUTHENTICATED | 0 | Auth trailer present |
| ENCRYPTED | 1 | Payload ciphertext |
| AEAD | 2 | Metadata block present |

Rules: ENCRYPTED ↔ AEAD; AEAD requires AUTHENTICATED. TRUNCATED (3) and COMPRESSED (4) may combine with security flags.

```mermaid
flowchart TD
  P[Plain TLVs] --> A{security mode?}
  A -->|none| W1[header + payload + CRC]
  A -->|HMAC only| W2[header + payload + CRC + HMAC32]
  A -->|AEAD| W3[header + meta28 + ciphertext + CRC + tag16]
```

## AEAD — XChaCha20-Poly1305 (device path)

### Metadata (28 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 24 | Nonce (XChaCha20) |
| 24 | 4 | key_id u32 LE |

### Wire

| Region | Size |
|--------|-----:|
| Fixed header | 24 |
| Metadata | 28 |
| Ciphertext | payload_length |
| Payload CRC | 4 = CRC32(metadata \|\| ciphertext) |
| Poly1305 tag | 16 |

### Parameters

| Item | Value |
|------|-------|
| Algorithm | XChaCha20-Poly1305 |
| AAD | header(24) \|\| metadata(28) |
| IKM | 32-byte device key |
| KDF | HKDF-SHA256 |
| salt | key_id \|\| sequence \|\| event_id (12 bytes LE) |
| info (v1) | `laststate/latch/envelope/v1` (ASCII, no NUL) |
| info (v2) | `laststate/latch/envelope/v2` (ASCII, no NUL) |
| Output | 32-byte derived key |

The info label MUST be selected from the envelope's `version` byte. v1 and
v2 must never share a derived key.

MUST NOT reuse (derived_key, nonce). Implementations MUST verify tag before exposing plaintext.

Golden (v1): [`../test-vectors/crypto/aead-xchacha-v1.hex`](../test-vectors/crypto/aead-xchacha-v1.hex)  
Golden (v2): [`../test-vectors/crypto/aead-xchacha-v2.hex`](../test-vectors/crypto/aead-xchacha-v2.hex)

Test keys and nonces for these goldens are recorded in
[`../test-vectors/manifest.json`](../test-vectors/manifest.json) so any
implementation can reproduce them.

## Auth-only — HMAC-SHA-256

| Region | Size |
|--------|-----:|
| Header | 24 |
| Payload | N |
| Payload CRC | 4 |
| HMAC | 32 |

```
mac = HMAC-SHA-256(key, header || payload || payload_crc)
```

Key id is out of band (config). Prefer the same numeric id space as AEAD `key_id`.

Golden (v1): [`../test-vectors/crypto/hmac-auth-only-v1.hex`](../test-vectors/crypto/hmac-auth-only-v1.hex)  
Golden (v2): [`../test-vectors/crypto/hmac-auth-only-v2.hex`](../test-vectors/crypto/hmac-auth-only-v2.hex)

## Replay

```mermaid
flowchart TD
  R[Receive] --> V[Validate / Open]
  V --> D{policy}
  D -->|same event_id + same hash| ACK2[ACK_DUPLICATE]
  D -->|same event_id + different hash| REJ[reject]
  D -->|new sequence in window| ACC[accept]
```

Default sequence window size: **64**.

## Non-goals

- Asymmetric envelope signatures (see signatures.md for bundles)
- Gateway-only historical metadata packing (removed; use device path)
- Per-version cipher suites (v1 and v2 use the same algorithms)  
