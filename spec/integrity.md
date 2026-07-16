# Integrity

## CRC-32 profile

| Property | Value |
|----------|-------|
| Name | CRC-32/ISO-HDLC (IEEE) |
| Poly (normal) | `0x04C11DB7` |
| Poly (reflected) | `0xEDB88320` |
| Init | `0xFFFFFFFF` |
| RefIn | true |
| RefOut | true |
| XorOut | `0xFFFFFFFF` |
| Width | 32 bits |
| Wire encoding | little-endian `u32` |

Test vector (empty message): CRC = `0x00000000` after full algorithm (init+xor).  
Common library check: `CRC32("123456789") = 0xCBF43926`.

## Header CRC

```
header_crc = CRC32(bytes[0 .. 20))
store LE at bytes[20 .. 24)
```

Covers: magic, version, event_type, architecture, flags, sequence, event_id, payload_length.

## Payload CRC

### Plain / auth-only

```
payload_crc = CRC32(payload)
store LE immediately after payload
```

### AEAD

```
payload_crc = CRC32(metadata || ciphertext)
store LE after ciphertext, before tag
```

## Relationship to authentication

| Mechanism | Protects against | Does not protect against |
|-----------|------------------|---------------------------|
| CRC-32 | Random bit flips, truncation | Malicious modification |
| HMAC-SHA-256 | Tampering (with key) | Confidentiality loss |
| AEAD tag | Tampering + binds AAD | Lost keys / weak nonces |

Receivers MUST verify CRCs even when cryptographic authentication is present (defense in depth / early reject).

## Stream-level CRC

Latch Stream frames carry an **additional** IEEE CRC-32 of the raw LEP envelope bytes. That CRC is part of framing, not of the envelope. See [`framing.md`](framing.md).
