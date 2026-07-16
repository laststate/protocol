# Limits

Receivers MUST enforce bounds **before** allocating based on untrusted lengths.

## Envelope

| Limit | Value | Enforcement |
|-------|------:|-------------|
| Fixed header size | 24 | Constant |
| Minimum plain envelope | 28 | header + empty payload CRC |
| Maximum envelope (gateway default) | 4 MiB (`4194304`) | Relay / reference Go |
| Recommended maximum (MCU) | 64 KiB | Product policy |
| Header maximum (v1) | 24 | No variable header in v1 |
| AEAD metadata | 28 | When AEAD |
| Max auth trailer | 32 | HMAC |

## TLV

| Limit | Value |
|-------|------:|
| Type | 1..65535 (`0` illegal) |
| Value length | 0..65535 |
| Nested identity string | 0..255 |
| Max TLVs per payload | Implementation-defined; MUST stop if malformed |

## Application (recommended defaults)

| Limit | Recommended max |
|-------|----------------:|
| Breadcrumbs per event | 32 |
| Metrics per event | 64 |
| Registers in CPU block | 32 general + documented specials |
| Stack snapshot | 256–4096 bytes (product) |
| Memory region dump | per-region cap (Latch: `LS_DUMP_REGION_MAX_BYTES`) |
| Fragments per envelope | 256 |
| Decompressed size | ≤ max envelope policy |

## Strings

| Limit | Value |
|-------|------:|
| Identity nested field | 255 bytes |
| Free-form messages | Prefer hashes on MCU; full strings optional |

## Fragmentation

| Limit | Value |
|-------|------:|
| Max fragment payload | Transport MTU minus framing overhead |
| Max outstanding reassembly | Implementation-defined; MUST age out |

## Denial-of-service

Implementations MUST:

1. Reject `payload_length` that implies total > configured max.
2. Reject COBS / Latch Stream frames > max.
3. Cap concurrent reassembly state.
4. Avoid unbounded recursion (TLV nesting depth in v1 is shallow: identity nested fields only one level).
