# Compression (v1.0)

**Status:** Frozen policy.

## Flag

| Bit | Name | Who sets |
|----:|------|----------|
| 3 | TRUNCATED | Latch / any producer omitting optional TLVs |
| 4 | COMPRESSED | Gateways only (zstd of entire payload) |

Devices **MUST NOT** set bit 4 unless they implement the same zstd profile as Relay.

## Gateway zstd (bit 4)

1. Start from plain envelope (flags 0 or TRUNCATED only).  
2. zstd-compress the payload bytes.  
3. Set `FlagCompressed`, update `payload_length` and CRCs.  
4. Optionally Seal afterward.

Receive: Open → if COMPRESSED → zstd decompress → TLV parse.

## MCU helpers (Latch)

RLE / varint / delta codecs exist **in-library** for field encoding; they are **not** the header COMPRESSED bit.

## Limits

Decompressed size MUST be ≤ configured max envelope. Reject compression bombs.
