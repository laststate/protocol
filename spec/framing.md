# Framing

The LEP envelope is transport-independent. Framing only delimits envelopes on a byte stream or datagram.

## Latch Stream (device ↔ Relay serial/TCP)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | magic `LS` |
| 2 | 1 | version = 1 |
| 3 | 1 | flags = 0 |
| 4 | 4 | `lep_length` u32 LE |
| 8 | N | LEP envelope |
| 8+N | 4 | CRC-32/IEEE of envelope |

Resync: on bad magic, advance one byte. Reject bad version/flags/length/CRC then continue.

Goldens: [`../test-vectors/transports/latch-stream-basic-v1.hex`](../test-vectors/transports/latch-stream-basic-v1.hex), [`../test-vectors/transports/latch-stream-basic-v2.hex`](../test-vectors/transports/latch-stream-basic-v2.hex)

## COBS

Encode LEP, append `0x00` delimiter. Decode until `0x00`. Max size is policy (gateway default 4 MiB).

## Length-prefix

`length u32 LE || LEP[length]`

## Datagram

One datagram = one LEP envelope (or fragment profile below).

## LSAK (ACK/NACK) — 12 bytes

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | `LSAK` |
| 4 | 1 | version = 1 |
| 5 | 1 | status |
| 6 | 2 | reserved = 0 |
| 8 | 4 | event_id u32 LE |

| Status | Name |
|-------:|------|
| 1 | ACK_STORED |
| 2 | ACK_DUPLICATE |
| 3 | NACK_CORRUPT |
| 4 | NACK_UNSUPPORTED |
| 5 | NACK_BUSY |
| 6 | NACK_TOO_LARGE |
| 7 | NACK_UNAUTHORIZED |
| 8 | NACK_INTERNAL |

Success for durable delivery: 1 or 2. Golden: 
[`../test-vectors/transports/lsak-ack-stored.hex`](../test-vectors/transports/lsak-ack-stored.hex) (status 1 = `ACK_STORED`, event_id 9)

## Fragmentation (MTU-limited links)

Semantic fields (Latch `ls_transport_fragment_t`):

| Field | Meaning |
|-------|---------|
| event_id | same as LEP header |
| envelope_crc | CRC-32 of full envelope |
| total_length | full envelope size |
| offset / fragment_index / fragment_count | slice position |
| fragment_crc | CRC of this slice |
| data | bytes |

Reassemble out of order; verify envelope CRC; then run normal LEP validate. Do not decrypt fragments individually.
