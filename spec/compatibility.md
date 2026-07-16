# Compatibility

Header `version` is the wire major. Unknown major → reject. Unknown TLVs → skip by length. Unknown flag bits outside `0x1F` → reject.

## Flags (v1)

| Bit | Name |
|----:|------|
| 0 | AUTHENTICATED |
| 1 | ENCRYPTED |
| 2 | AEAD |
| 3 | TRUNCATED |
| 4 | COMPRESSED (gateway zstd only) |

## Resolved product mismatches (historical)

| Topic | Resolution |
|-------|------------|
| Flag bit 3 | TRUNCATED (not compress) |
| Arch 3/4 | xtensa / linux |
| AEAD | 24B nonce + u32 key_id, XChaCha + HKDF |
| HMAC | header \|\| payload \|\| payload_crc |
| TLV 6/7 | BREADCRUMB / METRIC |

Older Relay builds that used bit3 as zstd or alternate AEAD packing need migration / dual-read.
