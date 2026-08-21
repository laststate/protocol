# Compatibility

Header `version` is the wire major. Unknown major → reject. Unknown TLVs → skip by length. Unknown flag bits outside `0x1F` → reject.

## Versions

| Version | Status | Notes |
|--------:|--------|-------|
| 1 | Supported | [`lep-v1.md`](lep-v1.md) |
| 2 | Supported (default for new producers) | [`lep-v2.md`](lep-v2.md) |

v2 keeps the v1 fixed header layout, flags, CRC algorithm, TLV shape, and
security layouts. The only functional difference is the wire `version` byte
and the version-bound HKDF info label (§6.4 of [`lep-v2.md`](lep-v2.md)).

**Compatibility rules:**

1. Producers SHOULD emit v2 unless a deployment constraint requires v1.
2. Receivers that support v2 MUST also accept v1.
3. Receivers MUST NOT accept any other version.
4. Cross-version crypto is impossible by construction: v1 and v2 derive
   distinct keys from the same IKM (different HKDF info labels), so a v1
   sealed envelope can never verify as v2 and vice versa. This is a
   security feature, not a migration path.

## Flags

| Bit | Name |
|----:|------|
| 0 | AUTHENTICATED |
| 1 | ENCRYPTED |
| 2 | AEAD |
| 3 | TRUNCATED |
| 4 | COMPRESSED (gateway zstd only) |

Flag semantics are identical across v1 and v2.

## Resolved product mismatches (historical)

| Topic | Resolution |
|-------|------------|
| Flag bit 3 | TRUNCATED (not compress) |
| Arch 3/4 | xtensa / linux |
| AEAD | 24B nonce + u32 key_id, XChaCha + HKDF |
| HMAC | header \|\| payload \|\| payload_crc |
| TLV 6/7 | BREADCRUMB / METRIC |

Older Relay builds that used bit3 as zstd or alternate AEAD packing need migration / dual-read.