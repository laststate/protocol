# Latch Attachment Chunks Specification (Protocol)

**Status:** Final  
**Version:** 1.0.0  
**Date:** 2026-08-16
**LEP Version:** 1.0

## Overview

Attachment chunks enable large payloads (crash dumps, logs, binaries) to be transmitted within Latch envelopes.

**This spec is frozen as of LEP v1.0.0. No backward-incompatible changes will be made.**

## Chunk Format

Each attachment chunk is a Latch envelope with:

- **TLV Tag:** `0x10` (ATTACHMENT_CHUNK)
- **Chunk Index:** 4 bytes (0-based)
- **Total Chunks:** 4 bytes (total number of chunks)
- **Payload:** Variable (chunk data, max 4 KB)
- **Checksum:** 4 bytes (CRC32 of chunk payload)

## Reassembly

1. **Receive** all chunks for a given attachment
2. **Sort** by chunk index
3. **Concatenate** payloads
4. **Verify** final checksum

## Constraints

- Maximum attachment size: 16 MB
- Maximum chunk size: 4 KB
- Maximum chunks per attachment: 4096

## Error Handling

- Missing chunks: Request retransmission
- Corrupted chunks: Discard and request retransmission
- Timeout: Abandon attachment and log error

## References

- [TLV Registry](registry/tlv-types.md)
- [Batch Spec](batch.md)
