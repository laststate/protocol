// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

// Package lep implements the Latch Event Protocol (LEP) reference codec.
//
// LEP is a binary envelope format for device telemetry used by the Latch
// platform. It supports authentication (HMAC-SHA256), encryption (XChaCha20-Poly1305),
// compression (zstd), and replay protection.
//
// Wire versions: v1 and v2 are accepted on decode; Encode emits v2 by
// default. Version-bound HKDF info labels prevent cross-version key reuse.
//
// # Envelope Format
//
//	A LEP envelope consists of:
//	  - 4-byte magic ("LSTP")
//	  - 1-byte version (1 or 2)
//	  - 1-byte event type
//	  - 1-byte architecture
//	  - 1-byte flags
//	  - 4-byte sequence number
//	  - 4-byte event ID
//	  - 4-byte payload length
//	  - 4-byte header CRC-32
//	  - [optional AEAD metadata: 24-byte nonce + 4-byte key ID]
//	  - payload (TLV-encoded)
//	  - 4-byte payload CRC-32
//	  - [optional AEAD tag: 16 bytes]
//	  - [optional HMAC-SHA256: 32 bytes]
//
// # Flags
//
//	0x01 - Authenticated (HMAC-SHA256)
//	0x02 - Encrypted (XChaCha20-Poly1305)
//	0x04 - AEAD mode (requires 0x01 and 0x02)
//	0x08 - Truncated (optional fields omitted)
//	0x10 - Compressed (zstd)
//
// # TLV Types
//
//	Standard LEP TLV types range from 1 (Source) to 22 (Environment).
//	Types 1-15 are base event fields; 16-22 are Latch-specific context.
//
// # Crypto
//
//	Key derivation uses HKDF-SHA256 with domain-separated info strings.
//	The info label is bound to the wire version:
//	  - v1 envelope key: "laststate/latch/envelope/v1"
//	  - v2 envelope key: "laststate/latch/envelope/v2"
//
//	Salt for envelope keys is: key_id(4) || sequence(4) || event_id(4), all LE.
//
// # Stream Framing
//
//	Envelopes are transmitted in Latch Stream frames:
//	  'LS' | version(1) | reserved(1) | length(u32 LE) | envelope | crc32(u32 LE)
//
//	LSAK control messages (12 bytes) acknowledge receipt:
//	  'LSAK' | version(1) | status(1) | reserved(4) | event_id(u32 LE)
//
// # Replay Protection
//
//	Use ReplayCache to detect recycled (source, event_id) pairs. The cache
//	maintains a sliding window of recent events and flags conflicts when
//	different payloads arrive for the same event_id.
package lep
