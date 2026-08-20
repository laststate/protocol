// SPDX-License-Identifier: Apache-2.0
// Package lep implements LEP v1 validation, encoding, decoding, and crypto.
//
// LEP (Latch Event Protocol) is a binary envelope format for device telemetry.
// This package provides the complete reference codec including:
//   - Plain envelope encode/validate
//   - AEAD encryption (XChaCha20-Poly1305 + HKDF-SHA256)
//   - HMAC-SHA256 authentication
//   - Replay window protection
//   - zstd compression
//   - TLV parsing and building
//   - Latch Stream framing with COBS resync
//   - LSAK control message handling
//
// The envelope format is:
//
//	LSTP | version | type | arch | flags | sequence | event_id | payload_len |
//	header_crc | [meta] | payload | payload_crc | [tag/auth]
//
// Flags:
//
//	0x01 authenticated  0x02 encrypted  0x04 AEAD  0x08 truncated  0x10 compressed
package lep

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// Envelope constants.
const (
	HeaderSize      = 24
	MaxEnvelopeSize = 4 << 20 // 4 MiB
	Magic           = "LSTP"
	Version1        = 1

	FlagAuthenticated uint8 = 1 << 0
	FlagEncrypted     uint8 = 1 << 1
	FlagAEAD          uint8 = 1 << 2
	FlagTruncated     uint8 = 1 << 3 // optional fields omitted
	FlagCompressed    uint8 = 1 << 4 // zstd of payload; devices do not set this
	KnownFlags              = FlagAuthenticated | FlagEncrypted | FlagAEAD | FlagTruncated | FlagCompressed
)

// CRC32 constants.
const (
	CRC32IEEEPolynomial          uint32 = 0x04C11DB7
	CRC32IEEEReflectedPolynomial uint32 = 0xEDB88320
)

// TLV type constants registered in the protocol registry.
const (
	TLVNone         uint16 = 0  // reserved
	TLVIdentity     uint16 = 1  // device identity (nested string fields)
	TLVReset        uint16 = 2  // boot/reset block
	TLVEvent        uint16 = 3  // event metadata
	TLVCpu          uint16 = 4  // multi-arch CPU context
	TLVFault        uint16 = 5  // fault registers
	TLVBreadcrumb   uint16 = 6  // repeatable breadcrumb
	TLVMetric       uint16 = 7  // repeatable metric
	TLVPower        uint16 = 8  // power samples
	TLVHealth       uint16 = 9  // watchdog/task health
	TLVAssert       uint16 = 10 // assertion
	TLVPeripheral   uint16 = 11 // peripheral/bus faults
	TLVLog          uint16 = 12 // structured log
	TLVMemory       uint16 = 13 // memory dump regions
	TLVStack        uint16 = 14 // stack snapshot
	TLVHeap         uint16 = 15 // heap stats
	TLVCPU64        uint16 = 16 // CPU64 capability descriptor
	TLVBlackbox     uint16 = 17 // blackbox event data
	TLVMission      uint16 = 18 // mission/profile context
	TLVTimeSync     uint16 = 19 // time synchronization
	TLVProvisioning uint16 = 20 // provisioning state
	TLVSupervisor   uint16 = 21 // supervisor/debug state
	TLVEnvironment  uint16 = 22 // environmental context
)

// Error kinds for validation failures.
type ErrorKind string

const (
	ErrorCorrupt     ErrorKind = "corrupt"
	ErrorUnsupported ErrorKind = "unsupported"
	ErrorTooLarge    ErrorKind = "too_large"
)

// ValidationError describes a validation failure.
type ValidationError struct {
	Kind   ErrorKind
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return e.Field + ": " + e.Reason
}

// Envelope represents a validated LEP v1 envelope header.
type Envelope struct {
	Version       uint8  `json:"version"`
	Type          uint8  `json:"type"`
	Architecture  uint8  `json:"architecture"`
	Flags         uint8  `json:"flags"`
	Sequence      uint32 `json:"sequence"`
	EventID       uint32 `json:"event_id"`
	PayloadLength uint32 `json:"payload_length"`
}

// TLV represents a Type-Length-Value field in a LEP payload.
type TLV struct {
	Type  uint16 `json:"type"`
	Value []byte `json:"-"`
}

// Validate parses and validates a LEP envelope from raw bytes.
func Validate(data []byte) (Envelope, error) {
	var env Envelope
	if len(data) > MaxEnvelopeSize {
		return env, &ValidationError{Kind: ErrorTooLarge, Field: "envelope", Reason: fmt.Sprintf("exceeds %d bytes", MaxEnvelopeSize)}
	}
	if len(data) < HeaderSize+4 {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "envelope", Reason: "too short"}
	}
	if string(data[:4]) != Magic {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "magic", Reason: "expected LSTP"}
	}
	env = Envelope{
		Version: data[4], Type: data[5], Architecture: data[6], Flags: data[7],
		Sequence: binary.LittleEndian.Uint32(data[8:12]), EventID: binary.LittleEndian.Uint32(data[12:16]),
		PayloadLength: binary.LittleEndian.Uint32(data[16:20]),
	}
	if env.Version != Version1 {
		return env, &ValidationError{Kind: ErrorUnsupported, Field: "version", Reason: fmt.Sprintf("unsupported LEP version %d", env.Version)}
	}
	if env.Flags&^uint8(KnownFlags) != 0 {
		return env, &ValidationError{Kind: ErrorUnsupported, Field: "flags", Reason: fmt.Sprintf("unknown flags 0x%02x", env.Flags&^uint8(KnownFlags))}
	}
	if (env.Flags&FlagEncrypted != 0) != (env.Flags&FlagAEAD != 0) {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "flags", Reason: "encrypted and AEAD flags must be used together"}
	}
	if env.Flags&FlagAEAD != 0 && env.Flags&FlagAuthenticated == 0 {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "flags", Reason: "AEAD requires authenticated flag"}
	}

	metaLen, authLen := 0, 0
	if env.Flags&FlagAEAD != 0 {
		metaLen, authLen = 28, 16
	} else if env.Flags&FlagAuthenticated != 0 {
		authLen = 32
	}
	overhead := HeaderSize + metaLen + 4 + authLen
	if len(data) < overhead || uint64(env.PayloadLength) != uint64(len(data)-overhead) {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "payload_length", Reason: "does not match envelope size"}
	}
	if binary.LittleEndian.Uint32(data[20:24]) != crc32.ChecksumIEEE(data[:20]) {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "header_crc", Reason: "CRC-32/IEEE mismatch"}
	}
	crcOff := HeaderSize + metaLen + int(env.PayloadLength)
	if crcOff+4 > len(data) {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "payload_crc", Reason: "missing checksum"}
	}
	if binary.LittleEndian.Uint32(data[crcOff:crcOff+4]) != crc32.ChecksumIEEE(data[HeaderSize:crcOff]) {
		return env, &ValidationError{Kind: ErrorCorrupt, Field: "payload_crc", Reason: "CRC-32/IEEE mismatch"}
	}
	// Plaintext TLVs only when not encrypted and not compressed.
	if env.Flags&FlagEncrypted == 0 && env.Flags&FlagCompressed == 0 {
		if err := validateTLVs(data[HeaderSize:crcOff]); err != nil {
			return env, err
		}
	}
	return env, nil
}

func validateTLVs(payload []byte) error {
	for off := 0; off < len(payload); {
		if len(payload)-off < 4 {
			return &ValidationError{Kind: ErrorCorrupt, Field: "payload", Reason: "incomplete TLV header"}
		}
		t := binary.LittleEndian.Uint16(payload[off : off+2])
		n := int(binary.LittleEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if t == 0 {
			return &ValidationError{Kind: ErrorCorrupt, Field: "payload", Reason: "TLV type zero is reserved"}
		}
		if n > len(payload)-off {
			return &ValidationError{Kind: ErrorCorrupt, Field: "payload", Reason: "TLV length exceeds payload"}
		}
		off += n
	}
	return nil
}

// Encode builds a plain (unauthenticated, unencrypted, uncompressed) LEP v1
// envelope from header fields and TLV payload bytes.
func Encode(h Envelope, payload []byte) ([]byte, error) {
	if h.Version == 0 {
		h.Version = Version1
	}
	if h.Version != Version1 {
		return nil, &ValidationError{Kind: ErrorUnsupported, Field: "version", Reason: "not 1"}
	}
	if len(payload) > MaxEnvelopeSize-HeaderSize-4 {
		return nil, &ValidationError{Kind: ErrorTooLarge, Field: "payload", Reason: "exceeds maximum envelope size"}
	}
	if h.Flags&^FlagTruncated != 0 {
		return nil, &ValidationError{Kind: ErrorUnsupported, Field: "flags", Reason: "plain encode only allows TRUNCATED"}
	}
	if err := validateTLVs(payload); err != nil && len(payload) > 0 {
		return nil, err
	}
	raw := make([]byte, HeaderSize+len(payload)+4)
	copy(raw[0:4], Magic)
	raw[4] = h.Version
	raw[5] = h.Type
	raw[6] = h.Architecture
	raw[7] = h.Flags & FlagTruncated
	binary.LittleEndian.PutUint32(raw[8:12], h.Sequence)
	binary.LittleEndian.PutUint32(raw[12:16], h.EventID)
	binary.LittleEndian.PutUint32(raw[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[20:24], crc32.ChecksumIEEE(raw[:20]))
	copy(raw[HeaderSize:], payload)
	binary.LittleEndian.PutUint32(raw[HeaderSize+len(payload):], crc32.ChecksumIEEE(payload))
	return raw, nil
}

// EncodeTLVs serializes TLV fields then encodes a plain envelope.
func EncodeTLVs(h Envelope, fields []TLV) ([]byte, error) {
	payload, err := MarshalTLVs(fields)
	if err != nil {
		return nil, err
	}
	return Encode(h, payload)
}

// MarshalTLVs serializes TLV fields to payload bytes.
func MarshalTLVs(fields []TLV) ([]byte, error) {
	var payload []byte
	for _, f := range fields {
		if f.Type == 0 {
			return nil, fmt.Errorf("TLV type zero is reserved")
		}
		if len(f.Value) > 0xffff {
			return nil, fmt.Errorf("TLV %d value exceeds uint16 length", f.Type)
		}
		entry := make([]byte, 4+len(f.Value))
		binary.LittleEndian.PutUint16(entry[0:2], f.Type)
		binary.LittleEndian.PutUint16(entry[2:4], uint16(len(f.Value)))
		copy(entry[4:], f.Value)
		payload = append(payload, entry...)
	}
	return payload, nil
}

// TLVs returns the unencrypted, uncompressed payload fields after validation.
func TLVs(data []byte) ([]TLV, error) {
	env, err := Validate(data)
	if err != nil {
		return nil, err
	}
	if env.Flags&FlagEncrypted != 0 {
		return nil, fmt.Errorf("encrypted LEP payload cannot be decoded without a key")
	}
	if env.Flags&FlagAuthenticated != 0 {
		return nil, fmt.Errorf("authenticated LEP payload cannot be decoded without a key")
	}
	if env.Flags&FlagCompressed != 0 {
		return nil, fmt.Errorf("compressed LEP payload cannot be decoded without a configured codec")
	}
	payload := data[HeaderSize : HeaderSize+int(env.PayloadLength)]
	return parseTLVs(payload)
}

func parseTLVs(payload []byte) ([]TLV, error) {
	fields := make([]TLV, 0)
	for off := 0; off < len(payload); {
		if len(payload)-off < 4 {
			return nil, &ValidationError{Kind: ErrorCorrupt, Field: "payload", Reason: "incomplete TLV"}
		}
		t := binary.LittleEndian.Uint16(payload[off : off+2])
		n := int(binary.LittleEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if n > len(payload)-off {
			return nil, &ValidationError{Kind: ErrorCorrupt, Field: "payload", Reason: "TLV length exceeds payload"}
		}
		fields = append(fields, TLV{Type: t, Value: append([]byte(nil), payload[off:off+n]...)})
		off += n
	}
	return fields, nil
}

// ParseTLVs parses TLV fields from a payload byte slice.
func ParseTLVs(payload []byte) ([]TLV, error) {
	return parseTLVs(payload)
}

// TLVSet is a helper for building TLV payloads with named accessors.
type TLVSet map[uint16][]byte

// Add inserts or replaces a TLV in the set.
func (s TLVSet) Add(t uint16, value []byte) {
	s[t] = append([]byte(nil), value...)
}

// Get retrieves a TLV value by type.
func (s TLVSet) Get(t uint16) []byte {
	return s[t]
}

// Marshal serializes the set into TLV payload bytes.
func (s TLVSet) Marshal() ([]byte, error) {
	return MarshalTLVs(ToSlice(s))
}

// ToSlice converts a TLVSet to a slice of TLVs.
func ToSlice(s TLVSet) []TLV {
	out := make([]TLV, 0, len(s))
	for t, v := range s {
		out = append(out, TLV{Type: t, Value: v})
	}
	return out
}
