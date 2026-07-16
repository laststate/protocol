// SPDX-License-Identifier: Apache-2.0
package lep

import (
	"encoding/binary"
	"hash/crc32"
)

// EncodeLatchStream wraps a LEP envelope in Latch Stream framing.
func EncodeLatchStream(envelope []byte) []byte {
	out := make([]byte, 8+len(envelope)+4)
	out[0], out[1] = 'L', 'S'
	out[2] = 1
	out[3] = 0
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(envelope)))
	copy(out[8:], envelope)
	binary.LittleEndian.PutUint32(out[8+len(envelope):], crc32.ChecksumIEEE(envelope))
	return out
}

const (
	AckStored uint8 = iota + 1
	AckDuplicate
	NackCorrupt
	NackUnsupported
	NackBusy
	NackTooLarge
	NackUnauthorized
	NackInternal
)

// EncodeLSAK builds a 12-byte LSAK control message.
func EncodeLSAK(eventID uint32, status uint8) []byte {
	out := []byte{'L', 'S', 'A', 'K', 1, status, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[8:], eventID)
	return out
}

// ParseLSAK parses a 12-byte LSAK frame.
func ParseLSAK(data []byte) (eventID uint32, status uint8, err error) {
	if len(data) < 12 {
		return 0, 0, fmtShort("lsak too short")
	}
	if string(data[0:4]) != "LSAK" || data[4] != 1 {
		return 0, 0, fmtShort("lsak bad magic/version")
	}
	return binary.LittleEndian.Uint32(data[8:12]), data[5], nil
}

type shortErr string

func (e shortErr) Error() string { return string(e) }
func fmtShort(s string) error    { return shortErr(s) }
