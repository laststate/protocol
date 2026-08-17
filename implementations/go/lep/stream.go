// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package lep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Stream framing constants.
const (
	LSHeaderSize     = 8
	LSTailSize       = 4
	LSAckMagic       = "LSAK"
	LSAckVersion     = 1
	LSAckSize        = 12
	LSAckStored      uint8 = iota + 1
	LSAckDuplicate
	LSAckNackCorrupt
	LSAckNackUnsupported
	LSAckNackBusy
	LSAckNackTooLarge
	LSAckNackUnauthorized
	LSAckNackInternal
)

// LSAK status codes (1-indexed).
const (
	LSAckStatusStored      = LSAckStored
	LSAckStatusDuplicate   = LSAckDuplicate
	LSAckStatusNackCorrupt = LSAckNackCorrupt
	LSAckStatusNackUnsupported = LSAckNackUnsupported
	LSAckStatusNackBusy    = LSAckNackBusy
	LSAckStatusNackTooLarge = LSAckNackTooLarge
	LSAckStatusNackUnauthorized = LSAckNackUnauthorized
	LSAckStatusNackInternal = LSAckNackInternal
)

// EncodeLatchStream wraps a LEP envelope in Latch Stream framing.
// Frame format: 'LS' | version(1) | reserved(1) | length(u32 LE) | envelope | crc32(u32 LE)
func EncodeLatchStream(envelope []byte) []byte {
	out := make([]byte, LSHeaderSize+len(envelope)+LSTailSize)
	out[0], out[1] = 'L', 'S'
	out[2] = 1
	out[3] = 0
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(envelope)))
	copy(out[8:], envelope)
	binary.LittleEndian.PutUint32(out[8+len(envelope):], crc32.ChecksumIEEE(envelope))
	return out
}

// ParseLatchStream extracts a LEP envelope from Latch Stream framing.
// Returns the envelope bytes and the offset past the trailing CRC.
// Returns (nil, 0, err) on parse failure.
func ParseLatchStream(data []byte) ([]byte, int, error) {
	if len(data) < LSHeaderSize+LSTailSize {
		return nil, 0, fmt.Errorf("stream frame too short: %d bytes", len(data))
	}
	if data[0] != 'L' || data[1] != 'S' {
		return nil, 0, fmt.Errorf("bad stream magic: %02x%02x", data[0], data[1])
	}
	if data[2] != 1 {
		return nil, 0, fmt.Errorf("unsupported stream version: %d", data[2])
	}
	length := binary.LittleEndian.Uint32(data[4:8])
	if uint64(length) > uint64(len(data)-LSHeaderSize-LSTailSize) {
		return nil, 0, fmt.Errorf("stream length %d exceeds remaining bytes", length)
	}
	envelope := data[LSHeaderSize : LSHeaderSize+int(length)]
	crcOff := LSHeaderSize + int(length)
	if binary.LittleEndian.Uint32(data[crcOff:crcOff+LSTailSize]) != crc32.ChecksumIEEE(envelope) {
		return nil, 0, fmt.Errorf("stream frame CRC mismatch")
	}
	return envelope, crcOff + LSTailSize, nil
}

// ParseLSAK parses a 12-byte LSAK control message.
func ParseLSAK(data []byte) (eventID uint32, status uint8, err error) {
	if len(data) < LSAckSize {
		return 0, 0, fmt.Errorf("lsak too short: %d bytes", len(data))
	}
	if string(data[0:4]) != LSAckMagic || data[4] != LSAckVersion {
		return 0, 0, fmt.Errorf("lsak bad magic/version")
	}
	return binary.LittleEndian.Uint32(data[8:12]), data[5], nil
}

// EncodeLSAK builds a 12-byte LSAK control message.
func EncodeLSAK(eventID uint32, status uint8) []byte {
	out := make([]byte, LSAckSize)
	copy(out[0:4], []byte(LSAckMagic))
	out[4] = LSAckVersion
	out[5] = status
	binary.LittleEndian.PutUint32(out[8:12], eventID)
	return out
}

// LatchStream is a reader that extracts LEP envelopes from a Latch Stream framing
// byte stream, with COBS-style resync on corrupt frames and fragment reassembly
// for envelopes split across multiple stream frames.
type LatchStream struct {
	r        io.Reader
	// buf accumulates bytes between stream frame boundaries.
	buf []byte
	// maxEnvelope is the maximum allowed envelope size (default MaxEnvelopeSize).
	maxEnvelope int
	// onFrame is called for each successfully extracted envelope.
	onFrame func(env []byte) error
	// maxFragmentedSize limits reassembled fragments.
	maxFragmentedSize int
}

// NewLatchStream creates a stream reader that extracts LEP envelopes from a
// byte stream with COBS-style resync and fragment reassembly.
func NewLatchStream(r io.Reader, maxEnvelope int) *LatchStream {
	if maxEnvelope <= 0 {
		maxEnvelope = MaxEnvelopeSize
	}
	return &LatchStream{
		r:                r,
		maxEnvelope:      maxEnvelope,
		maxFragmentedSize: maxEnvelope,
	}
}

// SetOnFrame sets the callback for successfully extracted envelopes.
func (ls *LatchStream) SetOnFrame(fn func(env []byte) error) {
	ls.onFrame = fn
}

// Read processes available bytes from the stream, extracting complete envelopes.
// Returns the number of bytes consumed or an error.
func (ls *LatchStream) Read(buf []byte) (int, error) {
	if buf == nil {
		return 0, errors.New("nil buffer")
	}
	// Append incoming bytes to our buffer.
	ls.buf = append(ls.buf, buf...)
	var consumed int
	for len(ls.buf) >= LSHeaderSize+LSTailSize {
		// Try to find a valid stream frame.
		env, consumedAt, err := parseStreamFrameAt(ls.buf)
		if err != nil {
			// COBS-style resync: skip one byte and try again.
			ls.buf = ls.buf[1:]
			consumed++
			continue
		}
		if len(env) > ls.maxEnvelope {
			return consumed, fmt.Errorf("envelope too large: %d bytes", len(env))
		}
		if ls.onFrame != nil {
			if err := ls.onFrame(env); err != nil {
				return consumed, err
			}
		}
		ls.buf = ls.buf[consumedAt:]
		consumed += consumedAt
	}
	return consumed, nil
}

// ReadAll reads all available stream frames from the reader until EOF.
// Each complete envelope is passed to onFrame.
func (ls *LatchStream) ReadAll() error {
	buf := make([]byte, 64*1024)
	for {
		n, err := ls.r.Read(buf)
		if n > 0 {
			if _, rerr := ls.Read(buf[:n]); rerr != nil {
				return rerr
			}
		}
		if err == io.EOF {
			// Process any remaining bytes.
			if len(ls.buf) > 0 {
				if _, rerr := ls.Read(ls.buf); rerr != nil {
					return rerr
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// parseStreamFrameAt tries to parse a stream frame starting at the beginning
// of data. Returns (envelope, bytesConsumed, error).
func parseStreamFrameAt(data []byte) ([]byte, int, error) {
	if len(data) < LSHeaderSize+LSTailSize {
		return nil, 0, fmt.Errorf("too short")
	}
	if data[0] != 'L' || data[1] != 'S' {
		return nil, 0, fmt.Errorf("bad magic")
	}
	if data[2] != 1 {
		return nil, 0, fmt.Errorf("bad version")
	}
	length := binary.LittleEndian.Uint32(data[4:8])
	totalLen := LSHeaderSize + int(length) + LSTailSize
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("incomplete frame")
	}
	envelope := data[LSHeaderSize : LSHeaderSize+int(length)]
	crcOff := LSHeaderSize + int(length)
	if binary.LittleEndian.Uint32(data[crcOff:crcOff+LSTailSize]) != crc32.ChecksumIEEE(envelope) {
		return nil, 0, fmt.Errorf("CRC mismatch")
	}
	return envelope, totalLen, nil
}
