// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package lep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/klauspost/compress/zstd"
)

// CompressPayload replaces a plain envelope's payload with zstd-compressed
// bytes and sets FlagCompressed. The envelope must be plain (no auth/crypto).
func CompressPayload(plain []byte) ([]byte, error) {
	env, err := Validate(plain)
	if err != nil {
		return nil, err
	}
	if env.Flags != 0 {
		return nil, fmt.Errorf("compress requires a plain envelope")
	}
	payload := plain[HeaderSize : HeaderSize+int(env.PayloadLength)]
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	compressed := encoder.EncodeAll(payload, nil)
	out := make([]byte, HeaderSize+len(compressed)+4)
	copy(out[:20], plain[:20])
	out[7] = FlagCompressed
	// Keep other flags but clear encrypted/authenticated.
	out[7] |= env.Flags & ^FlagCompressed
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(compressed)))
	binary.LittleEndian.PutUint32(out[20:24], crc32.ChecksumIEEE(out[:20]))
	copy(out[HeaderSize:], compressed)
	binary.LittleEndian.PutUint32(out[HeaderSize+len(compressed):], crc32.ChecksumIEEE(compressed))
	return out, nil
}

// DecompressPayload expands a FlagCompressed plain (or post-Open) envelope.
func DecompressPayload(raw []byte) ([]byte, error) {
	env, err := Validate(raw)
	if err != nil {
		return nil, err
	}
	if env.Flags&FlagCompressed == 0 {
		return append([]byte(nil), raw...), nil
	}
	if env.Flags&(FlagAuthenticated|FlagEncrypted|FlagAEAD) != 0 {
		return nil, fmt.Errorf("decompress requires Open first")
	}
	payload := raw[HeaderSize : HeaderSize+int(env.PayloadLength)]
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	plain, err := decoder.DecodeAll(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %w", err)
	}
	out := make([]byte, HeaderSize+len(plain)+4)
	copy(out[:20], raw[:20])
	out[7] = raw[7] & ^FlagCompressed
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(plain)))
	binary.LittleEndian.PutUint32(out[20:24], crc32.ChecksumIEEE(out[:20]))
	copy(out[HeaderSize:], plain)
	binary.LittleEndian.PutUint32(out[HeaderSize+len(plain):], crc32.ChecksumIEEE(plain))
	if _, err := Validate(out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeTLVs validates, optionally opens, optionally decompresses, then returns TLVs.
func DecodeTLVs(raw []byte, ring Keyring) ([]TLV, error) {
	opened := raw
	var err error
	env, err := Validate(raw)
	if err != nil {
		return nil, err
	}
	if env.Flags&FlagAuthenticated != 0 {
		if ring == nil {
			return nil, errors.New("encrypted or authenticated LEP payload cannot be decoded without a key")
		}
		opened, err = Open(raw, ring)
		if err != nil {
			return nil, err
		}
	}
	env, err = Validate(opened)
	if err != nil {
		return nil, err
	}
	if env.Flags&FlagCompressed != 0 {
		opened, err = DecompressPayload(opened)
		if err != nil {
			return nil, err
		}
	}
	return TLVs(opened)
}
