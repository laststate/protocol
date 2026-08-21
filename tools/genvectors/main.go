// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

// Command genvectors reproduces the LEP golden test vectors from the reference
// codec using documented test-only keys and fixed nonces, so every vector is
// independently verifiable (the key and nonce are public constants below).
//
// Usage (from the protocol repo root):
//
//	go run ./tools/genvectors
//
// It rewrites files under test-vectors/ deterministically.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/laststate/protocol/implementations/go/lep"
)

// Test-only key material. Never use in production.
const (
	testKeyHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testKeyID   = uint32(1)
	testNonce = "000102030405060708090a0b0c0d0e0f1011121314151617"
	authKeyHex  = "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func hexLine(b []byte) string {
	return hex.EncodeToString(b) + "\n"
}

func writeHex(root, rel, content string) {
	path := filepath.Join(root, rel)
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, []byte(content), 0o644))
}

// plainBasic returns the plain "basic" envelope for a wire version.
func plainBasic(version uint8) []byte {
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xaa, 0xbb}
	raw, err := lep.Encode(lep.Envelope{
		Version: version, Type: 2, Architecture: 0, Flags: 0,
		Sequence: 7, EventID: 9,
	}, payload)
	must(err)
	return raw
}

// cryptoAEAD seals the plain basic envelope for a version with the test key
// and a fixed nonce, making the output reproducible.
func cryptoAEAD(plain []byte) []byte {
	key, err := hex.DecodeString(testKeyHex)
	must(err)
	nonce, err := hex.DecodeString(testNonce)
	must(err)
	ring := lep.NewMemoryKeyring([]lep.Key{{NumericID: testKeyID, Key: key}}, testKeyID, testKeyID)
	sealed, err := lep.SealWithNonce(plain, ring, true, nonce)
	must(err)
	return sealed
}

// cryptoHMAC authenticates the plain basic envelope for a version with the
// auth test key.
func cryptoHMAC(plain []byte) []byte {
	key, err := hex.DecodeString(authKeyHex)
	must(err)
	ring := lep.NewMemoryKeyring([]lep.Key{{NumericID: testKeyID, Key: key}}, testKeyID, testKeyID)
	sealed, err := lep.Seal(plain, ring, false)
	must(err)
	return sealed
}

// stream wraps an envelope in Latch Stream framing.
func stream(env []byte) []byte {
	return lep.EncodeLatchStream(env)
}

func main() {
	root, err := filepath.Abs(filepath.Join("..", "..", "test-vectors"))
	must(err)
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err != nil {
		panic("run from tools/genvectors: test-vectors/ not found at " + root)
	}

	plainV1 := plainBasic(1)
	plainV2 := plainBasic(2)

	writeHex(root, "valid/lep-v1-basic.hex", hexLine(plainV1))
	writeHex(root, "valid/lep-v2-basic.hex", hexLine(plainV2))
	writeHex(root, "crypto/aead-xchacha-v1.hex", hexLine(cryptoAEAD(plainV1)))
	writeHex(root, "crypto/aead-xchacha-v2.hex", hexLine(cryptoAEAD(plainV2)))
	writeHex(root, "crypto/hmac-auth-only-v1.hex", hexLine(cryptoHMAC(plainV1)))
	writeHex(root, "crypto/hmac-auth-only-v2.hex", hexLine(cryptoHMAC(plainV2)))
	writeHex(root, "transports/latch-stream-basic-v1.hex", hexLine(stream(plainV1)))
	writeHex(root, "transports/latch-stream-basic-v2.hex", hexLine(stream(plainV2)))
	writeHex(root, "transports/lsak-ack-stored.hex", hexLine(lep.EncodeLSAK(9, lep.LSAckStored)))

	fmt.Println("wrote vectors under", root)
}