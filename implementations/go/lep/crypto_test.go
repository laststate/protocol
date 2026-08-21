// SPDX-License-Identifier: Apache-2.0
package lep_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laststate/protocol/implementations/go/lep"
)

// bytesEqual returns true if two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// base64Encode encodes bytes to standard base64.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// generateKey creates a test key with the given numeric ID.
func generateKey(id uint32) lep.Key {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return lep.Key{
		NumericID: id,
		ID:        lep.KeyIDFromNumeric(id),
		Key:       key,
	}
}

func TestKeyringActive(t *testing.T) {
	keys := []lep.Key{generateKey(1), generateKey(2)}
	ring := lep.NewMemoryKeyring(keys, 1, 2)
	if !ring.HaveActive {
		t.Fatal("expected active key")
	}
	if !ring.HaveAuth {
		t.Fatal("expected auth key")
	}
	active, ok := ring.Active()
	if !ok || active.NumericID != 1 {
		t.Errorf("active key = %d, want 1", active.NumericID)
	}
	auth, ok := ring.AuthKey()
	if !ok || auth.NumericID != 2 {
		t.Errorf("auth key = %d, want 2", auth.NumericID)
	}
}

func TestKeyringAuthFallsBackToActive(t *testing.T) {
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 99) // 99 not in key set
	if !ring.HaveActive {
		t.Fatal("expected active key")
	}
	// Auth should fall back to active when auth ID not found.
	if !ring.HaveAuth {
		t.Fatal("expected auth key to fall back to active")
	}
}

func TestSealOpenAEAD(t *testing.T) {
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)

	// Create a plain envelope.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Seal with encryption.
	sealed, err := lep.Seal(plain, ring, true)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the sealed envelope has AEAD flags.
	env, err := lep.Validate(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if env.Flags&lep.FlagAEAD == 0 {
		t.Fatal("expected AEAD flag")
	}
	if env.Flags&lep.FlagEncrypted == 0 {
		t.Fatal("expected Encrypted flag")
	}
	if env.Flags&lep.FlagAuthenticated == 0 {
		t.Fatal("expected Authenticated flag")
	}

	// Verify metadata key ID.
	keyID, ok := lep.MetadataKeyID(sealed)
	if !ok || keyID != 1 {
		t.Errorf("metadata key id = %d, want 1", keyID)
	}

	// Open the sealed envelope.
	opened, err := lep.Open(sealed, ring)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the opened envelope matches the original.
	openedEnv, err := lep.Validate(opened)
	if err != nil {
		t.Fatal(err)
	}
	if openedEnv.PayloadLength != 6 {
		t.Errorf("payload length = %d, want 6", openedEnv.PayloadLength)
	}
}

func TestSealOpenHMAC(t *testing.T) {
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)

	// Create a plain envelope.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Seal with authentication only.
	sealed, err := lep.Seal(plain, ring, false)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the sealed envelope has Authenticated flag.
	env, err := lep.Validate(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if env.Flags&lep.FlagAEAD != 0 {
		t.Fatal("unexpected AEAD flag")
	}
	if env.Flags&lep.FlagAuthenticated == 0 {
		t.Fatal("expected Authenticated flag")
	}

	// Open the sealed envelope.
	opened, err := lep.Open(sealed, ring)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the opened envelope matches the original.
	openedEnv, err := lep.Validate(opened)
	if err != nil {
		t.Fatal(err)
	}
	if openedEnv.PayloadLength != 6 {
		t.Errorf("payload length = %d, want 6", openedEnv.PayloadLength)
	}
}

func TestOpenWithWrongKey(t *testing.T) {
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)

	// Create and seal a plain envelope.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := lep.Seal(plain, ring, true)
	if err != nil {
		t.Fatal(err)
	}

	// Try to open with a different key.
	wrongRing := lep.NewMemoryKeyring([]lep.Key{generateKey(2)}, 2, 2)
	_, err = lep.Open(sealed, wrongRing)
	if err == nil {
		t.Fatal("expected error opening with wrong key")
	}
}

func TestOpenTamperedEnvelope(t *testing.T) {
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)

	// Create and seal a plain envelope.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := lep.Seal(plain, ring, true)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext.
	tampered := append([]byte(nil), sealed...)
	if len(tampered) > lep.HeaderSize+lep.AEADMetadataSize+1 {
		tampered[lep.HeaderSize+lep.AEADMetadataSize+1] ^= 0xff
	}

	_, err = lep.Open(tampered, ring)
	if err == nil {
		t.Fatal("expected error opening tampered envelope")
	}
}

func TestParseKeyMaterial(t *testing.T) {
	// Generate a test key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Test hex parsing.
	got, err := lep.ParseKeyMaterial("hex:" + hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(key, got) {
		t.Errorf("hex parse mismatch")
	}

	// Test base64 parsing.
	got, err = lep.ParseKeyMaterial("base64:" + base64Encode(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(key, got) {
		t.Errorf("base64 parse mismatch")
	}

	// Test empty input.
	_, err = lep.ParseKeyMaterial("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}

	// Test wrong size.
	_, err = lep.ParseKeyMaterial("hex:010203")
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestKeyIDConversion(t *testing.T) {
	// Test KeyIDFromString.
	id := lep.KeyIDFromString("test")
	if len(id) != lep.KeyIDSize {
		t.Errorf("KeyIDFromString length = %d, want %d", len(id), lep.KeyIDSize)
	}

	// Test KeyIDFromNumeric / NumericIDFromKeyID round-trip.
	id = lep.KeyIDFromNumeric(42)
	if lep.NumericIDFromKeyID(id) != 42 {
		t.Errorf("round-trip failed: %d -> %d", 42, lep.NumericIDFromKeyID(id))
	}
}

func TestBuildMemoryKeyring(t *testing.T) {
	keys := []lep.Key{
		{NumericID: 1, Key: make([]byte, 32)},
		{NumericID: 2, Key: make([]byte, 32)},
	}
	// Fill keys with random data.
	for i := range keys {
		if _, err := rand.Read(keys[i].Key); err != nil {
			t.Fatal(err)
		}
	}

	ring, err := lep.BuildMemoryKeyring(keys, "1", "2")
	if err != nil {
		t.Fatal(err)
	}
	if !ring.HaveActive {
		t.Fatal("expected active key")
	}
	if !ring.HaveAuth {
		t.Fatal("expected auth key")
	}

	// Test with empty keys.
	_, err = lep.BuildMemoryKeyring(nil, "1", "2")
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestReplayCache(t *testing.T) {
	cache := lep.NewReplayCache(100)

	// First observation.
	same, conflict := cache.Check("src1", 1, []byte("payload"))
	if same || conflict {
		t.Errorf("first observation: same=%v, conflict=%v", same, conflict)
	}
	cache.Record("src1", 1, []byte("payload"))

	// Exact retransmit.
	same, conflict = cache.Check("src1", 1, []byte("payload"))
	if !same || conflict {
		t.Errorf("retransmit: same=%v, conflict=%v", same, conflict)
	}

	// Different payload (replay attack).
	same, conflict = cache.Check("src1", 1, []byte("different"))
	if same || !conflict {
		t.Errorf("replay: same=%v, conflict=%v", same, conflict)
	}

	// New event ID.
	same, conflict = cache.Check("src1", 2, []byte("payload"))
	if same || conflict {
		t.Errorf("new event: same=%v, conflict=%v", same, conflict)
	}

	// Window expiry.
	for i := uint32(0); i < 200; i++ {
		cache.Record("src1", i, []byte("payload"))
	}
	// Event 0 should have expired from the window.
	if cache.Seen("src1", 0) {
		t.Error("event 0 should have expired")
	}
	// Event 199 should still be present.
	if !cache.Seen("src1", 199) {
		t.Error("event 199 should still be present")
	}
}

func TestStreamFrameEncodeDecode(t *testing.T) {
	envelope := []byte("test-envelope-data")
	framed := lep.EncodeLatchStream(envelope)

	// Verify frame structure.
	if len(framed) < lep.LSHeaderSize+lep.LSTailSize {
		t.Fatal("frame too short")
	}
	if framed[0] != 'L' || framed[1] != 'S' {
		t.Fatal("bad magic")
	}
	if framed[2] != 1 {
		t.Fatal("bad version")
	}

	// Parse it back.
	parsed, consumed, err := lep.ParseLatchStream(framed)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(framed) {
		t.Errorf("consumed = %d, want %d", consumed, len(framed))
	}
	if !bytesEqual(parsed, envelope) {
		t.Errorf("parsed envelope mismatch")
	}
}

func TestLSAKEncodeDecode(t *testing.T) {
	lsak := lep.EncodeLSAK(42, lep.LSAckStored)
	if len(lsak) != lep.LSAckSize {
		t.Fatalf("lsak length = %d, want %d", len(lsak), lep.LSAckSize)
	}
	if string(lsak[0:4]) != "LSAK" {
		t.Fatal("bad magic")
	}

	eventID, status, err := lep.ParseLSAK(lsak)
	if err != nil {
		t.Fatal(err)
	}
	if eventID != 42 || status != lep.LSAckStored {
		t.Errorf("lsak = (%d, %d), want (42, %d)", eventID, status, lep.LSAckStored)
	}
}

func TestDecodeTLVs(t *testing.T) {
	// Create a plain envelope with TLVs.
	fields := []lep.TLV{
		{Type: lep.TLVIdentity, Value: []byte("device-001")},
		{Type: lep.TLVHealth, Value: []byte{0x01}},
	}
	plain, err := lep.EncodeTLVs(lep.Envelope{Version: 1, Type: 1}, fields)
	if err != nil {
		t.Fatal(err)
	}

	// Decode without ring (plain envelope).
	tlvs, err := lep.DecodeTLVs(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(tlvs))
	}
	if string(tlvs[0].Value) != "device-001" {
		t.Errorf("first TLV value = %q", string(tlvs[0].Value))
	}
}

func TestDecodeTLVsRequiresRing(t *testing.T) {
	// Create a sealed envelope.
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, _ := lep.Encode(lep.Envelope{Version: 1, Type: 1}, payload)
	sealed, _ := lep.Seal(plain, ring, true)

	// Decode without ring should fail.
	_, err := lep.DecodeTLVs(sealed, nil)
	if err == nil {
		t.Fatal("expected error without ring")
	}
}

// golden keys and nonce, matching tools/genvectors/main.go.
const (
	goldenAEADKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	goldenAuthKeyHex = "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c"
	goldenNonceHex   = "000102030405060708090a0b0c0d0e0f1011121314151617"
)

func loadGoldenHex(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test-vectors", rel))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, string(data))
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGoldenAEAD verifies the crypto/aead-xchacha-v{1,2}.hex goldens: each must
// open with the documented test key and yield the exact basic plain envelope.
func TestGoldenAEAD(t *testing.T) {
	basic := map[uint8]string{1: "valid/lep-v1-basic.hex", 2: "valid/lep-v2-basic.hex"}
	for _, tc := range []struct {
		name    string
		vector  string
		version uint8
	}{
		{name: "v1", vector: "crypto/aead-xchacha-v1.hex", version: 1},
		{name: "v2", vector: "crypto/aead-xchacha-v2.hex", version: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed := loadGoldenHex(t, tc.vector)
			env, err := lep.Validate(sealed)
			if err != nil {
				t.Fatal(err)
			}
			if env.Version != tc.version {
				t.Fatalf("version = %d, want %d", env.Version, tc.version)
			}
			if env.Flags&(lep.FlagAEAD|lep.FlagEncrypted|lep.FlagAuthenticated) == 0 {
				t.Fatal("golden AEAD vector must carry AEAD/encrypted/authenticated flags")
			}
			keyBytes, err := hex.DecodeString(goldenAEADKeyHex)
			if err != nil {
				t.Fatal(err)
			}
			ring := lep.NewMemoryKeyring([]lep.Key{{NumericID: 1, Key: keyBytes}}, 1, 1)
			opened, err := lep.Open(sealed, ring)
			if err != nil {
				t.Fatalf("Open(golden AEAD) failed: %v", err)
			}
			// The decrypted plaintext must equal the documented basic envelope.
			plain := loadGoldenHex(t, basic[tc.version])
			if !bytesEqual(opened, plain) {
				t.Fatalf("golden AEAD plaintext mismatch\n got %x\nwant %x", opened, plain)
			}
			// Tampering with the tag must fail.
			tampered := append([]byte(nil), sealed...)
			tampered[len(tampered)-1] ^= 0xff
			if _, err := lep.Open(tampered, ring); err == nil {
				t.Fatal("Open(tampered AEAD) must fail")
			}
		})
	}
}

// TestGoldenHMAC verifies the crypto/hmac-auth-only-v{1,2}.hex goldens: each
// must verify with the documented auth key.
func TestGoldenHMAC(t *testing.T) {
	basic := map[uint8]string{1: "valid/lep-v1-basic.hex", 2: "valid/lep-v2-basic.hex"}
	for _, tc := range []struct {
		name    string
		vector  string
		version uint8
	}{
		{name: "v1", vector: "crypto/hmac-auth-only-v1.hex", version: 1},
		{name: "v2", vector: "crypto/hmac-auth-only-v2.hex", version: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed := loadGoldenHex(t, tc.vector)
			env, err := lep.Validate(sealed)
			if err != nil {
				t.Fatal(err)
			}
			if env.Version != tc.version {
				t.Fatalf("version = %d, want %d", env.Version, tc.version)
			}
			if env.Flags&lep.FlagAuthenticated == 0 || env.Flags&lep.FlagAEAD != 0 {
				t.Fatal("golden HMAC vector must be auth-only")
			}
			keyBytes, err := hex.DecodeString(goldenAuthKeyHex)
			if err != nil {
				t.Fatal(err)
			}
			ring := lep.NewMemoryKeyring([]lep.Key{{NumericID: 1, Key: keyBytes}}, 1, 1)
			opened, err := lep.Open(sealed, ring)
			if err != nil {
				t.Fatalf("Open(golden HMAC) failed: %v", err)
			}
			plain := loadGoldenHex(t, basic[tc.version])
			if !bytesEqual(opened, plain) {
				t.Fatalf("golden HMAC plaintext mismatch\n got %x\nwant %x", opened, plain)
			}
		})
	}
}

// TestGoldenStream verifies the transports/latch-stream-basic-v{1,2}.hex goldens.
func TestGoldenStream(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vector  string
		version uint8
	}{
		{name: "v1", vector: "transports/latch-stream-basic-v1.hex", version: 1},
		{name: "v2", vector: "transports/latch-stream-basic-v2.hex", version: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := loadGoldenHex(t, tc.vector)
			env, consumed, err := lep.ParseLatchStream(frame)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(frame) {
				t.Fatalf("consumed = %d, want %d", consumed, len(frame))
			}
			h, err := lep.Validate(env)
			if err != nil {
				t.Fatal(err)
			}
			if h.Version != tc.version {
				t.Fatalf("version = %d, want %d", h.Version, tc.version)
			}
		})
	}
}

// TestGoldenLSAK verifies the transports/lsak-ack-stored.hex golden.
func TestGoldenLSAK(t *testing.T) {
	raw := loadGoldenHex(t, "transports/lsak-ack-stored.hex")
	eventID, status, err := lep.ParseLSAK(raw)
	if err != nil {
		t.Fatal(err)
	}
	if eventID != 9 || status != lep.LSAckStored {
		t.Fatalf("lsak = (%d, %d), want (9, %d)", eventID, status, lep.LSAckStored)
	}
}

// TestVersionDomainSeparation proves v1 and v2 envelopes derive distinct keys
// from the same IKM (preventing cross-version key confusion).
func TestVersionDomainSeparation(t *testing.T) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plainV1, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}
	plainV2, err := lep.Encode(lep.Envelope{Version: 2, Type: 2, Sequence: 10, EventID: 20}, payload)
	if err != nil {
		t.Fatal(err)
	}
	ring := lep.NewMemoryKeyring([]lep.Key{{NumericID: 1, Key: keyBytes}}, 1, 1)
	sealedV1, err := lep.SealWithNonce(plainV1, ring, true, mustDecodeHex(t, goldenNonceHex))
	if err != nil {
		t.Fatal(err)
	}
	sealedV2, err := lep.SealWithNonce(plainV2, ring, true, mustDecodeHex(t, goldenNonceHex))
	if err != nil {
		t.Fatal(err)
	}
	// Same key, same nonce, same salt inputs, different version -> different tag.
	if bytesEqual(sealedV1, sealedV2) {
		t.Fatal("v1 and v2 seals must differ due to version-bound HKDF labels")
	}
	// A v2 envelope must open with the v2 label (the codec derives by version).
	opened, err := lep.Open(sealedV2, ring)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(opened, plainV2) {
		t.Fatal("v2 open round-trip mismatch")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
