// SPDX-License-Identifier: Apache-2.0
package lep_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
		{Type: lep.TLVSource, Value: []byte("device-001")},
		{Type: lep.TLVHeartbeat, Value: []byte{0x01}},
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
