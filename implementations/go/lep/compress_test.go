// SPDX-License-Identifier: Apache-2.0
package lep_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/laststate/protocol/implementations/go/lep"
)

// bigTLVs builds a TLV payload large enough to benefit from compression.
func bigTLVs(t *testing.T) []byte {
	t.Helper()
	payload := bytes.Repeat([]byte("repetitive-payload-content-"), 64)
	tlv := []byte{0x01, 0x00}
	tlv = append(tlv, byte(len(payload)), byte(len(payload)>>8))
	tlv = append(tlv, payload...)
	return tlv
}

func TestCompressPayloadRoundTrip(t *testing.T) {
	payload := bigTLVs(t)
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := lep.CompressPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	env, err := lep.Validate(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if env.Flags&lep.FlagCompressed == 0 {
		t.Fatal("expected FlagCompressed")
	}
	if int(env.PayloadLength) >= len(payload) {
		t.Fatalf("compressed not smaller: %d vs %d", env.PayloadLength, len(payload))
	}
	restored, err := lep.DecompressPayload(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, plain) {
		t.Fatal("round-trip mismatch")
	}
	// Round trip through DecodeTLVs must yield the original TLVs.
	tlvs, err := lep.DecodeTLVs(compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 1 || tlvs[0].Type != 1 {
		t.Fatalf("unexpected TLVs: %+v", tlvs)
	}
}

func TestCompressPayloadRejectsAuthenticated(t *testing.T) {
	payload := bigTLVs(t)
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Seal it so flags != 0.
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)
	sealed, err := lep.Seal(plain, ring, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lep.CompressPayload(sealed); err == nil {
		t.Fatal("CompressPayload must reject non-plain envelopes")
	}
	// Decompress on a non-compressed envelope returns a copy.
	copied, err := lep.DecompressPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, plain) {
		t.Fatal("DecompressPayload non-compressed copy mismatch")
	}
}

func TestDecompressPayloadRejectsSealed(t *testing.T) {
	payload := bigTLVs(t)
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := lep.CompressPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a compressed+authenticated envelope (flag combo) -> must fail.
	bad := append([]byte(nil), compressed...)
	bad[7] |= lep.FlagAuthenticated
	if _, err := lep.DecompressPayload(bad); err == nil {
		t.Fatal("DecompressPayload must reject compressed+authenticated without Open")
	}
}

func TestDecompressPayloadGarbage(t *testing.T) {
	payload := bigTLVs(t)
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := lep.CompressPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the compressed stream (flip a payload byte) -> zstd must fail.
	bad := append([]byte(nil), compressed...)
	bad[lep.HeaderSize+2] ^= 0xff
	if _, err := lep.DecompressPayload(bad); err == nil {
		t.Fatal("DecompressPayload must fail on corrupt zstd")
	}
}

// TestLatchStreamResync feeds a corrupt frame followed by a valid one and
// asserts resync extraction recovers the valid envelope.
func TestLatchStreamResync(t *testing.T) {
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	good := lep.EncodeLatchStream(plain)
	// Corrupt frame: same framing but with bad envelope CRC.
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-1] ^= 0xff
	// Mix: 2 garbage bytes, corrupt frame, then the good frame.
	stream := append([]byte{0x00, 0xff}, corrupt...)
	stream = append(stream, good...)

	ls := lep.NewLatchStream(bytes.NewReader(stream), 0)
	var got [][]byte
	ls.SetOnFrame(func(env []byte) error {
		got = append(got, env)
		return nil
	})
	if err := ls.ReadAll(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 recovered envelope, got %d", len(got))
	}
	if !bytes.Equal(got[0], plain) {
		t.Fatal("recovered envelope mismatch")
	}
}

func TestLatchStreamReadErrors(t *testing.T) {
	ls := lep.NewLatchStream(bytes.NewReader(nil), 0)
	if _, err := ls.Read(nil); err == nil {
		t.Fatal("nil buffer must error")
	}
	// Build a complete valid stream frame with a real envelope, then request a
	// smaller maxEnvelope so the too-large guard triggers.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := lep.EncodeLatchStream(plain)
	ls2 := lep.NewLatchStream(bytes.NewReader(frame), 16)
	if _, err := ls2.Read(frame); err == nil {
		t.Fatal("oversized envelope must error")
	}
	// EOF with leftover partial frame must be handled without error.
	partial := frame[:len(frame)-3]
	ls3 := lep.NewLatchStream(bytes.NewReader(partial), 0)
	if err := ls3.ReadAll(); err != nil {
		t.Fatalf("trailing partial frame must not error, got %v", err)
	}
}

func TestLatchStreamOnFrameError(t *testing.T) {
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := lep.EncodeLatchStream(plain)
	ls := lep.NewLatchStream(bytes.NewReader(frame), 0)
	ls.SetOnFrame(func(env []byte) error {
		return io.ErrUnexpectedEOF
	})
	if err := ls.ReadAll(); err != io.ErrUnexpectedEOF {
		t.Fatalf("expected onFrame error propagation, got %v", err)
	}
}

func TestParseStreamErrors(t *testing.T) {
	if _, _, err := lep.ParseLatchStream([]byte{'X', 'S'}); err == nil {
		t.Fatal("bad magic must fail")
	}
	if _, _, err := lep.ParseLatchStream([]byte{'L', 'S', 9, 0}); err == nil {
		t.Fatal("bad version must fail")
	}
	if _, _, err := lep.ParseLatchStream([]byte{'L', 'S', 1, 0, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("oversized length must fail")
	}
	if _, _, err := lep.ParseLatchStream([]byte{'L', 'S', 1, 0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}); err == nil {
		t.Fatal("CRC mismatch must fail")
	}
}

func TestParseLSAKErrors(t *testing.T) {
	if _, _, err := lep.ParseLSAK([]byte{1, 2, 3}); err == nil {
		t.Fatal("short LSAK must fail")
	}
	if _, _, err := lep.ParseLSAK(append([]byte("XXXX"), []byte{1, 0, 0, 0, 0, 0, 0, 0}...)); err == nil {
		t.Fatal("bad magic must fail")
	}
	if _, _, err := lep.ParseLSAK(append([]byte("LSAK"), []byte{9, 0, 0, 0, 0, 0, 0, 0}...)); err == nil {
		t.Fatal("bad version must fail")
	}
	// Round-trip.
	raw := lep.EncodeLSAK(42, lep.LSAckNackBusy)
	eventID, status, err := lep.ParseLSAK(raw)
	if err != nil {
		t.Fatal(err)
	}
	if eventID != 42 || status != lep.LSAckNackBusy {
		t.Fatalf("lsak round-trip = (%d, %d)", eventID, status)
	}
}

// TestAllKeysFallback drives openHMAC's enumeration of all ring keys when no
// explicit AuthKey is configured but a ring key still authenticates the MAC.
func TestAllKeysFallback(t *testing.T) {
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	keys := []lep.Key{generateKey(1), generateKey(2)}
	// ActiveID and AuthID reference ids absent from ByNumeric -> HaveAuth false.
	ring := lep.NewMemoryKeyring(keys, 1, 0)
	sealed, err := lep.Seal(plain, ring, false) // HMAC-only
	if err != nil {
		t.Fatal(err)
	}
	// Ring with AuthID set to an absent id: AuthKey() fails, allKeys must find it.
	fallbackRing := lep.NewMemoryKeyring(keys, 1, 99)
	opened, err := lep.Open(sealed, fallbackRing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("fallback open mismatch")
	}
	// Empty ring -> no auth key configured error path.
	emptyRing := lep.NewMemoryKeyring(nil, 0, 0)
	if _, err := lep.Open(sealed, emptyRing); err == nil {
		t.Fatal("no auth key must fail")
	}
}

// TestOpenHMACAuthOnlyErrorPaths covers openHMAC branches beyond happy path.
func TestOpenHMACAuthOnlyErrorPaths(t *testing.T) {
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	keys := []lep.Key{generateKey(1)}
	ring := lep.NewMemoryKeyring(keys, 1, 1)
	sealed, err := lep.Seal(plain, ring, false) // HMAC-only
	if err != nil {
		t.Fatal(err)
	}
	// Wrong key must fail.
	otherRing := lep.NewMemoryKeyring([]lep.Key{generateKey(99)}, 1, 1)
	if _, err := lep.Open(sealed, otherRing); err == nil {
		t.Fatal("wrong key must fail")
	}
	// Tampered HMAC must fail.
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 0xff
	if _, err := lep.Open(bad, ring); err == nil {
		t.Fatal("tampered HMAC must fail")
	}
	// Wrong-version label must fail (cross-version confusion guard).
	v2plain, err := lep.Encode(lep.Envelope{Version: 2, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	v2sealed, err := lep.Seal(v2plain, ring, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lep.Open(v2sealed, otherRing); err == nil {
		t.Fatal("wrong-key v2 HMAC must fail")
	}
}

func TestValidationErrorString(t *testing.T) {
	_, err := lep.Validate([]byte("nope"))
	if err == nil {
		t.Fatal("expected validation error")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestDecodeTLVsErrors(t *testing.T) {
	if _, err := lep.DecodeTLVs([]byte("garbage"), nil); err == nil {
		t.Fatal("garbage must fail")
	}
	// Sealed without ring -> must fail.
	payload := []byte{0x01, 0x00, 0x02, 0x00, 0xab, 0xcd}
	plain, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	ring := lep.NewMemoryKeyring([]lep.Key{generateKey(1)}, 1, 1)
	sealed, err := lep.Seal(plain, ring, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lep.DecodeTLVs(sealed, nil); err == nil {
		t.Fatal("sealed without ring must fail")
	}
	tlvs, err := lep.DecodeTLVs(sealed, ring)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 1 || tlvs[0].Type != 1 {
		t.Fatalf("unexpected TLVs: %+v", tlvs)
	}
}