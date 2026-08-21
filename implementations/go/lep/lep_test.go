// SPDX-License-Identifier: Apache-2.0
package lep_test

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laststate/protocol/implementations/go/lep"
)

func loadHex(t *testing.T, rel string) []byte {
	t.Helper()
	root := filepath.Join("..", "..", "..", "test-vectors")
	data, err := os.ReadFile(filepath.Join(root, rel))
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

func TestGoldenValid(t *testing.T) {
	raw := loadHex(t, "valid/lep-v1-basic.hex")
	h, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 1 || h.Type != 2 || h.Sequence != 7 || h.EventID != 9 || h.PayloadLength != 6 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestGoldenValidV2(t *testing.T) {
	raw := loadHex(t, "valid/lep-v2-basic.hex")
	h, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 2 || h.Type != 2 || h.Sequence != 7 || h.EventID != 9 || h.PayloadLength != 6 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestGoldenLatchPlatformContexts(t *testing.T) {
	raw := loadHex(t, "valid/latch-platform-contexts.hex")
	h, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Architecture != 5 || h.Sequence != 29 || h.EventID != 30 {
		t.Fatalf("unexpected header: %+v", h)
	}
	tlvs, err := lep.ParseTLVs(raw[lep.HeaderSize : lep.HeaderSize+int(h.PayloadLength)])
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{
		lep.TLVCPU64, lep.TLVBlackbox, lep.TLVMission, lep.TLVTimeSync,
		lep.TLVProvisioning, lep.TLVSupervisor, lep.TLVEnvironment,
	}
	if len(tlvs) != len(want) {
		t.Fatalf("got %d TLVs, want %d", len(tlvs), len(want))
	}
	for index, typ := range want {
		if tlvs[index].Type != typ {
			t.Fatalf("TLV %d: got %d, want %d", index, tlvs[index].Type, typ)
		}
	}
	if got := tlvs[0].Value; len(got) != 4 || got[0] != 1 || got[1] != 2 || got[2] != 5 || got[3] != 8 {
		t.Fatalf("unexpected CPU64 unavailable descriptor: %x", got)
	}
}

func TestGoldenLatchCPU64Complete(t *testing.T) {
	raw := loadHex(t, "valid/latch-cpu64-complete.hex")
	h, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := lep.ParseTLVs(raw[lep.HeaderSize : lep.HeaderSize+int(h.PayloadLength)])
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 1 || tlvs[0].Type != lep.TLVCPU64 || len(tlvs[0].Value) != 292 {
		t.Fatalf("unexpected CPU64 TLV: %+v", tlvs)
	}
	if got := tlvs[0].Value[:4]; got[0] != 1 || got[1] != 1 || got[2] != 5 || got[3] != 8 {
		t.Fatalf("unexpected CPU64 complete descriptor: %x", got)
	}
}

func TestRoundTrip(t *testing.T) {
	payload, _ := hex.DecodeString("01000200aabb")
	raw, err := lep.Encode(lep.Envelope{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := loadHex(t, "valid/lep-v1-basic.hex")
	if hex.EncodeToString(raw) != hex.EncodeToString(want) {
		t.Fatalf("got %x want %x", raw, want)
	}
}

func TestInvalid(t *testing.T) {
	files := []string{
		"invalid/bad-magic.hex",
		"invalid/bad-header-crc.hex",
		"invalid/bad-payload-crc.hex",
		"invalid/tlv-type-zero.hex",
		"invalid/unsupported-version.hex",
		"invalid/unknown-flags.hex",
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			raw := loadHex(t, f)
			if _, err := lep.Validate(raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestTLVTypesRegistryValues(t *testing.T) {
	expected := map[string]uint16{
		"TLVIdentity": 1, "TLVReset": 2, "TLVEvent": 3, "TLVCpu": 4,
		"TLVFault": 5, "TLVBreadcrumb": 6, "TLVMetric": 7, "TLVPower": 8,
		"TLVHealth": 9, "TLVAssert": 10, "TLVPeripheral": 11, "TLVLog": 12,
		"TLVMemory": 13, "TLVStack": 14, "TLVHeap": 15, "TLVCPU64": 16,
		"TLVBlackbox": 17, "TLVMission": 18, "TLVTimeSync": 19,
		"TLVProvisioning": 20, "TLVSupervisor": 21, "TLVEnvironment": 22,
	}
	values := map[string]uint16{
		"TLVIdentity": lep.TLVIdentity, "TLVReset": lep.TLVReset, "TLVEvent": lep.TLVEvent,
		"TLVCpu": lep.TLVCpu, "TLVFault": lep.TLVFault, "TLVBreadcrumb": lep.TLVBreadcrumb,
		"TLVMetric": lep.TLVMetric, "TLVPower": lep.TLVPower, "TLVHealth": lep.TLVHealth,
		"TLVAssert": lep.TLVAssert, "TLVPeripheral": lep.TLVPeripheral, "TLVLog": lep.TLVLog,
		"TLVMemory": lep.TLVMemory, "TLVStack": lep.TLVStack, "TLVHeap": lep.TLVHeap,
		"TLVCPU64": lep.TLVCPU64, "TLVBlackbox": lep.TLVBlackbox, "TLVMission": lep.TLVMission,
		"TLVTimeSync": lep.TLVTimeSync, "TLVProvisioning": lep.TLVProvisioning,
		"TLVSupervisor": lep.TLVSupervisor, "TLVEnvironment": lep.TLVEnvironment,
	}
	for name, want := range expected {
		if got := values[name]; got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestEncodeTLVs(t *testing.T) {
	fields := []lep.TLV{
		{Type: lep.TLVIdentity, Value: []byte("device-001")},
		{Type: lep.TLVHealth, Value: []byte{0x01}},
	}
	raw, err := lep.EncodeTLVs(lep.Envelope{Version: 1, Type: 1, Sequence: 1, EventID: 1}, fields)
	if err != nil {
		t.Fatal(err)
	}
	env, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.Flags != 0 {
		t.Errorf("expected plain envelope, got flags 0x%02x", env.Flags)
	}
	got, err := lep.TLVs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(got))
	}
	if got[0].Type != lep.TLVIdentity || string(got[0].Value) != "device-001" {
		t.Errorf("unexpected first TLV: %v", got[0])
	}
}

func TestTLVSetBuilder(t *testing.T) {
	set := lep.TLVSet{}
	set.Add(lep.TLVIdentity, []byte("test"))
	set.Add(lep.TLVHealth, []byte{0x01})
	payload, err := set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fields, err := lep.ParseTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(fields))
	}
	if string(set.Get(lep.TLVIdentity)) != "test" {
		t.Errorf("TLVSet.Get(TLVIdentity) = %q", set.Get(lep.TLVIdentity))
	}
}

func TestEdgeCaseEmptyPayload(t *testing.T) {
	raw, err := lep.Encode(lep.Envelope{Version: 1, Type: 1, Sequence: 0, EventID: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := lep.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.PayloadLength != 0 {
		t.Errorf("expected empty payload, got %d", env.PayloadLength)
	}
}

func TestEdgeCaseMaxPayload(t *testing.T) {
	// Create a payload near 64KB (TLV uint16 length limit).
	size := 64*1024 - lep.HeaderSize - 8
	payload := make([]byte, size)
	binary.LittleEndian.PutUint16(payload[0:2], 1) // type = Source
	binary.LittleEndian.PutUint16(payload[2:4], uint16(size-4))
	for i := 4; i < size; i++ {
		payload[i] = 0x42
	}
	raw, err := lep.Encode(lep.Envelope{Version: 1, Type: 1, Sequence: 1, EventID: 1}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(raw[16:20]) != uint32(size) {
		t.Errorf("payload length mismatch: got %d, want %d",
			binary.LittleEndian.Uint32(raw[16:20]), size)
	}
}

func TestEdgeCaseOverflowPayload(t *testing.T) {
	// Payload larger than MaxEnvelopeSize should fail.
	payload := make([]byte, lep.MaxEnvelopeSize+1)
	_, err := lep.Encode(lep.Envelope{Version: 1, Type: 1}, payload)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestEdgeCaseFlagCombinations(t *testing.T) {
	// Encrypted without AEAD should fail.
	raw, _ := lep.Encode(lep.Envelope{Version: 1, Type: 1, Flags: lep.FlagEncrypted}, []byte("test"))
	_, err := lep.Validate(raw)
	if err == nil {
		t.Fatal("expected error for encrypted without AEAD")
	}

	// AEAD without authenticated should fail.
	raw, _ = lep.Encode(lep.Envelope{Version: 1, Type: 1, Flags: lep.FlagAEAD}, []byte("test"))
	_, err = lep.Validate(raw)
	if err == nil {
		t.Fatal("expected error for AEAD without authenticated")
	}
}
