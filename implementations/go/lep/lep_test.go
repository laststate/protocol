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
	if h.Type != 2 || h.Sequence != 7 || h.EventID != 9 || h.PayloadLength != 6 {
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

func TestTLVTypesExported(t *testing.T) {
	// Verify all 22 TLV types are exported as constants.
	expected := []struct {
		name string
		val  uint16
	}{
		{"TLVNone", 0}, {"TLVSource", 1}, {"TLVEpoch", 2}, {"TLVVersion", 3},
		{"TLVFirmwareHash", 4}, {"TLVHeartbeat", 5}, {"TLVStackPointer", 6},
		{"TLVExceptionType", 7}, {"TLVExceptionAddr", 8}, {"TLVExceptionInfo", 9},
		{"TLVRegisters", 10}, {"TLVBacktrace", 11}, {"TLVMemoryUsage", 12},
		{"TLVSystemState", 13}, {"TLVBatteryStatus", 14}, {"TLVRadioStatus", 15},
		{"TLVCPU64", 16}, {"TLVBlackbox", 17}, {"TLVMission", 18}, {"TLVTimeSync", 19},
		{"TLVProvisioning", 20}, {"TLVSupervisor", 21}, {"TLVEnvironment", 22},
	}
	for _, e := range expected {
		t.Run(e.name, func(t *testing.T) {
			// Verify the constant value is set correctly.
			switch e.name {
			case "TLVNone":
				if lep.TLVNone != e.val {
					t.Errorf("TLVNone = %d, want %d", lep.TLVNone, e.val)
				}
			case "TLVSource":
				if lep.TLVSource != e.val {
					t.Errorf("TLVSource = %d, want %d", lep.TLVSource, e.val)
				}
			case "TLVEpoch":
				if lep.TLVEpoch != e.val {
					t.Errorf("TLVEpoch = %d, want %d", lep.TLVEpoch, e.val)
				}
			case "TLVVersion":
				if lep.TLVVersion != e.val {
					t.Errorf("TLVVersion = %d, want %d", lep.TLVVersion, e.val)
				}
			case "TLVFirmwareHash":
				if lep.TLVFirmwareHash != e.val {
					t.Errorf("TLVFirmwareHash = %d, want %d", lep.TLVFirmwareHash, e.val)
				}
			case "TLVHeartbeat":
				if lep.TLVHeartbeat != e.val {
					t.Errorf("TLVHeartbeat = %d, want %d", lep.TLVHeartbeat, e.val)
				}
			case "TLVStackPointer":
				if lep.TLVStackPointer != e.val {
					t.Errorf("TLVStackPointer = %d, want %d", lep.TLVStackPointer, e.val)
				}
			case "TLVExceptionType":
				if lep.TLVExceptionType != e.val {
					t.Errorf("TLVExceptionType = %d, want %d", lep.TLVExceptionType, e.val)
				}
			case "TLVExceptionAddr":
				if lep.TLVExceptionAddr != e.val {
					t.Errorf("TLVExceptionAddr = %d, want %d", lep.TLVExceptionAddr, e.val)
				}
			case "TLVExceptionInfo":
				if lep.TLVExceptionInfo != e.val {
					t.Errorf("TLVExceptionInfo = %d, want %d", lep.TLVExceptionInfo, e.val)
				}
			case "TLVRegisters":
				if lep.TLVRegisters != e.val {
					t.Errorf("TLVRegisters = %d, want %d", lep.TLVRegisters, e.val)
				}
			case "TLVBacktrace":
				if lep.TLVBacktrace != e.val {
					t.Errorf("TLVBacktrace = %d, want %d", lep.TLVBacktrace, e.val)
				}
			case "TLVMemoryUsage":
				if lep.TLVMemoryUsage != e.val {
					t.Errorf("TLVMemoryUsage = %d, want %d", lep.TLVMemoryUsage, e.val)
				}
			case "TLVSystemState":
				if lep.TLVSystemState != e.val {
					t.Errorf("TLVSystemState = %d, want %d", lep.TLVSystemState, e.val)
				}
			case "TLVBatteryStatus":
				if lep.TLVBatteryStatus != e.val {
					t.Errorf("TLVBatteryStatus = %d, want %d", lep.TLVBatteryStatus, e.val)
				}
			case "TLVRadioStatus":
				if lep.TLVRadioStatus != e.val {
					t.Errorf("TLVRadioStatus = %d, want %d", lep.TLVRadioStatus, e.val)
				}
			case "TLVCPU64":
				if lep.TLVCPU64 != e.val {
					t.Errorf("TLVCPU64 = %d, want %d", lep.TLVCPU64, e.val)
				}
			case "TLVBlackbox":
				if lep.TLVBlackbox != e.val {
					t.Errorf("TLVBlackbox = %d, want %d", lep.TLVBlackbox, e.val)
				}
			case "TLVMission":
				if lep.TLVMission != e.val {
					t.Errorf("TLVMission = %d, want %d", lep.TLVMission, e.val)
				}
			case "TLVTimeSync":
				if lep.TLVTimeSync != e.val {
					t.Errorf("TLVTimeSync = %d, want %d", lep.TLVTimeSync, e.val)
				}
			case "TLVProvisioning":
				if lep.TLVProvisioning != e.val {
					t.Errorf("TLVProvisioning = %d, want %d", lep.TLVProvisioning, e.val)
				}
			case "TLVSupervisor":
				if lep.TLVSupervisor != e.val {
					t.Errorf("TLVSupervisor = %d, want %d", lep.TLVSupervisor, e.val)
				}
			case "TLVEnvironment":
				if lep.TLVEnvironment != e.val {
					t.Errorf("TLVEnvironment = %d, want %d", lep.TLVEnvironment, e.val)
				}
			}
		})
	}
}

func TestEncodeTLVs(t *testing.T) {
	fields := []lep.TLV{
		{Type: lep.TLVSource, Value: []byte("device-001")},
		{Type: lep.TLVHeartbeat, Value: []byte{0x01}},
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
	if got[0].Type != lep.TLVSource || string(got[0].Value) != "device-001" {
		t.Errorf("unexpected first TLV: %v", got[0])
	}
}

func TestTLVSetBuilder(t *testing.T) {
	set := lep.TLVSet{}
	set.Add(lep.TLVSource, []byte("test"))
	set.Add(lep.TLVHeartbeat, []byte{0x01})
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
	if string(set.Get(lep.TLVSource)) != "test" {
		t.Errorf("TLVSet.Get(TLVSource) = %q", set.Get(lep.TLVSource))
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
