// SPDX-License-Identifier: Apache-2.0
package lep_test

import (
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
	raw, err := lep.Encode(lep.Header{Version: 1, Type: 2, Sequence: 7, EventID: 9}, payload)
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
