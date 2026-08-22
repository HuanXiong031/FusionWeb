package database

import (
	"strings"
	"testing"
)

func TestEncodeScanDebugPacketDataKeepsSafeText(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encoded := encodeScanDebugPacketData(raw)
	if encoded != raw {
		t.Fatalf("safe text should not be encoded: %q", encoded)
	}
	if decoded := decodeScanDebugPacketData(encoded); decoded != raw {
		t.Fatalf("safe text decode mismatch: %q", decoded)
	}
}

func TestEncodeScanDebugPacketDataProtectsPostgresText(t *testing.T) {
	raw := string([]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', 0xff, 0x00, 0xac})
	encoded := encodeScanDebugPacketData(raw)
	if !strings.HasPrefix(encoded, scanDebugPacketBase64Prefix) {
		t.Fatalf("unsafe packet was not encoded: %q", encoded)
	}
	if !isPostgresTextSafe(encoded) {
		t.Fatalf("encoded packet is not PostgreSQL TEXT safe")
	}
	if decoded := decodeScanDebugPacketData(encoded); decoded != raw {
		t.Fatalf("decoded packet mismatch: got %#v want %#v", []byte(decoded), []byte(raw))
	}
}

func TestDecodeScanDebugPacketDataLeavesInvalidEnvelopeUntouched(t *testing.T) {
	raw := scanDebugPacketBase64Prefix + "not-base64-%%%"
	if decoded := decodeScanDebugPacketData(raw); decoded != raw {
		t.Fatalf("invalid envelope should remain untouched: %q", decoded)
	}
}

func TestEncodeScanDebugPacketDataProtectsEnvelopePrefix(t *testing.T) {
	raw := scanDebugPacketBase64Prefix + "R0VUIC8="
	encoded := encodeScanDebugPacketData(raw)
	if encoded == raw {
		t.Fatalf("packet with envelope prefix should be encoded")
	}
	if decoded := decodeScanDebugPacketData(encoded); decoded != raw {
		t.Fatalf("decoded packet mismatch: got %q want %q", decoded, raw)
	}
}
