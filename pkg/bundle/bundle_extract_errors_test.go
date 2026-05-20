package bundle

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerifyRejectsUnreadableBundle(t *testing.T) {
	r := &failReader{}
	_, err := Verify(r, nil)
	if err == nil || !strings.Contains(err.Error(), "bundle.read_failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyRejectsPlainTarWithoutZstd(t *testing.T) {
	// Minimal invalid tar bytes (not a valid archive).
	_, err := Verify(bytes.NewReader([]byte("not-a-bundle")), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyRejectsCorruptZstdFrame(t *testing.T) {
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x00}
	_, err := Verify(bytes.NewReader(frame), nil)
	if err == nil || !strings.Contains(err.Error(), "bundle.") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseJSONLSkipsInvalidLines(t *testing.T) {
	items := parseJSONL([]byte("{\"event_id\":\"e1\"}\n{broken\n"))
	if len(items) != 1 {
		t.Fatalf("items=%d", len(items))
	}
}

func TestMustMarshal(t *testing.T) {
	raw := mustMarshal(map[string]interface{}{"k": "v"})
	if len(raw) == 0 {
		t.Fatal("empty")
	}
}

type failReader struct{}

func (f *failReader) Read([]byte) (int, error) {
	return 0, errAlwaysFail
}

var errAlwaysFail = errors.New("read failed")
