package canon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/fuzzcorpus"
)

func TestMarshalRawSpecCorpus(t *testing.T) {
	dir := fuzzcorpus.Dir(t, "canon")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one corpus file under %s", dir)
	}

	var ran int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read corpus file: %v", err)
			}
			assertGoldenMarshalRawIdempotent(t, data)
		})
	}
	if ran == 0 {
		t.Fatalf("no .json corpus files under %s", dir)
	}
}

func assertGoldenMarshalRawIdempotent(t *testing.T, data []byte) {
	t.Helper()
	out, err := MarshalRaw(json.RawMessage(data))
	if err != nil {
		t.Fatalf("MarshalRaw golden corpus: %v\ninput: %s", err, string(data))
	}
	assertMarshalRawIdempotent(t, out)
}

func assertMarshalRawIdempotent(t *testing.T, canonical []byte) {
	t.Helper()
	out2, err := MarshalRaw(canonical)
	if err != nil {
		t.Fatalf("re-canonicalize succeeded output: %v", err)
	}
	if !bytes.Equal(canonical, out2) {
		t.Fatalf("canonical output is not idempotent:\n  first: %s\n second: %s",
			string(canonical), string(out2))
	}
}
