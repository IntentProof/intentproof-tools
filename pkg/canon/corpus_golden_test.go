package canon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMarshalRawSpecCorpus(t *testing.T) {
	dir := specFuzzCorpusDir(t)
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
			assertMarshalRawIdempotent(t, data)
		})
	}
	if ran == 0 {
		t.Fatalf("no .json corpus files under %s", dir)
	}
}

func assertMarshalRawIdempotent(t *testing.T, data []byte) {
	t.Helper()
	out, err := MarshalRaw(json.RawMessage(data))
	if err != nil {
		return
	}
	out2, err := MarshalRaw(out)
	if err != nil {
		t.Fatalf("re-canonicalize succeeded output: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("canonical output is not idempotent:\n  first: %s\n second: %s",
			string(out), string(out2))
	}
}

func specFuzzCorpusDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("INTENTPROOF_SPEC_DIR"); dir != "" {
		corpus := filepath.Join(dir, "golden", "fuzz-corpora", "canon")
		if st, err := os.Stat(corpus); err == nil && st.IsDir() {
			return corpus
		}
	}
	for _, candidate := range []string{
		filepath.Join("..", "..", "intentproof-spec", "golden", "fuzz-corpora", "canon"),
		filepath.Join("..", "..", "..", "intentproof-spec", "golden", "fuzz-corpora", "canon"),
	} {
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				t.Fatalf("resolve corpus path: %v", err)
			}
			return abs
		}
	}
	t.Skip("intentproof-spec golden/fuzz-corpora/canon not found; set INTENTPROOF_SPEC_DIR")
	return ""
}
