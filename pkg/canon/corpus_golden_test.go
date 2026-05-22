package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func specFuzzCorpusDir(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("INTENTPROOF_SPEC_DIR"); env != "" {
		specDir := env
		if !filepath.IsAbs(specDir) {
			modRoot, err := moduleRoot()
			if err != nil {
				t.Fatalf("resolve INTENTPROOF_SPEC_DIR: %v", err)
			}
			specDir = filepath.Join(modRoot, specDir)
		}
		corpus := filepath.Join(specDir, "golden", "fuzz-corpora", "canon")
		if st, err := os.Stat(corpus); err == nil && st.IsDir() {
			return corpus
		}
		t.Fatalf("INTENTPROOF_SPEC_DIR=%q but fuzz corpus not found at %s", env, corpus)
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

func moduleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	modPath := strings.TrimSpace(string(out))
	if modPath == "" || modPath == "/dev/null" {
		return "", fmt.Errorf("go env GOMOD: no module root")
	}
	return filepath.Dir(modPath), nil
}
