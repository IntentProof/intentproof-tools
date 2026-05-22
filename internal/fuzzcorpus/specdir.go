// Package fuzzcorpus resolves golden fuzz seed directories in intentproof-spec.
package fuzzcorpus

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Dir returns golden/fuzz-corpora/<name> under INTENTPROOF_SPEC_DIR or monorepo fallback.
func Dir(t *testing.T, name string) string {
	t.Helper()
	base := specRoot(t)
	dir := filepath.Join(base, "golden", "fuzz-corpora", name)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		t.Fatalf("fuzz corpus not found: %s", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve corpus path: %v", err)
	}
	return abs
}

func specRoot(t *testing.T) string {
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
		corpusRoot := filepath.Join(specDir, "golden", "fuzz-corpora")
		if st, err := os.Stat(corpusRoot); err == nil && st.IsDir() {
			return specDir
		}
		t.Fatalf("INTENTPROOF_SPEC_DIR=%q but fuzz corpora not found under %s", env, corpusRoot)
	}
	for _, candidate := range []string{
		filepath.Join("..", "..", "intentproof-spec"),
		filepath.Join("..", "..", "..", "intentproof-spec"),
	} {
		corpusRoot := filepath.Join(candidate, "golden", "fuzz-corpora")
		if st, err := os.Stat(corpusRoot); err == nil && st.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				t.Fatalf("resolve spec path: %v", err)
			}
			return abs
		}
	}
	t.Skip("intentproof-spec golden/fuzz-corpora not found; set INTENTPROOF_SPEC_DIR")
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
