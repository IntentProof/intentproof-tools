// Package fuzzcorpus resolves golden fuzz seed directories in intentproof-spec.
package fuzzcorpus

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var errSpecCorpusNotFound = errors.New("intentproof-spec golden/fuzz-corpora not found; set INTENTPROOF_SPEC_DIR")

type dirErrAction int

const (
	dirErrOK dirErrAction = iota
	dirErrSkip
	dirErrFatal
)

func dirErrActionFor(err error) dirErrAction {
	if err == nil {
		return dirErrOK
	}
	if errors.Is(err, errSpecCorpusNotFound) {
		return dirErrSkip
	}
	return dirErrFatal
}

// Dir returns golden/fuzz-corpora/<name> under INTENTPROOF_SPEC_DIR or monorepo fallback.
func Dir(t *testing.T, name string) string {
	t.Helper()
	abs, err := dir(os.Getenv("INTENTPROOF_SPEC_DIR"), name)
	switch dirErrActionFor(err) {
	case dirErrSkip:
		t.Skip(err.Error())
	case dirErrFatal:
		t.Fatal(err)
	}
	return abs
}

func dir(specEnv, name string) (string, error) {
	root, err := specRootFromEnv(specEnv)
	if err != nil {
		return "", err
	}
	return corpusDir(root, name)
}

func specRootFromEnv(env string) (string, error) {
	if env != "" {
		specDir := env
		if !filepath.IsAbs(specDir) {
			modRoot, err := moduleRoot()
			if err != nil {
				return "", fmt.Errorf("resolve INTENTPROOF_SPEC_DIR: %w", err)
			}
			specDir = filepath.Join(modRoot, specDir)
		}
		corpusRoot := filepath.Join(specDir, "golden", "fuzz-corpora")
		if st, err := os.Stat(corpusRoot); err == nil && st.IsDir() {
			return specDir, nil
		}
		return "", fmt.Errorf("INTENTPROOF_SPEC_DIR=%q but fuzz corpora not found under %s", env, corpusRoot)
	}
	modRoot, err := moduleRoot()
	if err != nil {
		return "", fmt.Errorf("resolve spec corpora: %w", err)
	}
	for _, candidate := range []string{
		filepath.Join(modRoot, "intentproof-spec"),
		filepath.Join(modRoot, "..", "intentproof-spec"),
		filepath.Join(modRoot, "..", "..", "intentproof-spec"),
	} {
		corpusRoot := filepath.Join(candidate, "golden", "fuzz-corpora")
		if st, err := os.Stat(corpusRoot); err == nil && st.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", fmt.Errorf("resolve spec path: %w", err)
			}
			return abs, nil
		}
	}
	return "", errSpecCorpusNotFound
}

func corpusDir(base, name string) (string, error) {
	dirPath := filepath.Join(base, "golden", "fuzz-corpora", name)
	st, err := os.Stat(dirPath)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("fuzz corpus not found: %s", dirPath)
	}
	abs, err := filepath.Abs(dirPath)
	if err != nil {
		return "", fmt.Errorf("resolve corpus path: %w", err)
	}
	return abs, nil
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
