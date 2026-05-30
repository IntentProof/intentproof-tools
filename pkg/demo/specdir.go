package demo

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var errGoldenDemoNotFound = errors.New("intentproof-spec golden/demo not found; set INTENTPROOF_SPEC_DIR")

// GoldenDemoRoot resolves intentproof-spec/golden/demo for fixture loading.
func GoldenDemoRoot() (string, error) {
	return goldenDemoRootFromEnv(os.Getenv("INTENTPROOF_SPEC_DIR"))
}

func goldenDemoRootFromEnv(env string) (string, error) {
	specRoot, err := specRootFromEnv(env)
	if err != nil {
		return "", err
	}
	demoRoot := filepath.Join(specRoot, "golden", "demo")
	if st, err := os.Stat(demoRoot); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w (missing %s)", errGoldenDemoNotFound, demoRoot)
	}
	abs, err := filepath.Abs(demoRoot)
	if err != nil {
		return "", fmt.Errorf("resolve golden demo path: %w", err)
	}
	return abs, nil
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
		demoRoot := filepath.Join(specDir, "golden", "demo")
		if st, err := os.Stat(demoRoot); err == nil && st.IsDir() {
			return specDir, nil
		}
		return "", fmt.Errorf("INTENTPROOF_SPEC_DIR=%q but golden/demo not found under %s", env, specDir)
	}
	modRoot, err := moduleRoot()
	if err != nil {
		return "", fmt.Errorf("resolve spec root: %w", err)
	}
	for _, candidate := range []string{
		filepath.Join(modRoot, "intentproof-spec"),
		filepath.Join(modRoot, "..", "intentproof-spec"),
		filepath.Join(modRoot, "..", "..", "intentproof-spec"),
	} {
		demoRoot := filepath.Join(candidate, "golden", "demo")
		if st, err := os.Stat(demoRoot); err == nil && st.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", fmt.Errorf("resolve spec path: %w", err)
			}
			return abs, nil
		}
	}
	return "", errGoldenDemoNotFound
}

func moduleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err == nil {
		modPath := strings.TrimSpace(string(out))
		if modPath != "" && modPath != "/dev/null" {
			return filepath.Dir(modPath), nil
		}
	}
	if root, err := moduleRootFromSourceFile(); err == nil {
		return root, nil
	}
	return "", fmt.Errorf("go env GOMOD: no module root")
}

func moduleRootFromSourceFile() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve module root from source")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", file)
		}
		dir = parent
	}
}

// SpecSemanticsPath returns semantics/reasons.json under the spec root.
func SpecSemanticsPath() (string, error) {
	specRoot, err := specRootFromEnv(os.Getenv("INTENTPROOF_SPEC_DIR"))
	if err != nil {
		return "", err
	}
	path := filepath.Join(specRoot, "semantics", "reasons.json")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("reason catalog not found at %s: %w", path, err)
	}
	return path, nil
}
