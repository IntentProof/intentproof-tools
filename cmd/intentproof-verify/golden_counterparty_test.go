package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoldenCounterpartyVerifyStdout(t *testing.T) {
	specDir := resolveSpecDir(t)
	goldenDir := filepath.Join(specDir, "golden", "counterparty")
	bundlePath := filepath.Join(goldenDir, "counterparty-refund.proof.tar.zst")
	expectedPath := filepath.Join(goldenDir, "expected-verify-stdout-sha256.txt")
	if _, err := os.Stat(bundlePath); err != nil {
		t.Skipf("golden counterparty bundle not present at %s: %v", bundlePath, err)
	}
	wantRaw, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected stdout hash: %v", err)
	}
	want := strings.TrimSpace(string(wantRaw))

	var stdout, stderr strings.Builder
	code := run([]string{bundlePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify golden bundle: code=%d stderr=%s", code, stderr.String())
	}
	got := sha256.Sum256([]byte(stdout.String()))
	gotHex := hex.EncodeToString(got[:])
	if gotHex != want {
		t.Fatalf("stdout sha256 drift: got %s want %s\nstdout:\n%s", gotHex, want, stdout.String())
	}
}

func resolveSpecDir(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("INTENTPROOF_SPEC_DIR"); env != "" {
		if filepath.IsAbs(env) {
			return env
		}
		modRoot, err := moduleRoot()
		if err != nil {
			t.Fatalf("resolve INTENTPROOF_SPEC_DIR: %v", err)
		}
		return filepath.Join(modRoot, env)
	}
	candidates := []string{
		filepath.Join("..", "..", "intentproof-spec"),
		filepath.Join("..", "..", "..", "intentproof-spec"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "golden", "counterparty", "counterparty-refund.proof.tar.zst")); err == nil {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Skip("intentproof-spec golden/counterparty not found; set INTENTPROOF_SPEC_DIR")
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
