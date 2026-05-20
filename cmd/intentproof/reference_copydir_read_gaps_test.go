package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyDirSourceFileReadError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "secret.txt")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(file, 0o600) })

	dest := filepath.Join(t.TempDir(), "dest")
	if err := copyDir(src, dest); err == nil {
		t.Fatal("expected read error")
	}
}
