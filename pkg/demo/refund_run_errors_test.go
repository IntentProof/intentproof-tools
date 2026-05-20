package demo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRefundRejectsUnwritableWorkDir(t *testing.T) {
	home := t.TempDir()
	workFile := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(workFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunRefund(context.Background(), Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		HomeDir:        home,
		WorkDir:        workFile,
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil {
		t.Fatal("expected bundle create error")
	}
}

func TestRunRefundUsesDefaultHome(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	work := t.TempDir()
	err := RunRefund(context.Background(), Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		OpenBrowser:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
}
