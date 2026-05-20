package demo

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunRefundWithoutFixedTime(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		OpenBrowser:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefundAbsBundlePathFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	// Relative work dir exercises filepath.Abs in success path.
	work := "."
	t.Chdir(t.TempDir())
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
}
