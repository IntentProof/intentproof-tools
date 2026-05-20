package demo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunRefundOpenBrowserPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CI", "")
	t.Setenv(localloop.EnvLocalOpenBrowser, "1")

	var openedURL string
	restore := localloop.SetLaunchBrowserHook(func(u string) error {
		openedURL = u
		return nil
	})
	defer restore()

	err := RunRefund(context.Background(), Options{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		HomeDir:     home,
		WorkDir:     work,
		OpenBrowser: true,
		FixedTime:   time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if openedURL == "" {
		t.Fatal("expected dashboard URL launch attempt")
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefundGeneratesKeyWithoutSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := RunRefund(ctx, Options{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		HomeDir:     home,
		WorkDir:     work,
		OpenBrowser: false,
	}); err != nil {
		t.Fatal(err)
	}
}
