package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunRefundDefaultsNilWriters(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	err := RunRefund(context.Background(), Options{
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunRefundDefaultWorkDirCurrent(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Chdir(work)
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefundMkdirDataDirError(t *testing.T) {
	home := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(home, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "create data dir") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundNATStartError(t *testing.T) {
	home := t.TempDir()
	block := filepath.Join(home, ".intentproof", "local", "nats-demo")
	if err := os.MkdirAll(filepath.Dir(block), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(block, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "start nats") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundOpenBrowserHookError(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("CI", "")
	t.Setenv(localloop.EnvLocalOpenBrowser, "1")
	restore := localloop.SetLaunchBrowserHook(func(string) error {
		return os.ErrPermission
	})
	defer restore()

	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		OpenBrowser:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostActionChainRequestBuildError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = postActionChain(http.DefaultClient, "://bad-url", priv, "inst", "corr", []string{"payments.refund.execute"}, time.Now())
	if err == nil {
		t.Fatal("expected request build error")
	}
}
