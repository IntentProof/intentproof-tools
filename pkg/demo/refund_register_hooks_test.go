package demo

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunRefundRegisterSDKFailure(t *testing.T) {
	orig := refundRegisterSDK
	refundRegisterSDK = func(context.Context, *sql.DB, string, string, ed25519.PublicKey) error {
		return errors.New("register fail")
	}
	t.Cleanup(func() { refundRegisterSDK = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "register sdk") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundGenerateKeyFailure(t *testing.T) {
	orig := refundGenerateKey
	refundGenerateKey = func(io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
		return nil, nil, errors.New("generate fail")
	}
	t.Cleanup(func() { refundGenerateKey = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "generate key") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundStartNATSError(t *testing.T) {
	orig := refundStartNATS
	refundStartNATS = func(string) (*localloop.NATSWrapper, error) {
		return nil, errors.New("nats fail")
	}
	t.Cleanup(func() { refundStartNATS = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "start nats") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundOpenBrowserInvokesHook(t *testing.T) {
	restore := localloop.SetLaunchBrowserHook(func(url string) error {
		if url == "" {
			return errors.New("empty url")
		}
		return nil
	})
	defer restore()
	t.Setenv("CI", "")
	t.Setenv(localloop.EnvLocalOpenBrowser, "1")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	home := t.TempDir()
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: home, WorkDir: work, OpenBrowser: true,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
}
