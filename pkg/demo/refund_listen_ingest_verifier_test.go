package demo

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunRefundListenIngestFailure(t *testing.T) {
	orig := refundListenTCP
	refundListenTCP = func(network, address string) (net.Listener, error) {
		return nil, errors.New("listen ingest fail")
	}
	t.Cleanup(func() { refundListenTCP = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "listen ingest") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundListenVerifierFailure(t *testing.T) {
	calls := 0
	orig := refundListenTCP
	refundListenTCP = func(network, address string) (net.Listener, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("listen verifier fail")
		}
		return orig(network, address)
	}
	t.Cleanup(func() { refundListenTCP = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "listen verifier") {
		t.Fatalf("err=%v", err)
	}
}
