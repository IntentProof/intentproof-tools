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

func TestRunRefundListenDashboardFailure(t *testing.T) {
	calls := 0
	orig := refundListenTCP
	refundListenTCP = func(network, address string) (net.Listener, error) {
		calls++
		if calls == 3 {
			return nil, errors.New("listen dashboard fail")
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
	if err == nil || !strings.Contains(err.Error(), "listen dashboard") {
		t.Fatalf("err=%v", err)
	}
}
