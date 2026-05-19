package demo

import (
	"context"
	"os"
	"testing"
)

func TestRunRefundRejectsBadSeed(t *testing.T) {
	err := RunRefund(context.Background(), Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		HomeDir:        t.TempDir(),
		WorkDir:        t.TempDir(),
		PrivateKeySeed: []byte{1, 2, 3},
	})
	if err == nil {
		t.Fatal("expected seed length error")
	}
}
