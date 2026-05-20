package demo

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunRefundCreateBundlePermissionDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(blocker, "nested")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      deterministicRefundFixedTime(),
	})
	if err == nil {
		t.Fatal("expected bundle create error")
	}
}

func deterministicRefundFixedTime() time.Time {
	return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
}
