package localloop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunLocalDevLoopOpenBrowserHook(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "1")

	var opened string
	restore := SetLaunchBrowserHook(func(u string) error {
		opened = u
		return nil
	})
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := RunLocalDevLoop(ctx, LocalDevConfig{
		HomeDir:       home,
		IngestAddr:    "127.0.0.1:0",
		VerifierAddr:  "127.0.0.1:0",
		DashboardAddr: "127.0.0.1:0",
		OpenBrowser:   true,
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && err != context.Canceled {
		t.Fatalf("run: %v", err)
	}
	if opened == "" {
		t.Fatal("expected browser hook invocation")
	}
}

func TestRunLocalDevLoopMissingHome(t *testing.T) {
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{})
	if err == nil || err.Error() != "home dir is required" {
		t.Fatalf("err=%v", err)
	}
}

func TestRunLocalDevLoopCustomDataDir(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, "custom-data")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	err := RunLocalDevLoop(ctx, LocalDevConfig{
		HomeDir: home,
		DataDir: dataDir,
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "local.db")); err != nil {
		t.Fatalf("expected db at custom data dir: %v", err)
	}
}
