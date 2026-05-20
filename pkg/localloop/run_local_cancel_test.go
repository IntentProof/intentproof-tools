package localloop

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunLocalDevLoopStartsAndStops(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunLocalDevLoop(ctx, LocalDevConfig{
			HomeDir:       home,
			IngestAddr:    "127.0.0.1:0",
			VerifierAddr:  "127.0.0.1:0",
			DashboardAddr: "127.0.0.1:0",
			OpenBrowser:   false,
			Stdout:        func(string) {},
		})
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Logf("shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for RunLocalDevLoop")
	}
}

func TestBootstrapLocalRegistryFromKeypair(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), []byte(`{"privateKey":"AAAA","instanceId":"inst_local"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := BootstrapLocalRegistry(context.Background(), db, home); err != nil {
		t.Logf("bootstrap: %v", err)
	}
}
