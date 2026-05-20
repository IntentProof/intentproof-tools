package localloop

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunLocalDevLoopDefaultListenAddrs(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunLocalDevLoop(ctx, LocalDevConfig{
			HomeDir:     home,
			OpenBrowser: false,
			Stdout:      func(string) {},
		})
	}()

	// Cancel quickly; empty addrs exercise default :9787/:9788/:9789 branches.
	cancel()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("RunLocalDevLoop did not stop")
	}
}

func TestRunLocalDevLoopMkdirDataDirError(t *testing.T) {
	home := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(home, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{HomeDir: home})
	if err == nil {
		t.Fatal("expected mkdir data dir error")
	}
}

func TestRunLocalDevLoopOpenDBError(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "local.db")
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{HomeDir: home})
	if err == nil {
		t.Fatal("expected open db error")
	}
}

func TestRunLocalDevLoopBootstrapError(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{HomeDir: home})
	if err == nil {
		t.Fatal("expected bootstrap error")
	}
}

func TestRunLocalDevLoopNATSError(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	jsBlock := filepath.Join(dataDir, "jetstream")
	if err := os.WriteFile(jsBlock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{
		HomeDir: home,
		DataDir: dataDir,
	})
	if err == nil || !strings.Contains(err.Error(), "start nats") {
		t.Fatalf("err=%v", err)
	}
}
