package demo

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitHTTPCancelledBeforeReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitHTTP(ctx, http.DefaultClient, []string{"http://127.0.0.1:1/healthz"})
	if err == nil {
		t.Fatal("expected cancelled error")
	}
}

func TestWaitHTTPNon200ThenSuccess(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitHTTP(ctx, srv.Client(), []string{srv.URL}); err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestRunRefundOpenDBError(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "local.db")
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil {
		t.Fatal("expected open db error")
	}
}

func TestPostActionChainConnectionRefused(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	err := postActionChain(http.DefaultClient, "http://127.0.0.1:1/v1/events", priv, "inst", "corr",
		[]string{"payments.refund.execute"}, time.Now())
	if err == nil {
		t.Fatal("expected post error")
	}
}
