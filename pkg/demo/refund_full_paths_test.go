package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestRunRefundFullE2E(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := RunRefund(ctx, Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		OpenBrowser:    false,
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "demo-refund.proof.tar.zst")); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefundInvalidSeedLength(t *testing.T) {
	err := RunRefund(context.Background(), Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		HomeDir:        t.TempDir(),
		WorkDir:        t.TempDir(),
		PrivateKeySeed: []byte{1, 2, 3},
	})
	if err == nil || !strings.Contains(err.Error(), "private key seed") {
		t.Fatalf("err=%v", err)
	}
}

func TestPostActionChainRejectsNonAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = postActionChain(http.DefaultClient, srv.URL, priv, "inst", "corr", []string{"demo.action"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("err=%v", err)
	}
}

func TestPostActionChainHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := localloop.OpenDB(filepath.Join(dataDir, "post.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := localloop.RegisterSDKInstance(context.Background(), db, localloop.LocalTenantID, "inst_post", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	nats, err := localloop.StartEmbeddedNATS(filepath.Join(dataDir, "nats"))
	if err != nil {
		t.Fatal(err)
	}
	defer nats.Shutdown()

	srv := httptest.NewServer(localloop.NewIngestServer("", db, nats).Handler())
	defer srv.Close()

	if err := postActionChain(http.DefaultClient, srv.URL+"/v1/events", priv, "inst_post", "corr_post",
		[]string{"payments.refund.execute"}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForCorrelationFlowTimeout(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := localloop.OpenDB(filepath.Join(dataDir, "wait.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	err = waitForCorrelationFlow(ctx, db, "corr_missing", 3)
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for flow") {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitHTTPRequestBuildError(t *testing.T) {
	ctx := context.Background()
	client := &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		}),
	}
	// Invalid URL in list triggers NewRequest error path when malformed; use cancelled ctx.
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	err := waitHTTP(ctx2, client, []string{"http://127.0.0.1:1/healthz"})
	if err == nil {
		t.Fatal("expected error")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
