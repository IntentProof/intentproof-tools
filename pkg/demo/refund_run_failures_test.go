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
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestPostActionChainSecondPostFails(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".intentproof", "local")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := localloop.OpenDB(filepath.Join(dataDir, "postfail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := localloop.RegisterSDKInstance(context.Background(), db, localloop.LocalTenantID, "inst_pf", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if posts >= 2 {
			http.Error(w, "fail", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	err = postActionChain(http.DefaultClient, srv.URL+"/v1/events", priv, "inst_pf", "corr_pf",
		[]string{"payments.refund.execute", "ledger.entry.write"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitHTTPPartialFailure(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer badSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	err := waitHTTP(ctx, http.DefaultClient, []string{okSrv.URL, badSrv.URL})
	if err == nil {
		t.Fatal("expected wait failure")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not ready") && !strings.Contains(msg, "deadline exceeded") {
		t.Fatalf("err=%v", err)
	}
}

func TestHasReasonMissing(t *testing.T) {
	if hasReason(&verifier.VerificationRun{
		Findings: []map[string]any{{"reason": "other"}},
	}, "fail.required.missing") {
		t.Fatal("expected false")
	}
}
