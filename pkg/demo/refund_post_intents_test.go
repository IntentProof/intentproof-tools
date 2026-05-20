package demo

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostActionChainAllRefundIntents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	priv := ed25519.NewKeyFromSeed(deterministicRefundSeed())
	actions := []string{
		"payments.refund.execute",
		"ledger.entry.write",
		"customer.notify",
		"custom.action",
	}
	if err := postActionChain(http.DefaultClient, srv.URL, priv, "inst", "corr",
		actions, time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestWaitHTTPRequestBuildErrorInvalidURL(t *testing.T) {
	ctx := context.Background()
	err := waitHTTP(ctx, http.DefaultClient, []string{"://bad-url"})
	if err == nil {
		t.Fatal("expected request build error")
	}
}

func TestRunRefundWithGeneratedKeyAndFixedTime(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := RunRefund(ctx, Options{
		HomeDir:     home,
		WorkDir:     work,
		OpenBrowser: false,
		FixedTime:   time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
}
