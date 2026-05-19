package demo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestWaitHTTPReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := waitHTTP(ctx, srv.Client(), []string{srv.URL + "/"}); err != nil {
		t.Fatal(err)
	}
}

func TestWaitHTTPTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := waitHTTP(ctx, http.DefaultClient, []string{"http://127.0.0.1:1/"})
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestDemoIntentForAction(t *testing.T) {
	if demoIntentForAction("payments.refund.execute") == "" {
		t.Fatal("refund intent")
	}
	if demoIntentForAction("unknown.action") != "unknown.action" {
		t.Fatal("default")
	}
}

func TestHasReason(t *testing.T) {
	vr := &verifier.VerificationRun{
		Findings: []map[string]any{{"reason": "fail.temporal.exceeded"}},
	}
	if !hasReason(vr, "fail.temporal.exceeded") {
		t.Fatal("expected match")
	}
	if hasReason(vr, "other") {
		t.Fatal("unexpected match")
	}
}
