package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestDemoIntentForActionKnownAndDefault(t *testing.T) {
	if got := demoIntentForAction("payments.refund.execute"); got == "" {
		t.Fatal("expected non-empty intent")
	}
	if got := demoIntentForAction("custom.action"); got != "custom.action" {
		t.Fatalf("got=%q", got)
	}
}

func TestHasReasonDetectsFinding(t *testing.T) {
	run := &verifier.VerificationRun{
		Findings: []map[string]interface{}{{"reason": "fail.required.missing"}},
	}
	if !hasReason(run, "fail.required.missing") {
		t.Fatal("expected reason")
	}
	if hasReason(run, "pass.required.satisfied") {
		t.Fatal("unexpected reason")
	}
}

func TestPostActionChainHTTPTransportError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		}),
	}
	err = postActionChain(client, "http://127.0.0.1:1/v1/events", priv, "inst", "corr",
		[]string{"payments.refund.execute"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "post payments.refund.execute") {
		t.Fatalf("err=%v", err)
	}
}

func TestPostActionChainRejectsBadRequestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("rejected"))
	}))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = postActionChain(http.DefaultClient, srv.URL, priv, "inst", "corr",
		[]string{"payments.refund.execute"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundCancelledContextBeforeReady(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RunRefund(ctx, Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil {
		t.Fatal("expected cancelled error")
	}
}

func TestRunRefundPrintsCompletionSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	var stdout bytes.Buffer
	err := RunRefund(context.Background(), Options{
		Stdout:         &stdout,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{
		"loading scenario \"refund\"",
		"corr_demo_refund_ok",
		"corr_demo_refund_missing_notify",
		"fail.required.missing",
		"Required step was skipped",
		"demo-refund.proof.tar.zst",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestRunRefundOpenBrowserAttemptedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("CI", "")
	t.Setenv(localloop.EnvLocalOpenBrowser, "1")
	restore := localloop.SetLaunchBrowserHook(func(string) error { return nil })
	defer restore()

	err := RunRefund(context.Background(), Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		OpenBrowser:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
}
