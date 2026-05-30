package demo

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

const refundDemoAcceptanceTimeout = 120 * time.Second

// TestRefundDemoAcceptance is the Task 6.8 acceptance gate: offline refund demo,
// catalog copy, stripe@demo path, bundle export, re-verify, and timing budget.
func TestRefundDemoAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("golden demo acceptance")
	}

	home := t.TempDir()
	work := t.TempDir()
	var stdout bytes.Buffer

	start := time.Now()
	err := RunRefund(context.Background(), Options{
		Stdout:         &stdout,
		Stderr:         os.Stderr,
		HomeDir:        home,
		WorkDir:        work,
		OpenBrowser:    false,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 5, 0, 0, time.UTC),
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > refundDemoAcceptanceTimeout {
		t.Fatalf("demo refund took %s; want <= %s on %s/%s",
			elapsed, refundDemoAcceptanceTimeout, runtime.GOOS, runtime.GOARCH)
	}

	out := stdout.String()
	for _, want := range []string{
		"loading scenario \"refund\"",
		"stripe@demo attestation",
		"fail.required.missing",
		"Required step was skipped",
		"corr_demo_refund_ok",
		"corr_demo_refund_missing_notify",
		"Re-verify: intentproof verify ./demo-refund.proof.tar.zst",
		"Dashboard: http://",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q\n%s", want, out)
		}
	}

	bundlePath := filepath.Join(work, "demo-refund.proof.tar.zst")
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := bundle.Verify(bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != "pass" {
		t.Fatalf("offline bundle verify status=%s reason=%s findings=%v",
			vr.Status, vr.Reason, vr.Findings)
	}

	gotHash := canonicalBundleContentHash(t, raw)
	wantHash := readExpectedBundleHash(t)
	if gotHash != wantHash {
		t.Fatalf("bundle content sha256 mismatch on %s/%s: got %s want %s",
			runtime.GOOS, runtime.GOARCH, gotHash, wantHash)
	}

	t.Logf("PASS: refund demo acceptance on %s/%s in %s", runtime.GOOS, runtime.GOARCH, elapsed)
}
