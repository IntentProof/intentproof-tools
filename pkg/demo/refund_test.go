package demo

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestRunRefundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping demo integration in -short")
	}
	home := t.TempDir()
	work := t.TempDir()
	ctx := context.Background()
	opt := Options{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		HomeDir:     home,
		WorkDir:     work,
		OpenBrowser: false,
	}
	if err := RunRefund(ctx, opt); err != nil {
		t.Fatal(err)
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
		t.Fatalf("bundle status: %s reason=%s findings=%v", vr.Status, vr.Reason, vr.Findings)
	}
	if !hasBundleFinding(vr.Findings, "event.signature_valid") {
		t.Fatalf("expected event signature validation, findings=%v", vr.Findings)
	}
	if hasBundleFinding(vr.Findings, "event.signature_key_unavailable") {
		t.Fatalf("expected demo bundle to include event public keys, findings=%v", vr.Findings)
	}
}

func hasBundleFinding(findings []string, needle string) bool {
	for _, finding := range findings {
		if finding == needle {
			return true
		}
	}
	return false
}
