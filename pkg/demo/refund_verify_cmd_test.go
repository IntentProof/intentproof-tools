package demo

import (
	"path/filepath"
	"testing"
)

func TestVerifyCommandForBundle(t *testing.T) {
	work := t.TempDir()
	bundle := filepath.Join(work, "demo-refund.proof.tar.zst")
	if got := verifyCommandForBundle(work, bundle); got != "./demo-refund.proof.tar.zst" {
		t.Fatalf("got %q", got)
	}
	if got := verifyCommandForBundle(work, "/tmp/other.proof.tar.zst"); got != "/tmp/other.proof.tar.zst" {
		t.Fatalf("got %q", got)
	}
}
