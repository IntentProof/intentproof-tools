package demo

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatFindingCopyDescriptionOnly(t *testing.T) {
	out := FormatFindingCopy(ReasonCopy{
		Code:        "fail.required.missing",
		Title:       "Title only",
		Description: "Title only",
	})
	if !strings.Contains(out, "Title only") {
		t.Fatalf("out=%q", out)
	}
}

func TestPostStripeDemoError(t *testing.T) {
	orig := refundPostStripeDemo
	defer func() { refundPostStripeDemo = orig }()
	refundPostStripeDemo = func(_ *attestMemoryStore, _ ed25519.PrivateKey, _ RefundScenario, _ time.Time) error {
		return fmt.Errorf("stripe down")
	}
	err := RunRefund(t.Context(), Options{
		HomeDir:        t.TempDir(),
		WorkDir:        t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "stripe@demo") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadReasonCopyBadCatalog(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	if err := os.MkdirAll(demoRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "semantics"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "semantics", "reasons.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadReasonCopy("fail.required.missing"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGoldenDemoRootRelativeEnv(t *testing.T) {
	spec := filepath.Join("..", "..", "..", "intentproof-spec")
	if _, err := os.Stat(filepath.Join(spec, "golden", "demo")); err != nil {
		t.Skip("spec not present")
	}
	abs, err := filepath.Abs(spec)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Join(abs, "..", "intentproof-tools"), abs)
	if err != nil {
		t.Setenv("INTENTPROOF_SPEC_DIR", abs)
	} else {
		t.Setenv("INTENTPROOF_SPEC_DIR", rel)
	}
	if _, err := GoldenDemoRoot(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRefundScenarioMissingPolicy(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	scenarios := filepath.Join(demoRoot, "scenarios")
	stripeDir := filepath.Join(demoRoot, "stripe")
	for _, dir := range []string{scenarios, stripeDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(scenarios, "refund.json"), []byte(`{
  "happy_path":{"correlation_id":"a","actions":["x"],"stripe_demo":false},
  "divergent_path":{"correlation_id":"b","actions":["x"],"stripe_demo":false}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stripeDir, "refund-created.bytes"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stripeDir, "refund-created.headers.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected missing policy error")
	}
}
