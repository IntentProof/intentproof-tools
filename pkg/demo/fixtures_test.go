package demo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRefundScenarioInvalidJSON(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	scenarios := filepath.Join(demoRoot, "scenarios")
	if err := os.MkdirAll(scenarios, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenarios, "refund.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAttestationsJSONLEmptyStore(t *testing.T) {
	if got := newAttestMemoryStore().attestationsJSONL(); len(got) != 0 {
		t.Fatalf("got=%q", got)
	}
}

func TestLoadRefundScenarioMissingStripeBytes(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	scenarios := filepath.Join(demoRoot, "scenarios")
	policyDir := filepath.Join(demoRoot, "policies")
	for _, dir := range []string{scenarios, policyDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(scenarios, "refund.json"), []byte(`{
  "happy_path":{"correlation_id":"a","actions":["x"]},
  "divergent_path":{"correlation_id":"b","actions":["x"]}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "refund-with-notification.yaml"), []byte("rules: []"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected missing stripe bytes error")
	}
}
