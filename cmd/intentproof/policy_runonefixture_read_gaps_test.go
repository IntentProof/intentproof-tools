package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunOneFixtureReadExpectedPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"flow.json":          `{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0","events":[]}`,
		"attestations.jsonl": "",
		"expected-run.json":  `{"status":"pass","findings":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "expected-run.json"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(dir, "expected-run.json"), 0o644)
	})

	_, _, err := runOneFixture(dir, []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`))
	if err == nil || !strings.Contains(err.Error(), "expected-run.json") {
		t.Fatalf("err=%v", err)
	}
}
