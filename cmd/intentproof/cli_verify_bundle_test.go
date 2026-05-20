package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestRunVerifyBundlePass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.proof.tar.zst")
	var buf bytes.Buffer
	flowJSON, _ := json.Marshal(map[string]any{
		"flow_id": "f1", "tenant_id": "tnt", "events": []any{},
	})
	if err := bundle.Create(&buf, bundle.CreateOptions{
		BundleID:    "b1",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    flowJSON,
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		PublicKeys:  map[string][]byte{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestRunVerifyMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", filepath.Join(t.TempDir(), "missing.tar.zst")}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}
