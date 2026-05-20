package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestRunVerifyMarshalResultFailure(t *testing.T) {
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

	orig := verifyCmdJSONMarshalIndent
	verifyCmdJSONMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { verifyCmdJSONMarshalIndent = orig })

	var stdout, stderr bytes.Buffer
	if code := runVerify([]string{path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "marshal result:") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
