package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestRunPolicyLintSuccess(t *testing.T) {
	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("lint failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema: OK") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "fingerprint:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunPolicyPublishSuccessNoSigner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("publish: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "published") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestRunPolicyDiffSuccess(t *testing.T) {
	left := writeMinimalPolicyYAML(t)
	rightDir := t.TempDir()
	right := filepath.Join(rightDir, "policy.yaml")
	body, err := os.ReadFile(left)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, body, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "diff", left, right}, &stdout, &stderr); code != 0 {
		t.Fatalf("diff: %s", stderr.String())
	}
}

func TestRunVerifyBundleFailStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.proof.tar.zst")
	if err := os.WriteFile(path, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestRunVerifyBundlePassOutputsJSON(t *testing.T) {
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
		t.Fatalf("verify: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}
