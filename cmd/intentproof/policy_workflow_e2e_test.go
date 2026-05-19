package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyPublishToMockAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_acme.demo
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("publish: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "published") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestPolicyTestWithFixtureDir(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.yaml")
	fixDir := filepath.Join(root, "fixtures", "pass")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_fix.demo
tenant_id: tnt_fix
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "flow.json"), []byte(`{
  "flow_id":"f1","tenant_id":"tnt_fix","flow_merkle_root":"sha256:00",
  "events":[{"event_id":"e1","action":"demo.action","status":"ok",
    "started_at":"2026-05-16T00:00:00Z","completed_at":"2026-05-16T00:00:01Z"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixDir, "attestations.jsonl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("policy test: %s", stderr.String())
	}
}

func TestPolicyDiffAndActivateSmoke(t *testing.T) {
	dir := t.TempDir()
	policyA := filepath.Join(dir, "a.yaml")
	policyB := filepath.Join(dir, "b.yaml")
	body := `policy_id: tnt_diff.demo
tenant_id: tnt_diff
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`
	if err := os.WriteFile(policyA, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bodyB := strings.Replace(body, "policy_version: 1", "policy_version: 2", 1)
	if err := os.WriteFile(policyB, []byte(bodyB), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "diff", policyA, policyB}, &stdout, &stderr); code != 1 {
		t.Fatalf("diff expected exit 1 when policies differ, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy_version") {
		t.Fatalf("diff stdout=%s", stdout.String())
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy-bindings" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"policy", "activate", "tnt_diff.demo", "2",
		"--scope", "tenant", "--tenant-id", "tnt_diff",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("activate: %s", stderr.String())
	}
}
