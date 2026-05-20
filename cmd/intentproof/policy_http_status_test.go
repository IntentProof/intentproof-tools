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

func TestRunPolicyPublishBadRequestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("rejected"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
policy_id: tnt_x.demo
tenant_id: tnt_x
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
	if code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr); code == 0 {
		t.Fatal("expected publish rejection")
	}
	if !strings.Contains(stderr.String(), "publish rejected") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyActivateBadRequestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("rejected"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"policy", "activate", "tnt_x.demo", "1", "--scope", "global",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate rejection")
	}
	if !strings.Contains(stderr.String(), "activate rejected") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyTestCompileFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("not: valid: yaml: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "case1"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "test", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected compile failure")
	}
	if !strings.Contains(stderr.String(), "policy compile failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyDiffCompileRightFailure(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left.yaml")
	right := filepath.Join(dir, "right.yaml")
	if err := os.WriteFile(left, []byte(`
policy_id: tnt_x.demo
tenant_id: tnt_x
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
	if err := os.WriteFile(right, []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "diff", left, right}, &stdout, &stderr); code == 0 {
		t.Fatal("expected diff failure")
	}
	if !strings.Contains(stderr.String(), "compile right failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
