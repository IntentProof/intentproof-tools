package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyPublishSignerInitFailure(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`policy_id: tnt_sign.demo
tenant_id: tnt_sign
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "alias/unconfigured")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	var stdout, stderr bytes.Buffer
	if code := runPolicyPublish([]string{policyPath}, &stdout, &stderr); code == 0 {
		t.Fatal("expected sign failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("sign failed")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
