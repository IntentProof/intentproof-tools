package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyPublishRejectsBadRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid policy body", http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code == 0 {
		t.Fatalf("expected failure stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid policy body") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestPolicyPublishServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "upstream down") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestPolicyPublishWithLocalSigner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("publish: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "published") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func writeMinimalPolicyYAML(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := `policy_id: tnt_pub.demo
tenant_id: tnt_pub
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
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
