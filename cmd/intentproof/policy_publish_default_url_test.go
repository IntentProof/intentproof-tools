package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitForDefaultPolicyAPI(t *testing.T, path string) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	url := "http://127.0.0.1:8090" + path
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("default policy API not ready on :8090")
}

func TestRunPolicyPublishUsesDefaultLocalhostAPI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8090")
	if err != nil {
		t.Skip("127.0.0.1:8090 unavailable:", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	waitForDefaultPolicyAPI(t, "/v1/policies")

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`policy_id: tnt_def.demo
tenant_id: tnt_def
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
	t.Setenv("INTENTPROOF_QUERY_API_URL", "")
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	var stdout, stderr bytes.Buffer
	if code := runPolicyPublish([]string{policyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("publish failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "published tnt_def.demo") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunPolicyActivateUsesDefaultLocalhostAPI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8090")
	if err != nil {
		t.Skip("127.0.0.1:8090 unavailable:", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy-bindings" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	waitForDefaultPolicyAPI(t, "/v1/policy-bindings")

	t.Setenv("INTENTPROOF_QUERY_API_URL", "")
	var stdout, stderr bytes.Buffer
	if code := runPolicyActivate([]string{
		"tnt_def.demo", "1", "--scope", "global", "--tenant-id", "tnt_def",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("activate failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "activated tnt_def.demo") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
