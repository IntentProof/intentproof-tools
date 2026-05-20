package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunLocalCommandFailsOnBusyPort(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("INTENTPROOF_LOCAL_OPEN_BROWSER", "0")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	t.Setenv("INTENTPROOF_LOCAL_INGEST_ADDR", fmt.Sprintf("127.0.0.1:%d", port))
	t.Setenv("INTENTPROOF_LOCAL_VERIFIER_ADDR", "127.0.0.1:0")
	t.Setenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR", "127.0.0.1:0")
	defer occupied.Close()

	done := make(chan int, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- run([]string{"local"}, &stdout, &stderr)
	}()

	select {
	case code := <-done:
		if code == 0 {
			t.Fatal("expected local command failure")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("local command hung")
	}
}

func TestRunDemoRefundRunError(t *testing.T) {
	home := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(home, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CI", "1")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"demo", "refund"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected demo failure")
	}
	if !strings.Contains(stderr.String(), "demo refund:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunInitDetectFailure(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	if err := os.Remove(work); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"init"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected init failure")
	}
	if !strings.Contains(stderr.String(), "init failed:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunInitAgentUnknownTemplate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"init", "--agent", "--template", "nope"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "unknown init template") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunVerifyCommandFailStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.proof.tar.zst")
	if err := os.WriteFile(path, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", path}, &stdout, &stderr); code == 0 {
		t.Fatal("expected verify failure")
	}
}

func TestRunPolicyPublishServerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
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
		t.Fatal("expected publish failure")
	}
	if !strings.Contains(stderr.String(), "publish failed (500)") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyActivateServerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"policy", "activate", "tnt_x.demo", "1", "--scope", "global",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate failure")
	}
	if !strings.Contains(stderr.String(), "activate failed (500)") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
