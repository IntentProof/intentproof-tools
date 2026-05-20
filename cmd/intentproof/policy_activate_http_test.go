package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyActivateUnexpectedArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"policy", "activate", "tnt_x.demo", "1",
		"--scope", "default", "extra",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestPolicyActivateEffectiveAtFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"policy", "activate", "tnt_eff.demo", "1",
		"--scope", "tenant",
		"--effective-at", "2026-06-01T12:00:00Z",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("activate: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "2026-06-01T12:00:00Z") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestPolicyActivateMissingScopeValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"policy", "activate", "tnt_x.demo", "1", "--scope",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
}

func TestPolicyActivateTenantIDRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"policy", "activate", ".", "1", "--scope", "s",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr.String(), "tenant_id is required") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
