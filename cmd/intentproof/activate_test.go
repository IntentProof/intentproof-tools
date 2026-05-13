package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyActivateCommandMissingArgs(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage output, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandInvalidVersion(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate", "tnt_acme.policy", "abc", "--scope", "default"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "invalid policy version") {
		t.Fatalf("expected version error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandMissingScope(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate", "tnt_acme.policy", "1"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "--scope is required") {
		t.Fatalf("expected scope error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandInvalidEffectiveAt(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate", "tnt_acme.policy", "1", "--scope", "default", "--effective-at", "not-a-time"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "invalid effective-at") {
		t.Fatalf("expected time error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandMissingEffectiveAtValue(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate", "tnt_acme.policy", "1", "--scope", "default", "--effective-at"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "--effective-at requires a value") {
		t.Fatalf("expected missing value error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandUnknownFlag(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "activate", "tnt_acme.policy", "1", "--scope", "default", "--unknown-flag"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "unknown flag: --unknown-flag") {
		t.Fatalf("expected unknown flag error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/policy-bindings" {
			t.Fatalf("expected /v1/policy-bindings, got %s", r.URL.Path)
		}
		var req struct {
			TenantID      string `json:"tenant_id"`
			Scope         string `json:"scope"`
			PolicyID      string `json:"policy_id"`
			PolicyVersion int    `json:"policy_version"`
			EffectiveAt   string `json:"effective_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.TenantID != "tnt_acme" {
			t.Fatalf("unexpected tenant_id: %s", req.TenantID)
		}
		if req.PolicyID != "tnt_acme.refund-flow" {
			t.Fatalf("unexpected policy_id: %s", req.PolicyID)
		}
		if req.PolicyVersion != 2 {
			t.Fatalf("unexpected policy_version: %d", req.PolicyVersion)
		}
		if req.Scope != "default" {
			t.Fatalf("unexpected scope: %s", req.Scope)
		}
		if req.EffectiveAt == "" {
			t.Fatal("expected non-empty effective_at")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "activate", "tnt_acme.refund-flow", "2", "--scope", "default"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "activated tnt_acme.refund-flow v2 for scope \"default\"") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestPolicyActivateCommandWithTenantIDOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.TenantID != "override_tenant" {
			t.Fatalf("unexpected tenant_id: %s", req.TenantID)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "activate", "some.policy", "1", "--scope", "default", "--tenant-id", "override_tenant"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
}

func TestPolicyActivateCommandServerRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "policy version not found", http.StatusBadRequest)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "activate", "tnt_acme.policy", "99", "--scope", "default"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "policy version not found") {
		t.Fatalf("expected version not found error, got %s", stderr.String())
	}
}

func TestPolicyActivateCommandServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("database timeout"))
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "activate", "tnt_acme.policy", "1", "--scope", "default"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "database timeout") {
		t.Fatalf("expected server error, got %s", stderr.String())
	}
}
