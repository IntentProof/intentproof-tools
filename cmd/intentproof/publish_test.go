package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

func TestPolicyPublishCommandMissingFile(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := run([]string{"policy", "publish"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage output, got %s", stderr.String())
	}
}

func TestPolicyPublishCommandInvalidYAML(t *testing.T) {
	tmp := t.TempDir()
	badPath := filepath.Join(tmp, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("not: valid: [yaml"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "publish", badPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "compile failed") {
		t.Fatalf("expected compile error, got %s", stderr.String())
	}
}

func TestPolicyPublishCommandSuccess(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/policies" {
			t.Fatalf("expected /v1/policies, got %s", r.URL.Path)
		}
		var req struct {
			TenantID      string `json:"tenant_id"`
			PolicyID      string `json:"policy_id"`
			PolicyVersion int    `json:"policy_version"`
			Body          any    `json:"body"`
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
		if req.PolicyVersion != 1 {
			t.Fatalf("unexpected policy_version: %d", req.PolicyVersion)
		}
		if req.Body == nil {
			t.Fatal("expected non-nil body")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "published tnt_acme.refund-flow v1") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestPolicyPublishCommandServerRejection(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "policy signature is required", http.StatusBadRequest)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "policy signature is required") {
		t.Fatalf("expected signature error, got %s", stderr.String())
	}
}

func TestPolicyPublishCommandWithSigning(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_ID", "test:k1")

	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var capturedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Body json.RawMessage `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if err := json.Unmarshal(req.Body, &capturedBody); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected code 0, got %d stderr=%s", code, stderr.String())
	}

	if capturedBody == nil {
		t.Fatal("expected captured body")
	}
	sigRaw, ok := capturedBody["signature"]
	if !ok {
		t.Fatal("expected signature in published body")
	}
	sigMap, ok := sigRaw.(map[string]any)
	if !ok {
		t.Fatalf("signature should be object, got %T", sigRaw)
	}
	if sigMap["alg"] != "ed25519" {
		t.Fatalf("expected alg ed25519, got %v", sigMap["alg"])
	}
	if sigMap["key_id"] != "test:k1" {
		t.Fatalf("expected key_id test:k1, got %v", sigMap["key_id"])
	}
	if sigMap["value"] == "" {
		t.Fatal("expected non-empty signature value")
	}
	if capturedBody["signed_at"] == nil {
		t.Fatal("expected signed_at in published body")
	}

	// Verify the signature cryptographically.
	delete(capturedBody, "signature")
	delete(capturedBody, "signed_at")
	payload, err := policysig.BuildPolicySignPayload(capturedBody)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	digest := crypto.DigestSHA256(payload)
	sigValue, _ := sigMap["value"].(string)
	sigBytes, err := base64.StdEncoding.DecodeString(sigValue)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, digest, sigBytes) {
		t.Fatal("signature verification failed")
	}
}

func TestPolicyPublishCommandServerError(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
policy_id: tnt_acme.refund-flow
tenant_id: tnt_acme
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: payments.stripe.refunds.create
rules:
  - id: r1
    type: required
    action: payments.stripe.refunds.create
    min: 1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("database unavailable"))
	}))
	defer server.Close()

	t.Setenv("INTENTPROOF_QUERY_API_URL", server.URL)

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"policy", "publish", policyPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero code")
	}
	if !strings.Contains(stderr.String(), "database unavailable") {
		t.Fatalf("expected server error, got %s", stderr.String())
	}
}
