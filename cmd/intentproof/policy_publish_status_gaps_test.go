package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestRunPolicyPublishInternalServerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("expected publish failure")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("publish failed (500)")) {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestMaybeSignPolicySignSuccessWithLocalSigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))
	compiled, err := policy.Compile([]byte(`
policy_id: tnt_signed.demo
tenant_id: tnt_signed
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := maybeSignPolicy(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if body["signature"] == nil {
		t.Fatal("expected signature in body")
	}
}

func TestRunPolicyLintCompileFileError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", "/no/such/policy.yaml"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected lint compile failure")
	}
}
