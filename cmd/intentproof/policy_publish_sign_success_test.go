package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunPolicyPublishWithLocalSignerSuccess(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))

	dir := writeMinimalPolicyYAML(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "publish", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("publish failed: %s", stderr.String())
	}
}

func TestRunPolicyActivateGlobalScopeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "2", "--scope", "global"}, &stdout, &stderr); code != 0 {
		t.Fatalf("activate failed: %s", stderr.String())
	}
}

func TestRunPolicyLintMissingPolicyFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "lint", "/no/such/policy.yaml"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected lint failure")
	}
}
