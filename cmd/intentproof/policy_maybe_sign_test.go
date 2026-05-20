package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policy"
)

func TestMaybeSignPolicyWithoutSigner(t *testing.T) {
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", "")
	raw := []byte(`
policy_id: tnt_sign.demo
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
`)
	compiled, err := policy.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := maybeSignPolicy(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := body["signature"]; ok {
		t.Fatal("unexpected signature")
	}
}

func TestMaybeSignPolicyWithLocalSigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_KMS_KEY_ID", "")
	t.Setenv("INTENTPROOF_POLICY_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(priv))
	raw := []byte(`
policy_id: tnt_sign2.demo
tenant_id: tnt_sign2
policy_version: 1
spec_version: 1.0.0
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`)
	compiled, err := policy.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := maybeSignPolicy(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if body["signature"] == nil || body["signed_at"] == nil {
		t.Fatalf("body=%v", body)
	}
}
