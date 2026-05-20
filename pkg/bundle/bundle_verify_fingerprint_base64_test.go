package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

func TestVerifySignedMapAcceptsBase64Signature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := map[string]interface{}{"event_id": "e1", "action": "pay"}
	payload, err := canonicalSignedMap(ev, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	ev["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "inst1",
		"value": base64.StdEncoding.EncodeToString(sig),
	}
	b := &Bundle{PublicKeys: map[string][]byte{"inst1": pub}}
	findings, err := verifySignedMap(b, nil, "event", "signature", ev, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifyPassWithValidPolicyFingerprint(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	policyMap := map[string]interface{}{
		"policy_id": "p1", "tenant_id": "tnt", "policy_version": 1,
		"rules": []interface{}{},
	}
	fp, err := policysig.ComputeFingerprint(policyMap)
	if err != nil {
		t.Fatal(err)
	}
	policyMap["policy_fingerprint"] = fp
	policyJSON, err := json.Marshal(policyMap)
	if err != nil {
		t.Fatal(err)
	}
	opts := buildTestBundleOpts(t, priv)
	opts.PolicyJSON = policyJSON
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s reason=%s findings=%v", res.Status, res.Reason, res.Findings)
	}
	if !hasFinding(res.Findings, "policy.fingerprint_valid") {
		t.Fatalf("findings=%v", res.Findings)
	}
}

func TestIsEd25519HexSignatureDistinguishesEncodings(t *testing.T) {
	if isEd25519HexSignature(base64.StdEncoding.EncodeToString(make([]byte, 32))) {
		t.Fatal("base64 should not be treated as hex signature")
	}
	if !isEd25519HexSignature(hex.EncodeToString(make([]byte, ed25519.SignatureSize))) {
		t.Fatal("expected valid hex signature")
	}
}
