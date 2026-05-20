package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCreateAndVerifyWithInclusionProofAndCertificate(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	opts := buildTestBundleOpts(t, priv)
	opts.CertificateJSON = []byte(`{"certificate_id":"cert1","schema":"intentproof.certificate.v1"}`)
	opts.InclusionProof = []byte(`{"proof_id":"p1","leaves":[]}`)
	opts.PublicKeys = map[string][]byte{"inst1": pub}
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
}
