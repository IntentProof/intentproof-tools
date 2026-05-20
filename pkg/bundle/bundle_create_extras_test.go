package bundle

import (
	"bytes"
	"testing"
)

func TestCreateWithCertificateAndInclusionProof(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.CertificateJSON = []byte(`{"schema":"intentproof.certificate.v1"}`)
	opts.InclusionProof = []byte(`{"proof":"demo"}`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s findings=%v", res.Status, res.Findings)
	}
}

func TestCanonicalManifestJSONStripsSignature(t *testing.T) {
	m := &Manifest{
		Schema:    "intentproof.bundle.manifest.v1",
		BundleID:  "b1",
		CreatedAt: "2026-05-12T00:00:00Z",
		FlowID:    "f1",
		TenantID:  "tnt",
		Signature: &SignatureEnvelope{Alg: "ed25519", KeyID: "k", Value: "sig"},
	}
	raw, err := canonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("signature")) {
		t.Fatalf("signature should be stripped: %s", raw)
	}
}
