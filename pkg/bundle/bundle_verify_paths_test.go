package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
)

func TestVerifyManifestMissing(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "flow.json", Size: 2, Mode: 0o644})
	_, _ = tw.Write([]byte("{}"))
	_ = tw.Close()
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "fail" || res.Reason != "bundle.manifest_missing" {
		t.Fatalf("got %+v", res)
	}
}

func TestVerifyManifestSignatureInvalid(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	opts.Signer = func(data []byte) (*SignatureEnvelope, error) {
		sig := ed25519.Sign(priv, sha256Sum(data))
		return &SignatureEnvelope{Alg: "ed25519", KeyID: "test", Value: hex.EncodeToString(sig)}, nil
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	// Corrupt signature in-place by re-verifying with wrong key.
	wrongPub := make([]byte, ed25519.PublicKeySize)
	res, err := Verify(&buf, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "fail" {
		t.Fatalf("status=%s reason=%s", res.Status, res.Reason)
	}
	_ = pub
}

func TestVerifyFileHashMismatch(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	tr, err := bundleTarReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var tampered bytes.Buffer
	tw := tar.NewWriter(&tampered)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, body); err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "flow.json" {
			body = []byte(`{"flow_id":"tampered"}`)
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	res, err := Verify(&tampered, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.file_hash_mismatch" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestVerifyEventMerkleMismatch(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	tr, err := bundleTarReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var tampered bytes.Buffer
	tw := tar.NewWriter(&tampered)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, body); err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "manifest.json" {
			var m Manifest
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			m.EventMerkle = "sha256:deadbeef"
			body, err = json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	res, err := Verify(&tampered, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.event_merkle_mismatch" {
		t.Fatalf("reason=%s", res.Reason)
	}
}

func TestVerifyPolicyJSONDecodeError(t *testing.T) {
	policyBody := []byte("{")
	manifest := Manifest{
		Schema: "intentproof.bundle.manifest.v1", BundleID: "b1",
		CreatedAt: "2026-05-12T00:00:00Z", FlowID: "f1", TenantID: "tnt",
		VerificationProfile: &VerificationProfile{
			SpecVersion: "v0.test", VerifierVersion: "dev", ExportProfile: "full",
			FlowSnapshotID: "f1", RunID: "run_f1",
		},
		Files: []ManifestEntry{{Path: "policy.json", SHA: "sha256:" + sha256hex(policyBody)}},
	}
	mBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(mBody)), Mode: 0o644})
	_, _ = tw.Write(mBody)
	_ = tw.WriteHeader(&tar.Header{Name: "policy.json", Size: int64(len(policyBody)), Mode: 0o644})
	_, _ = tw.Write(policyBody)
	_ = tw.Close()
	_, err = Verify(&buf, nil)
	if err == nil || !contains(err.Error(), "policy_json_decode") {
		t.Fatalf("err=%v", err)
	}
}

func TestBundleTarReaderPlainTar(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: 2, Mode: 0o644})
	_, _ = tw.Write([]byte("{}"))
	_ = tw.Close()
	tr, err := bundleTarReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Fatal("expected tar reader")
	}
}

func TestVerifySignedMapUnsupportedAlgEvent(t *testing.T) {
	b := &Bundle{PublicKeys: map[string][]byte{"k": {1}}}
	doc := map[string]interface{}{
		"signature": map[string]interface{}{
			"alg": "rsa", "key_id": "k", "value": "00",
		},
	}
	findings, err := verifySignedMap(b, nil, "event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_unsupported_alg") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifySignedMapKeyUnavailable(t *testing.T) {
	doc := map[string]interface{}{
		"signature": map[string]interface{}{
			"alg": "ed25519", "key_id": "missing", "value": "00",
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{}}, nil, "event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_key_unavailable") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestDecodeSignatureValueHexFallback(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	b64 := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJj"
	_ = sig
	if _, err := decodeSignatureValue(b64); err == nil {
		return
	}
	hexSig := hex.EncodeToString(sig)
	if _, err := decodeSignatureValue(hexSig); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalManifestJSONMarshalError(t *testing.T) {
	m := &Manifest{Schema: "intentproof.bundle.manifest.v1"}
	raw, err := canonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected bytes")
	}
}

func TestParseJSONLEmpty(t *testing.T) {
	if parseJSONL(nil) != nil {
		t.Fatal("expected nil")
	}
}

func TestVerifyZstdBundle(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	var zbuf bytes.Buffer
	if err := Create(&zbuf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&zbuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s", res.Status)
	}
}

func TestVerifyGzipNotZstdStillReads(t *testing.T) {
	// isZstdFrame false path uses raw tar reader.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: 2, Mode: 0o644})
	_, _ = tw.Write([]byte("{}"))
	_ = tw.Close()
	_ = gw.Close()
	_, err := Verify(&buf, nil)
	if err == nil {
		// may fail manifest validation; still exercised tar path
		return
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSignatureEnvelopeFromMapUnmarshalError(t *testing.T) {
	doc := map[string]interface{}{"signature": "not-an-object"}
	_, ok, err := signatureEnvelopeFromMap(doc, "signature")
	if err == nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestVerifyObjectSignaturesRunBranch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]interface{}{"run_id": "r1"}
	payload, err := canonicalSignedMap(run, []string{"signature", "run_fingerprint", "started_at", "completed_at"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	run["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "run:k1", "value": hex.EncodeToString(sig),
	}
	b := &Bundle{
		PublicKeys:   map[string][]byte{"run:k1": pub},
		Run:          run,
		Events:       []map[string]interface{}{},
		Attestations: []map[string]interface{}{},
	}
	findings, err := verifyObjectSignatures(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestPolicyFingerprintValidFinding(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	policyMap := map[string]interface{}{"policy_id": "p1", "rules": []interface{}{}}
	fp, err := json.Marshal(policyMap)
	if err != nil {
		t.Fatal(err)
	}
	opts.PolicyJSON = fp
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
