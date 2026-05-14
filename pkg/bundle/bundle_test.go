package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/canon"
)

func TestBundleRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	opts := buildTestBundleOpts(t, priv)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass, got %s: %s", res.Status, res.Reason)
	}
	wantFindings := []string{
		"manifest.signature_valid",
		"file_hash_valid:flow.json",
		"file_hash_valid:events.jsonl",
		"file_hash_valid:attestations.jsonl",
		"file_hash_valid:policy.json",
		"file_hash_valid:run.json",
		"event_merkle_valid",
		"attestation_merkle_valid",
		"bundle.verify_pass",
	}
	for _, wf := range wantFindings {
		if !hasFinding(res.Findings, wf) {
			t.Fatalf("expected finding %q, got %v", wf, res.Findings)
		}
	}
}

func TestCanonicalManifestJSON_Hash(t *testing.T) {
	m := &Manifest{
		Schema:    "intentproof.bundle.manifest.v1",
		BundleID:  "bundle_f1",
		CreatedAt: "2026-05-12T00:00:00Z",
		FlowID:    "f1",
		TenantID:  "tnt",
		Files:     []ManifestEntry{{Path: "flow.json", SHA: "sha256:abc"}},
		EventMerkle: "sha256:def",
		AttMerkle:   "sha256:ghi",
	}
	canonical, err := canonicalManifestJSON(m)
	if err != nil {
		t.Fatalf("canonicalManifestJSON: %v", err)
	}
	wantHash := "d23ef437013795a52f1f27347f5c2c2eaf08f9e681279e302ca5168049f7ef2a"
	gotHash := hex.EncodeToString(sha256Sum(canonical))
	if gotHash != wantHash {
		t.Fatalf("manifest canonical hash mismatch: want %s, got %s", wantHash, gotHash)
	}

	// Verify canon.Marshal produces identical bytes for the same input.
	m2 := &Manifest{
		Schema:    "intentproof.bundle.manifest.v1",
		BundleID:  "bundle_f1",
		CreatedAt: "2026-05-12T00:00:00Z",
		FlowID:    "f1",
		TenantID:  "tnt",
		Files:     []ManifestEntry{{Path: "flow.json", SHA: "sha256:abc"}},
		EventMerkle: "sha256:def",
		AttMerkle:   "sha256:ghi",
	}
	raw, err := json.Marshal(m2)
	if err != nil {
		t.Fatalf("json.Marshal manifest: %v", err)
	}
	var tmp map[string]interface{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		t.Fatalf("json.Unmarshal manifest: %v", err)
	}
	delete(tmp, "signature")
	canonBytes, err := canon.Marshal(tmp)
	if err != nil {
		t.Fatalf("canon.Marshal: %v", err)
	}
	if !bytes.Equal(canonical, canonBytes) {
		t.Fatalf("canonicalManifestJSON drift from canon.Marshal")
	}
}

func TestVerifyMissingManifest(t *testing.T) {
	var buf bytes.Buffer
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" {
		t.Fatalf("expected fail, got %s", res.Status)
	}
	if res.Reason != "bundle.manifest_missing" {
		t.Fatalf("expected manifest_missing, got %s", res.Reason)
	}
}

func TestVerifyTamperedFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	opts := buildTestBundleOpts(t, priv)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Tamper: replace "pass" with "FAIL" in the tar bytes.
	tarBytes := bytes.Replace(buf.Bytes(), []byte(`"status":"pass"`), []byte(`"status":"FAIL"`), 1)

	res, err := Verify(bytes.NewReader(tarBytes), pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" {
		t.Fatalf("expected fail, got %s", res.Status)
	}
	if !strings.Contains(res.Reason, "file_hash_mismatch") {
		t.Fatalf("expected file_hash_mismatch, got %s", res.Reason)
	}
	// Signature should still be valid (checked before file hashes).
	if !hasFinding(res.Findings, "manifest.signature_valid") {
		t.Fatalf("expected signature_valid before hash failure, findings: %v", res.Findings)
	}
}

func TestVerifyTamperedEventMerkle(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	opts := buildTestBundleOpts(t, priv)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	b := mustExtractBundle(t, &buf)
	b.Manifest.EventMerkle = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	b.Manifest.Signature = nil
	resignManifest(t, b, priv)

	var tampered bytes.Buffer
	if err := writeBundle(&tampered, b); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}

	res, err := Verify(&tampered, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" {
		t.Fatalf("expected fail, got %s", res.Status)
	}
	if res.Reason != "bundle.event_merkle_mismatch" {
		t.Fatalf("expected event_merkle_mismatch, got %s", res.Reason)
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub := wrongPriv.Public().(ed25519.PublicKey)

	opts := buildTestBundleOpts(t, priv)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, wrongPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" {
		t.Fatalf("expected fail, got %s", res.Status)
	}
	if res.Reason != "bundle.signature_invalid" {
		t.Fatalf("expected signature_invalid, got %s", res.Reason)
	}
}

func TestVerifyUnsignedBundle(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass for unsigned bundle, got %s: %s", res.Status, res.Reason)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildTestBundleOpts(t *testing.T, signerPriv ed25519.PrivateKey) CreateOptions {
	t.Helper()
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":   "f1",
		"tenant_id": "tnt",
		"events":    []string{"e1", "e2"},
	})
	eventsJSONL := []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n" +
		`{"event_id":"e2","action":"refund","status":"ok"}`)
	attsJSONL := []byte(`{"attestation_id":"a1","claim":"refund.ok","claim_value":true}`)
	policyJSON, _ := json.Marshal(map[string]interface{}{
		"policy_id": "p1",
		"rules":     []interface{}{},
	})
	runJSON, _ := json.Marshal(map[string]interface{}{
		"run_id":   "run_f1",
		"flow_id":  "f1",
		"status":   "pass",
		"findings": []interface{}{},
	})

	opts := CreateOptions{
		BundleID:          "bundle_f1",
		FlowID:            "f1",
		TenantID:          "tnt",
		FlowJSON:          flowJSON,
		EventsJSONL:       eventsJSONL,
		AttestationsJSONL: attsJSONL,
		PolicyJSON:        policyJSON,
		RunJSON:           runJSON,
	}

	if signerPriv != nil {
		opts.Signer = func(data []byte) (*SignatureEnvelope, error) {
			sig := ed25519.Sign(signerPriv, sha256Sum(data))
			return &SignatureEnvelope{
				Alg:   "ed25519",
				KeyID: "test",
				Value: hex.EncodeToString(sig),
			}, nil
		}
	}

	return opts
}

func hasFinding(findings []string, needle string) bool {
	for _, f := range findings {
		if f == needle {
			return true
		}
	}
	return false
}

func sha256Sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

func mustExtractBundle(t *testing.T, r io.Reader) *Bundle {
	t.Helper()
	tr := tar.NewReader(r)
	b := &Bundle{PublicKeys: map[string][]byte{}, RawFiles: map[string][]byte{}}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, tr); err != nil {
			t.Fatalf("tar copy: %v", err)
		}
		body := buf.Bytes()
		b.RawFiles[hdr.Name] = body
		switch hdr.Name {
		case "manifest.json":
			if err := json.Unmarshal(body, &b.Manifest); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}
		case "flow.json":
			json.Unmarshal(body, &b.Flow)
		case "events.jsonl":
			b.Events = parseJSONL(body)
		case "attestations.jsonl":
			b.Attestations = parseJSONL(body)
		case "policy.json":
			json.Unmarshal(body, &b.Policy)
		case "run.json":
			json.Unmarshal(body, &b.Run)
		case "certificate.json":
			json.Unmarshal(body, &b.Certificate)
		case "inclusion_proof.json":
			json.Unmarshal(body, &b.InclusionProof)
		default:
			if strings.HasPrefix(hdr.Name, "keys/") && strings.HasSuffix(hdr.Name, ".pub") {
				keyID := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "keys/"), ".pub")
				b.PublicKeys[keyID] = body
			}
		}
	}
	return b
}

func writeBundle(w io.Writer, b *Bundle) error {
	// Start with original raw bytes for everything except manifest,
	// which we re-serialize because we modified it.
	files := make(map[string][]byte, len(b.RawFiles))
	for k, v := range b.RawFiles {
		files[k] = v
	}
	manifestJSON, _ := json.Marshal(b.Manifest)
	files["manifest.json"] = manifestJSON

	tw := tar.NewWriter(w)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}
	return tw.Close()
}

func resignManifest(t *testing.T, b *Bundle, priv ed25519.PrivateKey) {
	t.Helper()
	canonical, err := canonicalManifestJSON(b.Manifest)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, sha256Sum(canonical))
	b.Manifest.Signature = &SignatureEnvelope{
		Alg:   "ed25519",
		KeyID: "test",
		Value: hex.EncodeToString(sig),
	}
}

func jsonOrEmpty(v map[string]interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
