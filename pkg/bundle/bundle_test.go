package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/canon"
	"github.com/klauspost/compress/zstd"
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
	if !isZstdFrame(buf.Bytes()) {
		t.Fatalf("expected Create to emit zstd-compressed tar")
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
		Schema:      "intentproof.bundle.manifest.v1",
		BundleID:    "bundle_f1",
		CreatedAt:   "2026-05-12T00:00:00Z",
		FlowID:      "f1",
		TenantID:    "tnt",
		Files:       []ManifestEntry{{Path: "flow.json", SHA: "sha256:abc"}},
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
		Schema:      "intentproof.bundle.manifest.v1",
		BundleID:    "bundle_f1",
		CreatedAt:   "2026-05-12T00:00:00Z",
		FlowID:      "f1",
		TenantID:    "tnt",
		Files:       []ManifestEntry{{Path: "flow.json", SHA: "sha256:abc"}},
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

	b := mustExtractBundle(t, &buf)
	b.RawFiles["run.json"] = bytes.Replace(b.RawFiles["run.json"], []byte(`"status":"pass"`), []byte(`"status":"FAIL"`), 1)
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

func TestVerifyPlainTarBackCompat(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	var compressed bytes.Buffer
	if err := Create(&compressed, buildTestBundleOpts(t, priv)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	b := mustExtractBundle(t, &compressed)

	var plain bytes.Buffer
	if err := writeBundlePlainTar(&plain, b); err != nil {
		t.Fatalf("writeBundlePlainTar: %v", err)
	}
	if isZstdFrame(plain.Bytes()) {
		t.Fatalf("expected plain tar fixture, got zstd")
	}

	res, err := Verify(&plain, pub)
	if err != nil {
		t.Fatalf("Verify plain tar: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass, got %s: %s", res.Status, res.Reason)
	}
}

func TestVerifyEmbeddedObjectSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	event := map[string]interface{}{
		"event_id": "e1",
		"action":   "pay",
		"status":   "ok",
	}
	signMap(t, event, "signature", priv, "object:k1", []string{"signature"})

	attestation := map[string]interface{}{
		"attestation_id": "a1",
		"claim":          "refund.ok",
		"claim_value":    true,
	}
	signMap(t, attestation, "platform_signature", priv, "object:k1", []string{"platform_signature"})

	run := map[string]interface{}{
		"run_id":          "run_f1",
		"flow_id":         "f1",
		"status":          "pass",
		"started_at":      "2026-05-12T00:00:00Z",
		"completed_at":    "2026-05-12T00:00:01Z",
		"findings":        []interface{}{},
		"run_fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	signMap(t, run, "signature", priv, "object:k1", []string{
		"signature",
		"run_fingerprint",
		"started_at",
		"completed_at",
	})

	certificate := map[string]interface{}{
		"certificate_id": "cert_f1",
		"run_id":         "run_f1",
		"issued_at":      "2026-05-12T00:00:02Z",
	}
	signMap(t, certificate, "signature", priv, "object:k1", []string{"signature"})

	opts := buildTestBundleOpts(t, nil)
	opts.EventsJSONL = jsonlBytes([]map[string]interface{}{event})
	opts.AttestationsJSONL = jsonlBytes([]map[string]interface{}{attestation})
	opts.RunJSON = jsonOrEmpty(run)
	opts.CertificateJSON = jsonOrEmpty(certificate)
	opts.PublicKeys = map[string][]byte{"object:k1": pub}

	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass, got %s: %s findings=%v", res.Status, res.Reason, res.Findings)
	}
	for _, want := range []string{
		"event.signature_valid",
		"attestation.signature_valid",
		"run.signature_valid",
		"certificate.signature_valid",
	} {
		if !hasFinding(res.Findings, want) {
			t.Fatalf("expected %q, findings=%v", want, res.Findings)
		}
	}
}

func TestVerifyEmbeddedObjectSignatureInvalid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	event := map[string]interface{}{
		"event_id": "e1",
		"action":   "pay",
		"status":   "ok",
	}
	signMap(t, event, "signature", priv, "object:k1", []string{"signature"})
	event["action"] = "tampered"

	opts := buildTestBundleOpts(t, nil)
	opts.EventsJSONL = jsonlBytes([]map[string]interface{}{event})
	opts.PublicKeys = map[string][]byte{"object:k1": pub}

	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" || res.Reason != "bundle.object_signature_invalid" {
		t.Fatalf("expected object signature failure, got status=%s reason=%s findings=%v",
			res.Status, res.Reason, res.Findings)
	}
	if !hasFinding(res.Findings, "event.signature_invalid") {
		t.Fatalf("expected event.signature_invalid, findings=%v", res.Findings)
	}
}

func TestVerifyEmbeddedHexObjectSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	event := map[string]interface{}{
		"event_id": "e1",
		"action":   "pay",
		"status":   "ok",
	}
	payload, err := canonicalSignedMap(event, []string{"signature"})
	if err != nil {
		t.Fatalf("canonical signed map: %v", err)
	}
	event["signature"] = map[string]interface{}{
		"alg":    "ed25519",
		"key_id": "object:k1",
		"value":  hex.EncodeToString(ed25519.Sign(priv, sha256Sum(payload))),
	}

	opts := buildTestBundleOpts(t, nil)
	opts.EventsJSONL = jsonlBytes([]map[string]interface{}{event})
	opts.PublicKeys = map[string][]byte{"object:k1": pub}

	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass, got status=%s reason=%s findings=%v",
			res.Status, res.Reason, res.Findings)
	}
	if !hasFinding(res.Findings, "event.signature_valid") {
		t.Fatalf("expected event.signature_valid, findings=%v", res.Findings)
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

func TestVerifyPolicyFingerprintMismatchBundle(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	opts := buildTestBundleOpts(t, priv)
	opts.PolicyJSON, err = json.Marshal(map[string]interface{}{
		"policy_id":          "p1",
		"policy_fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"rules":              []interface{}{},
	})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	res, err := Verify(&buf, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "fail" || res.Reason != "bundle.policy_fingerprint_mismatch" {
		t.Fatalf("expected policy fingerprint mismatch, got status=%s reason=%s findings=%v",
			res.Status, res.Reason, res.Findings)
	}
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
	tr, err := bundleTarReader(r)
	if err != nil {
		t.Fatalf("bundle reader: %v", err)
	}
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
	var tarBuf bytes.Buffer
	if err := writeBundlePlainTar(&tarBuf, b); err != nil {
		return err
	}
	return writeZstd(w, tarBuf.Bytes())
}

func writeBundlePlainTar(w io.Writer, b *Bundle) error {
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

func writeZstd(w io.Writer, data []byte) error {
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return err
	}
	return zw.Close()
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

func signMap(
	t *testing.T,
	doc map[string]interface{},
	field string,
	priv ed25519.PrivateKey,
	keyID string,
	excludedFields []string,
) {
	t.Helper()
	payload, err := canonicalSignedMap(doc, excludedFields)
	if err != nil {
		t.Fatalf("canonical signed map: %v", err)
	}
	sig := ed25519.Sign(priv, sha256Sum(payload))
	doc[field] = map[string]interface{}{
		"alg":    "ed25519",
		"key_id": keyID,
		"value":  base64.StdEncoding.EncodeToString(sig),
	}
}
