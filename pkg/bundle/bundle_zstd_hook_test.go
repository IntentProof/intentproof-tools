package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestCreateZstdWriterInitFailure(t *testing.T) {
	orig := bundleNewZstdWriter
	bundleNewZstdWriter = func(io.Writer, ...zstd.EOption) (*zstd.Encoder, error) {
		return nil, errors.New("zstd init fail")
	}
	t.Cleanup(func() { bundleNewZstdWriter = orig })

	var buf bytes.Buffer
	err := Create(&buf, buildTestBundleOpts(t, nil))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("zstd")) {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyZstdReaderInitFailure(t *testing.T) {
	orig := bundleNewZstdReader
	bundleNewZstdReader = func(io.Reader, ...zstd.DOption) (*zstd.Decoder, error) {
		return nil, errors.New("zstd read fail")
	}
	t.Cleanup(func() { bundleNewZstdReader = orig })

	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x00, 0x00}
	_, err := Verify(bytes.NewReader(frame), nil)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("zstd_read_failed")) {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyManifestJSONDecodeFailure(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{Name: "manifest.json", Mode: 0o644, Size: 1}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zbuf bytes.Buffer
	zw, err := zstd.NewWriter(&zbuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(zw, &tarBuf); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(&zbuf, nil)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("manifest_decode_failed")) {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifySignedMapReportsInvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"event_id": "e1",
		"signature": map[string]interface{}{
			"alg": "ed25519", "key_id": "k1",
			"value": hex.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{"k1": pub}}, nil,
		"event", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "event.signature_invalid") {
		t.Fatalf("findings=%v", findings)
	}
}

func TestVerifyObjectSignaturesSignedRunDocument(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]interface{}{"run_id": "r1", "status": "pass"}
	payload, err := canonicalSignedMap(run, []string{"signature", "run_fingerprint", "started_at", "completed_at"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, sha256sum(payload))
	run["signature"] = map[string]interface{}{
		"alg": "ed25519", "key_id": "k1",
		"value": hex.EncodeToString(sig),
	}
	findings, err := verifyObjectSignatures(&Bundle{
		PublicKeys: map[string][]byte{"k1": pub},
		Run:        run,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "run.signature_valid") {
		t.Fatalf("findings=%v", findings)
	}
}
