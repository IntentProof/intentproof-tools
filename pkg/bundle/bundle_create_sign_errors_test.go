package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestCreateSignerError(t *testing.T) {
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		BundleID:    "b1",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		Signer: func([]byte) (*SignatureEnvelope, error) {
			return nil, errors.New("sign failed")
		},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("sign manifest")) {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateIncludesCertificateAndInclusionProof(t *testing.T) {
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		BundleID:        "b1",
		FlowID:          "f1",
		TenantID:        "tnt",
		FlowJSON:        []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL:     []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:      []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:         []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		CertificateJSON: []byte(`{"cert":"demo"}`),
		InclusionProof:  []byte(`{"proof":"demo"}`),
		PublicKeys:      map[string][]byte{"k1": {1, 2, 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	vr, err := Verify(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != "pass" {
		t.Fatalf("status=%s", vr.Status)
	}
}

func TestVerifyTruncatedTar(t *testing.T) {
	_, err := Verify(bytes.NewReader([]byte("not-a-valid-bundle")), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeSignatureValueInvalidHex(t *testing.T) {
	if _, err := decodeSignatureValue("zz"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestVerifySignedMapEmptySignatureSkipped(t *testing.T) {
	doc := map[string]interface{}{
		"signature": map[string]interface{}{
			"alg": "ed25519", "key_id": "k", "value": "",
		},
	}
	findings, err := verifySignedMap(&Bundle{PublicKeys: map[string][]byte{}}, nil, "run", "signature", doc, []string{"signature"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings=%v", findings)
	}
}

func TestCreateWithManifestSignerSuccess(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = Create(&buf, CreateOptions{
		BundleID:    "b1",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		Signer: func(data []byte) (*SignatureEnvelope, error) {
			sum := sha256.Sum256(data)
			sig := ed25519.Sign(priv, sum[:])
			return &SignatureEnvelope{
				Alg:   "ed25519",
				KeyID: "k1",
				Value: hex.EncodeToString(sig),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	vr, err := Verify(bytes.NewReader(buf.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != "pass" {
		t.Fatalf("status=%s reason=%s", vr.Status, vr.Reason)
	}
}

func TestVerifyReaderError(t *testing.T) {
	_, err := Verify(errorReader{}, nil)
	if err == nil {
		t.Fatal("expected read error")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
