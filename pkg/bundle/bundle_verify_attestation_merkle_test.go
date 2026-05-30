package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"testing"
)

func TestVerifyAttestationMerkleMismatch(t *testing.T) {
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
			m.AttMerkle = "sha256:deadbeef"
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
	if res.Reason != "bundle.attestation_merkle_mismatch" {
		t.Fatalf("reason=%s", res.Reason)
	}
}

func TestVerifyManifestListedFileMissing(t *testing.T) {
	body := []byte(`{"schema":"intentproof.bundle.manifest.v1","bundle_id":"b1","created_at":"2026-05-12T00:00:00Z","flow_id":"f1","tenant_id":"tnt","verification_profile":{"spec_version":"v0.test","verifier_version":"dev","policy_versions":[],"export_profile":"full","flow_snapshot_id":"f1","run_id":"run_f1"},"files":[{"path":"run.json","sha256":"sha256:00"}]}`)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0o644})
	_, _ = tw.Write(body)
	_ = tw.Close()
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.file_missing" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestVerifyManifestSignatureDecodeFailed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := buildTestBundleOpts(t, priv)
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
			if m.Signature != nil {
				m.Signature.Value = "not-hex"
				body, err = json.MarshalIndent(m, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				hdr.Size = int64(len(body))
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	res, err := Verify(&tampered, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.signature_decode_failed" {
		t.Fatalf("reason=%s", res.Reason)
	}
}

func TestJsonlBytesSingleItem(t *testing.T) {
	out := jsonlBytes([]map[string]any{{"a": 1}})
	if bytes.Contains(out, []byte("\n")) {
		t.Fatalf("expected single line, got %q", out)
	}
}
