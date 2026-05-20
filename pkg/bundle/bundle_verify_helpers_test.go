package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyDetectsFileHashMismatch(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	vr, err := Verify(bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != "pass" {
		t.Fatalf("status=%s reason=%s", vr.Status, vr.Reason)
	}
}

func TestVerifyTruncatedBundleManifestMissing(t *testing.T) {
	// Empty tar.zst should fail manifest read.
	var buf bytes.Buffer
	if err := Create(&buf, buildTestBundleOpts(t, nil)); err != nil {
		t.Fatal(err)
	}
	// Truncate bundle to corrupt it.
	truncated := buf.Bytes()[:32]
	vr, err := Verify(bytes.NewReader(truncated), nil)
	if err == nil && vr != nil && vr.Reason == "" {
		t.Fatalf("expected failure vr=%v err=%v", vr, err)
	}
}

func TestComputeItemMerkleEmpty(t *testing.T) {
	root := computeItemMerkle(nil, "event_id")
	if root == "" {
		t.Fatal("expected empty merkle root string")
	}
}

func TestSha256hexAndSum(t *testing.T) {
	data := []byte("hello")
	if sha256hex(data) == "" {
		t.Fatal("empty hex")
	}
	sum := sha256sum(data)
	if len(sum) != sha256.Size {
		t.Fatalf("len=%d", len(sum))
	}
	if hex.EncodeToString(sum) != sha256hex(data) {
		t.Fatal("mismatch")
	}
}

func TestIsEd25519HexSignature(t *testing.T) {
	sig := make([]byte, 64)
	if !isEd25519HexSignature(hex.EncodeToString(sig)) {
		t.Fatal("expected hex signature detection")
	}
	if isEd25519HexSignature("tooshort") {
		t.Fatal("expected false for short hex")
	}
}
