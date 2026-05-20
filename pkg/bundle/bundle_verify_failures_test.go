package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestDecodeSignatureValueHex(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	for i := range sig {
		sig[i] = byte(i)
	}
	hexSig := hex.EncodeToString(sig)
	got, err := decodeSignatureValue(hexSig)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != ed25519.SignatureSize {
		t.Fatalf("len=%d", len(got))
	}
}

func TestCreateSignerErrorPropagates(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.Signer = func([]byte) (*SignatureEnvelope, error) {
		return nil, ioErr("sign failed")
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err == nil {
		t.Fatal("expected sign error")
	}
}

type ioErr string

func (e ioErr) Error() string { return string(e) }
