package crypto

import (
	"context"
	"testing"
)

func TestNewLocalEd25519PolicySignerAndDigestSHA256(t *testing.T) {
	signer, err := NewLocalEd25519PolicySigner()
	if err != nil {
		t.Fatal(err)
	}
	digest := DigestSHA256([]byte("payload"))
	env, err := signer.Sign(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if env.Value == "" {
		t.Fatal("expected signature value")
	}
}
