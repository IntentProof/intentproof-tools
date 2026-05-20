package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifyObjectSignaturesRunCanonicalizeError(t *testing.T) {
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
	run["bad"] = make(chan int)
	b := &Bundle{
		PublicKeys: map[string][]byte{"k1": pub},
		Run:        run,
	}
	_, err = verifyObjectSignatures(b, nil)
	if err == nil {
		t.Fatal("expected run canonicalize error")
	}
}
