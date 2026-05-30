package bundle

import (
	"bytes"
	"testing"
)

func TestVerifyPolicyJSONDecodeFailure(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.PolicyJSON = []byte(`{not json`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err == nil {
		t.Fatal("expected create error for invalid policy json")
	}
}

func TestVerifyPolicyFingerprintMismatch(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.PolicyJSON = []byte(`{
  "policy_id":"p1",
  "tenant_id":"tnt",
  "policy_version":1,
  "policy_fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "rules":[]
}`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.policy_fingerprint_mismatch" {
		t.Fatalf("reason=%s", res.Reason)
	}
}
