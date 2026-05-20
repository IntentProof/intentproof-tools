package bundle

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCreateUsesCurrentTimeWhenCreatedAtZero(t *testing.T) {
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		BundleID:    "b_zero_time",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
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

func TestCreateCanonicalizeManifestError(t *testing.T) {
	var buf bytes.Buffer
	err := Create(&buf, CreateOptions{
		BundleID:    "b_bad_manifest",
		FlowID:      "f1",
		TenantID:    "tnt",
		FlowJSON:    []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON:  []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:     []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		CreatedAt:   time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Signer: func([]byte) (*SignatureEnvelope, error) {
			return nil, errors.New("boom")
		},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("sign manifest")) {
		t.Fatalf("err=%v", err)
	}
}
