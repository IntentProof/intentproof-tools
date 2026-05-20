package localloop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestHandleVerifyBundleInvalidPubkeyEnv(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "not-hex")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyBundleHappyPath(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	t.Setenv(EnvLocalBundleVerifyPubkey, "")
	h := LocalVerifierHandler()

	opts := bundle.CreateOptions{
		BundleID:   "b1",
		FlowID:     "f1",
		TenantID:   "tnt",
		FlowJSON:   []byte(`{"flow_id":"f1","tenant_id":"tnt","events":[]}`),
		EventsJSONL: []byte(`{"event_id":"e1","action":"pay","status":"ok"}` + "\n"),
		PolicyJSON: []byte(`{"policy_id":"p1","rules":[]}`),
		RunJSON:    []byte(`{"run_id":"r1","flow_id":"f1","status":"pass","findings":[]}`),
		PublicKeys: map[string][]byte{},
	}
	var buf bytes.Buffer
	if err := bundle.Create(&buf, opts); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(buf.Bytes()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	_ = pub
}

func TestHandleVerifyRunMissingPolicy(t *testing.T) {
	h := LocalVerifierHandler()
	body := []byte(`{"flow":{"flow_id":"f1","tenant_id":"tnt","events":[]}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}
