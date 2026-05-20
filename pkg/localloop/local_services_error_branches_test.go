package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLocalVerifierHealthzMethodNotAllowed(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHandleVerifyRunVerifyInputError(t *testing.T) {
	h := LocalVerifierHandler()
	body := []byte(`{"flow":"not-an-object","policy":{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]},"attestations":""}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyRunBodyTooLarge(t *testing.T) {
	h := LocalVerifierHandler()
	body := bytes.Repeat([]byte("x"), maxVerifyRunBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHandleVerifyBundleWrongKeyLength(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "abcd")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIngestHandleV1EventsInternalStoreError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "internal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Do not register SDK; signature verification returns unauthorized, not internal.
	// Close DB to force internal error on store after passing validation is hard without
	// race; instead test invalid signature internal path via corrupt DB after register.
	if err := RegisterSDKInstance(context.Background(), db, "tnt_int", "inst_int", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()
	ev := mustSignedEvent(t, priv, "tnt_int", "inst_int", "corr_int", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestHandleV1EventsBadRequestValidation(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badreq.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	ev := ExecutionEvent{Schema: "intentproof.event.v1", EventID: "e1"}
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
