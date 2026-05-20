package localloop

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleVerifyBundleInvalidBundleBytes(t *testing.T) {
	t.Setenv("INTENTPROOF_LOCAL_BUNDLE_VERIFY_PUBKEY", "")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("not-a-bundle")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyBundleBadPubkeyConfig(t *testing.T) {
	t.Setenv("INTENTPROOF_LOCAL_BUNDLE_VERIFY_PUBKEY", "!!!")
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyBundleOversizedBodyRejected(t *testing.T) {
	t.Setenv("INTENTPROOF_LOCAL_BUNDLE_VERIFY_PUBKEY", "")
	h := LocalVerifierHandler()
	body := bytes.Repeat([]byte("x"), maxVerifyBundleBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
