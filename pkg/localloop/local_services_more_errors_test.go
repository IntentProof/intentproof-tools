package localloop

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLocalDashboardHandlerQueryError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dashclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("sql")) && rec.Body.Len() > 0 {
		// Error message should appear in rendered page.
		if !bytes.Contains(rec.Body.Bytes(), []byte("database")) &&
			!bytes.Contains(rec.Body.Bytes(), []byte("closed")) {
			t.Fatalf("body=%s", rec.Body.String())
		}
	}
}

func TestHandleVerifyBundleInvalidTarBody(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader([]byte("not-a-tar")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyBundleMethodNotAllowed(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodGet, "/v1/verify/bundle", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHandleVerifyRunMalformedJSONBody(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader([]byte("{")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestParseLocalBundleVerifyPubkeyInvalidHex(t *testing.T) {
	t.Setenv(EnvLocalBundleVerifyPubkey, "zzzz")
	if _, err := parseLocalBundleVerifyPubkey(); err == nil {
		t.Fatal("expected hex decode error")
	}
}
