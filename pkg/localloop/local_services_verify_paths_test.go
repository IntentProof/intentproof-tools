package localloop

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLocalDashboardHandlerGET(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dash.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	links := LocalDashboardLinks{
		IngestURL:    "http://127.0.0.1:1",
		VerifierURL:  "http://127.0.0.1:2",
		DashboardURL: "http://127.0.0.1:3",
	}
	h := LocalDashboardHandler(db, links)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHandleVerifyBundleEmptyBody(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyRunMissingFlowAndPolicy(t *testing.T) {
	h := LocalVerifierHandler()
	body := []byte(`{"policy":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLocalPublicBaseURLDefaults(t *testing.T) {
	if got := LocalPublicBaseURL(""); got != "http://localhost:9787" {
		t.Fatalf("got %s", got)
	}
	if got := LocalPublicBaseURL(":9999"); got != "http://localhost:9999" {
		t.Fatalf("got %s", got)
	}
}
