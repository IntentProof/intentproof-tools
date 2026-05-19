package localloop

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestIngestHandlerHealthzAndMethodChecks(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := NewIngestServer("", db, nil).Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: %d %q", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST healthz: %d", rec2.Code)
	}
}
