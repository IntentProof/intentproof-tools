package localloop

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLocalDashboardHandlerNotFoundPath(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dash_nf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLocalDashboardHandlerMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dash_ma.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLocalDashboardHealthzWrongMethod(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dash_hz.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLocalPublicBaseURLVariants(t *testing.T) {
	if got := LocalPublicBaseURL("127.0.0.1:1234"); got != "http://127.0.0.1:1234" {
		t.Fatalf("got %s", got)
	}
	if got := LocalPublicBaseURL("http://example.com/"); got != "http://example.com" {
		t.Fatalf("got %s", got)
	}
}
