package localloop

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleVerifyRunInvalidJSON(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerifyRunMethodNotAllowed(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodGet, "/v1/verify/run", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}
