package localloop

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalVerifierHandlerVerifyRun(t *testing.T) {
	h := LocalVerifierHandler()
	body := []byte(`{"flow":{"events":[]},"policy":{"rules":[]},"attestations":""}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] == nil {
		t.Fatalf("expected status in run: %#v", got)
	}
}

func TestLocalVerifierHandlerHealthz(t *testing.T) {
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("unexpected health: %d %q", rec.Code, rec.Body.String())
	}
}

func TestLocalPublicBaseURL(t *testing.T) {
	if u := LocalPublicBaseURL(":9787"); u != "http://localhost:9787" {
		t.Fatalf("got %q", u)
	}
	if u := LocalPublicBaseURL(""); u != "http://localhost:9787" {
		t.Fatalf("empty default got %q", u)
	}
}
