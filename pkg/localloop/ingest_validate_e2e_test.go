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
	"strings"
	"testing"
)

func TestValidateEventRejectsBadFields(t *testing.T) {
	base := mustSignedEvent(t, mustPriv(t), "tnt_v", "inst_v", "corr_v", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "a")
	cases := []struct {
		name string
		mut  func(*ExecutionEvent)
	}{
		{"schema", func(e *ExecutionEvent) { e.Schema = "bad" }},
		{"event_id", func(e *ExecutionEvent) { e.EventID = "" }},
		{"chain_pos", func(e *ExecutionEvent) { e.ChainPosition = 0 }},
		{"sig_alg", func(e *ExecutionEvent) { e.Signature.Alg = "rsa" }},
		{"prev_prefix", func(e *ExecutionEvent) { e.PrevEventHash = "md5:aa" }},
		{"prev_len", func(e *ExecutionEvent) { e.PrevEventHash = "sha256:abc" }},
		{"prev_hex", func(e *ExecutionEvent) {
			e.PrevEventHash = "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := base
			tc.mut(&ev)
			if err := validateEvent(ev); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func mustPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestIngestHandlerRejectsMethodsAndBadBodies(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := NewIngestServer("", db, nil).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader("{"))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rec2.Code)
	}

	req3 := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"schema":"intentproof.event.v1"}`))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("validate status=%d", rec3.Code)
	}
}

func TestIngestChainConflictReturns409(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := RegisterSDKInstance(context.Background(), db, "tnt_cc", "inst_cc", pub); err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_cc", "inst_cc", "corr_cc", 1,
		"sha256:0101010101010101010101010101010101010101010101010101010101010101", "a")
	body, _ := json.Marshal(ev)
	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("first status=%d", resp.StatusCode)
	}
}

func TestFlowBuilderHandleErrors(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	fb := NewFlowBuilder(db, nw)
	ctx := context.Background()

	if err := fb.handle(ctx, []byte("not-json")); err == nil {
		t.Fatal("bad json")
	}
	if err := fb.handle(ctx, []byte(`{}`)); err == nil {
		t.Fatal("missing fields")
	}
	if err := fb.handle(ctx, []byte(`{"tenant_id":"t","correlation_id":"c","event_id":"e"}`)); err == nil {
		t.Fatal("no events")
	}
}

func TestEventChainDigestAndCanonicalize(t *testing.T) {
	ev := mustSignedEvent(t, mustPriv(t), "tnt_d", "inst_d", "corr_d", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "act")
	if _, err := EventChainDigest(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalizeWithoutSignature(ev); err != nil {
		t.Fatal(err)
	}
}
