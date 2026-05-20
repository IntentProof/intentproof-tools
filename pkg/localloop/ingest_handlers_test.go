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

func TestIngestHealthzMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestV1EventsMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestRejectsInvalidJSONBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestUnauthorizedUnknownSDK(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest4.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_u", "unknown_inst", "corr_u", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	_ = context.Background()
}
