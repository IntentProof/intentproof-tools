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

func TestIngestRejectsUnregisteredSDK(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_x", "inst_unregistered", "corr_x", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"act")
	body, _ := json.Marshal(ev)

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

func TestIngestRejectsInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	ctx := context.Background()
	if err := RegisterSDKInstance(ctx, db, "tnt_x", "inst_x", pub); err != nil {
		t.Fatal(err)
	}

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, wrongPriv, "tnt_x", "inst_x", "corr_x", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"act")
	body, _ := json.Marshal(ev)

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

func TestIngestAcceptsRegisteredSDK(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ingest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	ctx := context.Background()
	if err := RegisterSDKInstance(ctx, db, "tnt_x", "inst_x", pub); err != nil {
		t.Fatal(err)
	}

	ev := mustSignedEvent(t, priv, "tnt_x", "inst_x", "corr_x", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"act")
	body, _ := json.Marshal(ev)

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d want 202", resp.StatusCode)
	}
}
