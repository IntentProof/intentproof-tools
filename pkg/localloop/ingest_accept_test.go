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

func TestIngestAcceptsSignedEvent(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "accept.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_ok"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_ok", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	ev := mustSignedEvent(t, priv, tenant, "inst_ok", "corr_ok", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestIngestReturnsConflictOnChainError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_cc"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_cc", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev1 := mustSignedEventWithID(t, priv, tenant, "inst_cc", "corr_cc", 1, sentinel, "a1", "evt_a")
	body1, _ := json.Marshal(ev1)
	resp1, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body1))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first status=%d", resp1.StatusCode)
	}

	ev2 := mustSignedEventWithID(t, priv, tenant, "inst_cc", "corr_cc", 1, sentinel, "a1b", "evt_b")
	body2, _ := json.Marshal(ev2)
	resp2, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second status=%d", resp2.StatusCode)
	}
}

func TestIngestWithoutNATSStillAccepts(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "nonats.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tnt_nn"
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_nn", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewIngestServer("", db, nil).Handler())
	defer srv.Close()

	ev := mustSignedEvent(t, priv, tenant, "inst_nn", "corr_nn", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	body, _ := json.Marshal(ev)
	resp, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestEventChainDigestAndFormatChainHash(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "t", "i", "c", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "a")
	d, err := EventChainDigest(ev)
	if err != nil {
		t.Fatal(err)
	}
	formatted := FormatChainHash(d)
	if formatted == "" {
		t.Fatal("empty hash")
	}
}
