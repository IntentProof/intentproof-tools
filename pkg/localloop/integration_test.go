package localloop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestIngestWritesFlowsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "local.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = NewFlowBuilder(db, nw).Run(ctx)
	}()

	srv := httptest.NewServer(NewIngestServer("", db, nw).Handler())
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := RegisterSDKInstance(ctx, db, "tnt_e2e", "inst_e2e", pub); err != nil {
		t.Fatal(err)
	}

	ev1 := mustSignedEvent(t, priv, "tnt_e2e", "inst_e2e", "corr_e2e", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"e2e.action")
	b1, _ := json.Marshal(ev1)
	resp1, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(b1))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("event1 status=%d", resp1.StatusCode)
	}

	c1, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	d1 := sha256.Sum256(c1)
	prev2 := "sha256:" + fmt.Sprintf("%x", d1)

	ev2 := mustSignedEvent(t, priv, "tnt_e2e", "inst_e2e", "corr_e2e", 2, prev2, "e2e.action2")
	b2, _ := json.Marshal(ev2)
	resp2, err := http.Post(srv.URL+"/v1/events", "application/json", bytes.NewReader(b2))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("event2 status=%d", resp2.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flows WHERE tenant_id = ? AND correlation_id = ?`,
			"tnt_e2e", "corr_e2e").Scan(&n)
		if err == nil && n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n < 2 {
		t.Fatalf("expected >=2 flow rows, got %d", n)
	}
}

func mustSignedEvent(t *testing.T, priv ed25519.PrivateKey, tenantID, instanceID, correlationID string, chainPos int, prevHash, action string) ExecutionEvent {
	return mustSignedEventWithID(t, priv, tenantID, instanceID, correlationID, chainPos, prevHash, action, "")
}

func mustSignedEventWithID(t *testing.T, priv ed25519.PrivateKey, tenantID, instanceID, correlationID string, chainPos int, prevHash, action, eventID string) ExecutionEvent {
	t.Helper()
	if eventID == "" {
		eventID = fmt.Sprintf("evt_%d_%s", chainPos, correlationID)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       eventID,
		TenantID:      tenantID,
		InstanceID:    instanceID,
		CorrelationID: correlationID,
		PrevEventHash: prevHash,
		ChainPosition: chainPos,
		Intent:        "e2e intent",
		Action:        action,
		Status:        "ok",
		StartedAt:     now,
		CompletedAt:   now.Add(time.Millisecond),
		DurationMS:    1,
		Inputs:        []any{},
		Output:        map[string]any{"ok": true},
		SpecVersion:   "1.0.0",
		SDKVersion:    "test",
		Attributes:    map[string]any{},
	}
	canonical, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(canonical)
	sig := ed25519.Sign(priv, d[:])
	ev.Signature = Signature{
		Alg:   "ed25519",
		KeyID: instanceID + ":k1",
		Value: base64.StdEncoding.EncodeToString(sig),
	}
	return ev
}
