package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEventFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt", "inst", "corr", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_ = db.Close()
	if _, err := StoreEvent(context.Background(), db, ev, h[:]); err == nil {
		t.Fatal("expected store error on closed db")
	}
}

func TestLoadFlowEventsFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "loadclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := LoadFlowEvents(context.Background(), db, "tnt", "corr"); err == nil {
		t.Fatal("expected query error on closed db")
	}
}

func TestFlowBoundsAndModeRejectsInvalidTimestamps(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_badts"); err != nil {
		t.Fatal(err)
	}
	body := `{"schema":"intentproof.event.v1","event_id":"e1","tenant_id":"tnt_badts","instance_id":"inst","correlation_id":"corr_badts","chain_position":1,"prev_event_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","action":"demo.action","status":"ok","started_at":"2020-01-01T00:00:00Z","completed_at":"2020-01-01T00:00:01Z","duration_ms":1,"spec_version":"1.0.0","signature":{"alg":"ed25519","value":"AA=="}}`
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_badts", "e1", "corr_badts", "inst", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		[]byte{1}, "demo.action", "ok", "not-a-timestamp", "also-bad", 1, "1.0.0", body, `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := FlowBoundsAndMode(ctx, db, "tnt_badts", "corr_badts"); err == nil {
		t.Fatal("expected parse error for invalid timestamps")
	}
}

func TestUpsertFlowFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsertclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap := FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f", TenantID: "tnt",
		CorrelationID: "c", Window: SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
		SnapshotURI: "local://snapshot/f",
	}
	_ = db.Close()
	if err := UpsertFlow(context.Background(), db, snap); err == nil {
		t.Fatal("expected upsert error on closed db")
	}
}

func TestGetFlowByCorrelationIDInvalidSnapshotJSON(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badsnap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(ctx, `
INSERT INTO flows (tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at,
  closure_reason, event_count, flow_merkle_root, instrumentation_mode, snapshot_uri, flow_published_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt", "flow_bad", "corr_bad", now, now, "event_committed", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "operational",
		"local://snapshot/flow_bad", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO snapshots (snapshot_id, tenant_id, flow_id, json_body)
VALUES (?,?,?,?)`, "local://snapshot/flow_bad", "tnt", "flow_bad", "{not json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetFlowByCorrelationID(ctx, db, "tnt", "corr_bad"); err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestBuildVerifierFlowJSONInvalidEventBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badbody.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	snapJSON := `{"schema":"intentproof.flow.v1","flow_id":"flow1","tenant_id":"tnt","correlation_id":"corr1","window":{"opened_at":"2020-01-01T00:00:00Z","closed_at":"2020-01-01T00:00:01Z","closure_reason":"event_committed"},"instrumentation_mode":"operational","flow_merkle_root":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","snapshot_uri":"local://snapshot/flow1"}`
	_, err = db.ExecContext(ctx, `
INSERT INTO flows (tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at,
  closure_reason, event_count, flow_merkle_root, instrumentation_mode, snapshot_uri, flow_published_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt", "flow1", "corr1", now, now, "event_committed", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "operational",
		"local://snapshot/flow1", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO snapshots (snapshot_id, tenant_id, flow_id, json_body)
VALUES (?,?,?,?)`, "local://snapshot/flow1", "tnt", "flow1", snapJSON)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt", "e1", "corr1", "inst", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		[]byte{1}, "demo.action", "ok", now, now, 1, "1.0.0", "{bad", `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildVerifierFlowJSON(ctx, db, "tnt", "corr1"); err == nil {
		t.Fatal("expected decode event body error")
	}
}

func TestLoadEventsJSONLFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "jsonlclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := LoadEventsJSONL(context.Background(), db, "tnt", "corr"); err == nil {
		t.Fatal("expected query error on closed db")
	}
}
