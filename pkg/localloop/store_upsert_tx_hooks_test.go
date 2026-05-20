package localloop

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpsertFlowInsertFlowsExecFailure(t *testing.T) {
	orig := storeTxExec
	storeTxExec = func(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
		if strings.Contains(query, "INSERT INTO flows") {
			return nil, errors.New("flows exec fail")
		}
		return orig(ctx, tx, query, args...)
	}
	t.Cleanup(func() { storeTxExec = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert_flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	err = UpsertFlow(context.Background(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f", TenantID: "tnt", CorrelationID: "c",
		Window:      SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
		SnapshotURI: "local://snapshot/f",
	})
	if err == nil || !strings.Contains(err.Error(), "upsert flow") {
		t.Fatalf("err=%v", err)
	}
}

func TestUpsertFlowInsertSnapshotExecFailure(t *testing.T) {
	orig := storeTxExec
	storeTxExec = func(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
		if strings.Contains(query, "INSERT INTO snapshots") {
			return nil, errors.New("snapshot exec fail")
		}
		return orig(ctx, tx, query, args...)
	}
	t.Cleanup(func() { storeTxExec = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert_snap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	err = UpsertFlow(context.Background(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f2", TenantID: "tnt", CorrelationID: "c2",
		Window:      SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
		SnapshotURI: "local://snapshot/f2",
	})
	if err == nil || !strings.Contains(err.Error(), "upsert snapshot") {
		t.Fatalf("err=%v", err)
	}
}

func TestGetFlowByCorrelationIDCorruptSnapshotBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bad_snap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bs"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapURI := "local://snapshot/bad"
	_, err = db.ExecContext(ctx, `
INSERT INTO flows (
  tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at,
  closure_reason, event_count, flow_merkle_root, instrumentation_mode,
  snapshot_uri, flow_published_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_bs", "flow_bad", "corr_bs",
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		"event_committed", 0, "sha256:0", "operational", snapURI,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO snapshots (snapshot_id, tenant_id, flow_id, json_body)
VALUES (?,?,?,?)`, snapURI, "tnt_bs", "flow_bad", "{not-json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = GetFlowByCorrelationID(ctx, db, "tnt_bs", "corr_bs")
	if err == nil {
		t.Fatal("expected invalid snapshot json error")
	}
}

func TestBuildVerifierFlowJSONQueryCancelled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "query_cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_qc"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := UpsertFlow(ctx, db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f_qc", TenantID: "tnt_qc", CorrelationID: "corr_qc",
		Window:      SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
		SnapshotURI: "local://snapshot/f_qc",
	}); err != nil {
		t.Fatal(err)
	}

	qctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = BuildVerifierFlowJSON(qctx, db, "tnt_qc", "corr_qc")
	if err == nil {
		t.Fatal("expected cancelled query error")
	}
}

func TestLoadEventsJSONLQueryCancelled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "jsonl_cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	qctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = LoadEventsJSONL(qctx, db, "tnt", "corr")
	if err == nil {
		t.Fatal("expected cancelled query error")
	}
}
