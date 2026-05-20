package localloop

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenDBBusyTimeoutPragmaFailure(t *testing.T) {
	orig := storeDBExec
	storeDBExec = func(db *sql.DB, query string) (sql.Result, error) {
		if strings.Contains(query, "busy_timeout") {
			return nil, errors.New("busy_timeout fail")
		}
		return orig(db, query)
	}
	t.Cleanup(func() { storeDBExec = orig })

	_, err := OpenDB(filepath.Join(t.TempDir(), "busy.db"))
	if err == nil || !strings.Contains(err.Error(), "busy_timeout") {
		t.Fatalf("err=%v", err)
	}
}

func TestOpenDBSchemaMigrationFailure(t *testing.T) {
	orig := storeDBExec
	storeDBExec = func(db *sql.DB, query string) (sql.Result, error) {
		if strings.Contains(query, "CREATE TABLE") {
			return nil, errors.New("schema fail")
		}
		return orig(db, query)
	}
	t.Cleanup(func() { storeDBExec = orig })

	_, err := OpenDB(filepath.Join(t.TempDir(), "schema.db"))
	if err == nil || !strings.Contains(err.Error(), "migrate schema") {
		t.Fatalf("err=%v", err)
	}
}

func TestOpenDBJournalModePragmaFailure(t *testing.T) {
	orig := storeDBExec
	storeDBExec = func(db *sql.DB, query string) (sql.Result, error) {
		if strings.Contains(query, "journal_mode") {
			return nil, errors.New("journal fail")
		}
		return orig(db, query)
	}
	t.Cleanup(func() { storeDBExec = orig })

	_, err := OpenDB(filepath.Join(t.TempDir(), "journal.db"))
	if err == nil || !strings.Contains(err.Error(), "journal_mode") {
		t.Fatalf("err=%v", err)
	}
}

func TestFlowBoundsAndModeBadTimestamp(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds_bad.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := t.Context()
	if err := EnsureTenant(ctx, db, "tnt_bt"); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_bt", "evt_bt", "corr_bt", "inst", 1,
		chainSentinelHash(), []byte{1}, "demo.action", "ok",
		"not-a-time", "not-a-time", 1, "v1", `{}`, `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = FlowBoundsAndMode(ctx, db, "tnt_bt", "corr_bt")
	if err == nil || !strings.Contains(err.Error(), "parse started_at") {
		t.Fatalf("err=%v", err)
	}
}

func TestUpsertFlowSnapshotExecFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert_exec.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	now := mustParseTime(t, "2026-05-15T12:00:00Z")
	err = UpsertFlow(t.Context(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f", TenantID: "tnt", CorrelationID: "c",
		Window: SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
	})
	if err == nil {
		t.Fatal("expected upsert exec error")
	}
}

func mustParseTime(t *testing.T, raw string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatal(err)
	}
	return ts.UTC()
}
