package localloop

// SQLite persistence for the local loop is split across store_*.go by concern
// (schema/open, chain validation, events, flows, modes, merkle).
import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// ErrChainConflict means the event does not extend the existing chain.
var ErrChainConflict = errors.New("localloop: chain conflict")

// storeDBExec is overridden in tests to exercise OpenDB error paths.
var storeDBExec = func(db *sql.DB, query string) (sql.Result, error) {
	return db.Exec(query)
}

// storeTxExec is overridden in tests to exercise UpsertFlow error paths.
var storeTxExec = func(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	return tx.ExecContext(ctx, query, args...)
}

// storeTxCommit is overridden in tests to exercise transaction commit failures.
var storeTxCommit = func(tx *sql.Tx) error {
	return tx.Commit()
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sdk_instances (
    tenant_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    registered_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (tenant_id, instance_id)
);

CREATE TABLE IF NOT EXISTS execution_events (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    chain_position INTEGER NOT NULL,
    prev_event_hash TEXT NOT NULL,
    event_hash BLOB NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    spec_version TEXT NOT NULL,
    body TEXT NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_correlation
ON execution_events(tenant_id, correlation_id, chain_position);

CREATE UNIQUE INDEX IF NOT EXISTS ux_events_chain_slot
ON execution_events(tenant_id, instance_id, correlation_id, chain_position);

CREATE TABLE IF NOT EXISTS flows (
    tenant_id TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    window_opened_at TEXT,
    window_closed_at TEXT,
    closure_reason TEXT,
    event_count INTEGER,
    flow_merkle_root TEXT,
    instrumentation_mode TEXT,
    snapshot_uri TEXT,
    flow_published_at TEXT,
    PRIMARY KEY (tenant_id, flow_id)
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    json_body TEXT NOT NULL
);
`

// OpenDB opens the SQLite database at the given path and runs schema
// migration.
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := storeDBExec(db, `PRAGMA busy_timeout = 5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pragma busy_timeout: %w", err)
	}
	if _, err := storeDBExec(db, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	if _, err := storeDBExec(db, `PRAGMA journal_mode = WAL`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pragma journal_mode: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
