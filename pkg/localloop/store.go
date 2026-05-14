package localloop

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/merkle"
	_ "modernc.org/sqlite"
)

const schemaSQL = `
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
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return db, nil
}

// StoreEvent persists an ExecutionEvent with its computed SHA-256 hash.
func StoreEvent(ctx context.Context, db *sql.DB, ev ExecutionEvent, eventHash []byte) error {
	bodyBytes, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event body: %w", err)
	}
	sigBytes, err := json.Marshal(ev.Signature)
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO execution_events (
		  tenant_id, event_id, correlation_id, instance_id, chain_position,
		  prev_event_hash, event_hash, action, status, started_at, completed_at,
		  duration_ms, spec_version, body, signature
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		ev.TenantID, ev.EventID, ev.CorrelationID, ev.InstanceID, ev.ChainPosition,
		ev.PrevEventHash, eventHash, ev.Action, ev.Status,
		ev.StartedAt.Format(time.RFC3339Nano), ev.CompletedAt.Format(time.RFC3339Nano),
		ev.DurationMS, ev.SpecVersion, string(bodyBytes), string(sigBytes),
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// EventRow is a lightweight representation of an event for flow building.
type EventRow struct {
	EventID string
	Hash    []byte
}

// LoadFlowEvents returns all events for a given (tenant_id, correlation_id)
// ordered by chain_position ASC, event_id ASC.
func LoadFlowEvents(ctx context.Context, db *sql.DB, tenantID, correlationID string) ([]EventRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT event_id, event_hash
		FROM execution_events
		WHERE tenant_id = ? AND correlation_id = ?
		ORDER BY chain_position ASC, event_id ASC`,
		tenantID, correlationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.EventID, &e.Hash); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// FlowBoundsAndMode returns the time bounds and instrumentation mode for a
// correlation.  Modes are reduced using the minimal<operational<full rule.
func FlowBoundsAndMode(ctx context.Context, db *sql.DB, tenantID, correlationID string) (time.Time, time.Time, string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT started_at, completed_at, COALESCE(json_extract(body, '$.attributes.intentproof.mode'), '') AS mode
		FROM execution_events
		WHERE tenant_id = ? AND correlation_id = ?
		ORDER BY chain_position ASC, event_id ASC`,
		tenantID, correlationID,
	)
	if err != nil {
		return time.Time{}, time.Time{}, "", fmt.Errorf("query bounds: %w", err)
	}
	defer rows.Close()

	var startedAt, closedAt time.Time
	modes := make([]string, 0)
	for rows.Next() {
		var s, c, m string
		if err := rows.Scan(&s, &c, &m); err != nil {
			return time.Time{}, time.Time{}, "", fmt.Errorf("scan bounds: %w", err)
		}
		st, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return time.Time{}, time.Time{}, "", fmt.Errorf("parse started_at %q: %w", s, err)
		}
		ct, err := time.Parse(time.RFC3339Nano, c)
		if err != nil {
			return time.Time{}, time.Time{}, "", fmt.Errorf("parse completed_at %q: %w", c, err)
		}
		if len(modes) == 0 || st.Before(startedAt) {
			startedAt = st
		}
		if len(modes) == 0 || ct.After(closedAt) {
			closedAt = ct
		}
		if m == "" {
			m = "operational"
		}
		modes = append(modes, m)
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, time.Time{}, "", fmt.Errorf("iterate bounds: %w", err)
	}
	return startedAt, closedAt, reduceFlowMode(modes), nil
}

// UpsertFlow writes or updates a flow record and its snapshot.
func UpsertFlow(ctx context.Context, db *sql.DB, snap FlowSnapshot) error {
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO flows (
		  tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at,
		  closure_reason, event_count, flow_merkle_root, instrumentation_mode,
		  snapshot_uri, flow_published_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, flow_id) DO UPDATE SET
		  window_opened_at = excluded.window_opened_at,
		  window_closed_at = excluded.window_closed_at,
		  closure_reason = excluded.closure_reason,
		  event_count = excluded.event_count,
		  flow_merkle_root = excluded.flow_merkle_root,
		  instrumentation_mode = excluded.instrumentation_mode,
		  snapshot_uri = excluded.snapshot_uri,
		  flow_published_at = excluded.flow_published_at`,
		snap.TenantID, snap.FlowID, snap.CorrelationID,
		snap.Window.OpenedAt.Format(time.RFC3339Nano),
		snap.Window.ClosedAt.Format(time.RFC3339Nano),
		snap.Window.ClosureReason, len(snap.Events), snap.FlowMerkleRoot,
		snap.InstrumentationMode, snap.SnapshotURI,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert flow: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO snapshots (snapshot_id, tenant_id, flow_id, json_body)
		VALUES (?,?,?,?)
		ON CONFLICT (snapshot_id) DO UPDATE SET json_body = excluded.json_body`,
		snap.SnapshotURI, snap.TenantID, snap.FlowID, string(snapJSON),
	)
	if err != nil {
		return fmt.Errorf("upsert snapshot: %w", err)
	}

	return tx.Commit()
}

// GetFlowByCorrelationID returns a flow snapshot for the given correlation.
func GetFlowByCorrelationID(ctx context.Context, db *sql.DB, tenantID, correlationID string) (*FlowSnapshot, error) {
	var snapJSON string
	var flowID string
	err := db.QueryRowContext(ctx, `
		SELECT f.flow_id, s.json_body
		FROM flows f
		JOIN snapshots s ON s.snapshot_id = f.snapshot_uri
		WHERE f.tenant_id = ? AND f.correlation_id = ?
		ORDER BY f.window_closed_at DESC
		LIMIT 1`,
		tenantID, correlationID,
	).Scan(&flowID, &snapJSON)
	if err != nil {
		return nil, err
	}
	var snap FlowSnapshot
	if err := json.Unmarshal([]byte(snapJSON), &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

const (
	modeMinimal     = "minimal"
	modeOperational = "operational"
	modeFull        = "full"
	defaultMode     = modeOperational
)

func modeRank(mode string) int {
	switch mode {
	case modeMinimal:
		return 0
	case modeOperational:
		return 1
	case modeFull:
		return 2
	default:
		return 1
	}
}

func reduceFlowMode(modes []string) string {
	if len(modes) == 0 {
		return defaultMode
	}
	minMode := modes[0]
	minR := modeRank(minMode)
	for _, m := range modes[1:] {
		if r := modeRank(m); r < minR {
			minR = r
			minMode = m
		}
	}
	switch minMode {
	case modeMinimal, modeOperational, modeFull:
		return minMode
	default:
		return defaultMode
	}
}

// ComputeMerkleRoot computes the RFC 6962 Merkle root over event hashes.
func ComputeMerkleRoot(events []EventRow) []byte {
	hashes := make([][]byte, len(events))
	for i, e := range events {
		hashes[i] = e.Hash
	}
	return merkle.Root(hashes)
}

// HexRoot formats a raw hash with the sha256: prefix.
func HexRoot(root []byte) string {
	return "sha256:" + hex.EncodeToString(root)
}
