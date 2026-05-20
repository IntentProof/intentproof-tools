package localloop

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/merkle"
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

func normalizePrevEventHash(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func checkChain(ctx context.Context, tx *sql.Tx, ev ExecutionEvent) error {
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if ev.ChainPosition == 1 {
		if normalizePrevEventHash(ev.PrevEventHash) != sentinel {
			return fmt.Errorf("%w: first event prev_event_hash must be %s", ErrChainConflict, sentinel)
		}
	} else {
		rows, err := tx.QueryContext(ctx, `
			SELECT event_hash FROM execution_events
			WHERE tenant_id = ? AND instance_id = ? AND correlation_id = ? AND chain_position = ?
			ORDER BY event_id ASC`,
			ev.TenantID, ev.InstanceID, ev.CorrelationID, ev.ChainPosition-1,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		var prevHash []byte
		n := 0
		for rows.Next() {
			n++
			if err := rows.Scan(&prevHash); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		switch n {
		case 0:
			return fmt.Errorf("%w: previous event missing (chain gap)", ErrChainConflict)
		case 1:
			want := "sha256:" + hex.EncodeToString(prevHash)
			if normalizePrevEventHash(ev.PrevEventHash) != want {
				return fmt.Errorf("%w: prev_event_hash mismatch", ErrChainConflict)
			}
		default:
			return fmt.Errorf("%w: forked chain at previous position", ErrChainConflict)
		}
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT event_id FROM execution_events
		WHERE tenant_id = ? AND instance_id = ? AND correlation_id = ? AND chain_position = ?
		ORDER BY event_id ASC`,
		ev.TenantID, ev.InstanceID, ev.CorrelationID, ev.ChainPosition,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var occupantIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		occupantIDs = append(occupantIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	switch len(occupantIDs) {
	case 0:
		return nil
	case 1:
		if occupantIDs[0] != ev.EventID {
			return fmt.Errorf("%w: chain position already occupied by another event", ErrChainConflict)
		}
		return nil
	default:
		return fmt.Errorf("%w: forked chain at current position", ErrChainConflict)
	}
}

// StoreEvent persists an ExecutionEvent with its computed SHA-256 hash.
// It returns inserted=false when the row already existed (idempotent no-op).
func StoreEvent(ctx context.Context, db *sql.DB, ev ExecutionEvent, eventHash []byte) (inserted bool, err error) {
	bodyBytes, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("marshal event body: %w", err)
	}
	sigBytes, err := json.Marshal(ev.Signature)
	if err != nil {
		return false, fmt.Errorf("marshal signature: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := checkChain(ctx, tx, ev); err != nil {
		return false, err
	}

	res, err := storeTxExec(ctx, tx, `
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
		return false, fmt.Errorf("insert event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	if err := storeTxCommit(tx); err != nil {
		return false, err
	}
	return n > 0, nil
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

	_, err = storeTxExec(ctx, tx, `
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
		snap.Window.OpenedAt.UTC().Format(time.RFC3339Nano),
		snap.Window.ClosedAt.UTC().Format(time.RFC3339Nano),
		snap.Window.ClosureReason, len(snap.Events), snap.FlowMerkleRoot,
		snap.InstrumentationMode, snap.SnapshotURI,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert flow: %w", err)
	}

	_, err = storeTxExec(ctx, tx, `
		INSERT INTO snapshots (snapshot_id, tenant_id, flow_id, json_body)
		VALUES (?,?,?,?)
		ON CONFLICT (snapshot_id) DO UPDATE SET json_body = excluded.json_body`,
		snap.SnapshotURI, snap.TenantID, snap.FlowID, string(snapJSON),
	)
	if err != nil {
		return fmt.Errorf("upsert snapshot: %w", err)
	}

	return storeTxCommit(tx)
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
		ORDER BY f.window_closed_at DESC, f.event_count DESC, f.flow_id DESC
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

// verifierFlowEvent is the subset of an execution event consumed by
// pkg/verifier.Verify.
type verifierFlowEvent struct {
	EventID     string                 `json:"event_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	StartedAt   string                 `json:"started_at"`
	CompletedAt string                 `json:"completed_at"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

// verifierFlowDoc is flow JSON consumable by pkg/verifier.Verify.
type verifierFlowDoc struct {
	FlowID         string              `json:"flow_id"`
	TenantID       string              `json:"tenant_id"`
	FlowMerkleRoot string              `json:"flow_merkle_root"`
	Events         []verifierFlowEvent `json:"events"`
}

// BuildVerifierFlowJSON builds verifier flow JSON for the latest materialized
// snapshot of a correlation.
func BuildVerifierFlowJSON(ctx context.Context, db *sql.DB, tenantID, correlationID string) ([]byte, error) {
	snap, err := GetFlowByCorrelationID(ctx, db, tenantID, correlationID)
	if err != nil {
		return nil, fmt.Errorf("get flow snapshot: %w", err)
	}
	rows, err := db.QueryContext(ctx, `
		SELECT body FROM execution_events
		WHERE tenant_id = ? AND correlation_id = ?
		ORDER BY chain_position ASC, event_id ASC`,
		tenantID, correlationID)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []verifierFlowEvent
	for rows.Next() {
		var bodyStr string
		if err := rows.Scan(&bodyStr); err != nil {
			return nil, err
		}
		var full ExecutionEvent
		if err := json.Unmarshal([]byte(bodyStr), &full); err != nil {
			return nil, fmt.Errorf("decode event body: %w", err)
		}
		attrs := map[string]interface{}(nil)
		if len(full.Attributes) > 0 {
			attrs = make(map[string]interface{}, len(full.Attributes))
			for k, v := range full.Attributes {
				attrs[k] = v
			}
		}
		events = append(events, verifierFlowEvent{
			EventID:     full.EventID,
			Action:      full.Action,
			Status:      full.Status,
			StartedAt:   full.StartedAt.UTC().Format(time.RFC3339),
			CompletedAt: full.CompletedAt.UTC().Format(time.RFC3339),
			Attributes:  attrs,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	doc := verifierFlowDoc{
		FlowID:         snap.FlowID,
		TenantID:       snap.TenantID,
		FlowMerkleRoot: snap.FlowMerkleRoot,
		Events:         events,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal flow doc: %w", err)
	}
	return raw, nil
}

// LoadEventsJSONL returns JSONL event bodies (one signed ExecutionEvent JSON
// per line) for a correlation, ordered by chain position.
func LoadEventsJSONL(ctx context.Context, db *sql.DB, tenantID, correlationID string) ([]byte, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT body FROM execution_events
		WHERE tenant_id = ? AND correlation_id = ?
		ORDER BY chain_position ASC, event_id ASC`,
		tenantID, correlationID)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var buf bytes.Buffer
	first := true
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if !first {
			buf.WriteByte('\n')
		}
		first = false
		buf.WriteString(body)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
