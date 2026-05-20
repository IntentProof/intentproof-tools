package localloop

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// FlowBoundsAndMode returns the time bounds and instrumentation mode for a
// correlation. Modes are reduced using the minimal<operational<full rule.
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
