package localloop

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

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
