package localloop

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

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
