package doctor

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
	_ "modernc.org/sqlite"
)

type localDBSnapshot struct {
	EventCount       int
	FlowCount        int
	SDKInstanceCount int
	LastEventAt      string
	Actions          map[string]int
}

func inspectLocalDB(ctx context.Context, dbPath string) (localDBSnapshot, error) {
	var snap localDBSnapshot
	snap.Actions = map[string]int{}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return snap, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	tenantID := localloop.LocalTenantID
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM execution_events WHERE tenant_id = ?`, tenantID).Scan(&snap.EventCount); err != nil {
		return snap, err
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM flows WHERE tenant_id = ?`, tenantID).Scan(&snap.FlowCount); err != nil {
		return snap, err
	}
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sdk_instances WHERE tenant_id = ? AND revoked_at IS NULL`,
		tenantID).Scan(&snap.SDKInstanceCount); err != nil {
		return snap, err
	}

	var last sql.NullString
	if err := db.QueryRowContext(ctx, `
SELECT MAX(completed_at) FROM execution_events WHERE tenant_id = ?`, tenantID).Scan(&last); err != nil {
		return snap, err
	}
	if last.Valid {
		snap.LastEventAt = last.String
	}

	rows, err := db.QueryContext(ctx, `
SELECT action, COUNT(*) FROM execution_events
WHERE tenant_id = ?
GROUP BY action
ORDER BY action ASC`, tenantID)
	if err != nil {
		return snap, err
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			return snap, err
		}
		snap.Actions[action] = count
	}
	return snap, rows.Err()
}

func formatLastEventAge(iso string) string {
	if iso == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return iso
		}
	}
	age := time.Since(t).Round(time.Second)
	if age < time.Minute {
		return fmt.Sprintf("%s ago", age)
	}
	return fmt.Sprintf("%s ago", age.Truncate(time.Minute))
}
