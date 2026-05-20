package localloop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalDashboardHandlerCancelledContext(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dashcancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLocalDashboardHandlerScanErrorFromCorruptRow(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "dashbad.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, LocalTenantID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(ctx, `
INSERT INTO flows (
  tenant_id, flow_id, correlation_id, window_opened_at, window_closed_at,
  closure_reason, event_count, flow_merkle_root, instrumentation_mode,
  snapshot_uri, flow_published_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		LocalTenantID, "flow_bad", "corr_bad", now, now,
		"event_committed", 1, 123, "operational", "local://snap", now,
	)
	if err != nil {
		t.Fatal(err)
	}

	h := LocalDashboardHandler(db, LocalDashboardLinks{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}
