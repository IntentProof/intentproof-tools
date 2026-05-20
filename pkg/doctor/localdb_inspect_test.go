package doctor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestInspectLocalDBWithEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "local.db")
	db, err := localloop.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := localloop.LocalTenantID
	if err := localloop.EnsureTenant(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}

	snap, err := inspectLocalDB(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.EventCount != 0 {
		t.Fatalf("events=%d", snap.EventCount)
	}
	db.Close()
}

func TestFormatLastEventAgeFormatsRecent(t *testing.T) {
	iso := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339)
	got := formatLastEventAge(iso)
	if got == "" {
		t.Fatal("expected age string")
	}
}

func TestFormatLastEventAgeReturnsRawOnParseFailure(t *testing.T) {
	if got := formatLastEventAge("not-a-timestamp"); got != "not-a-timestamp" {
		t.Fatalf("got %q", got)
	}
}
