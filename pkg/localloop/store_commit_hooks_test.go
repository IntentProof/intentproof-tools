package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreEventCommitFailure(t *testing.T) {
	orig := storeTxCommit
	storeTxCommit = func(*sql.Tx) error {
		return errors.New("commit fail")
	}
	t.Cleanup(func() { storeTxCommit = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "commit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEventWithID(t, priv, "tnt_c", "inst_c", "corr_c", 1, sentinel, "demo.action", "evt_c")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil || !strings.Contains(err.Error(), "commit fail") {
		t.Fatalf("err=%v", err)
	}
}

func TestUpsertFlowCommitFailure(t *testing.T) {
	orig := storeTxCommit
	storeTxCommit = func(*sql.Tx) error {
		return errors.New("commit fail")
	}
	t.Cleanup(func() { storeTxCommit = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert_commit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	err = UpsertFlow(context.Background(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f_commit", TenantID: "tnt", CorrelationID: "c",
		Window:      SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
		SnapshotURI: "local://snapshot/f_commit",
	})
	if err == nil || !strings.Contains(err.Error(), "commit fail") {
		t.Fatalf("err=%v", err)
	}
}

type errRowsAffectedResult struct {
	sql.Result
}

func (errRowsAffectedResult) RowsAffected() (int64, error) {
	return 0, errors.New("rows affected fail")
}

func TestStoreEventRowsAffectedFailure(t *testing.T) {
	orig := storeTxExec
	storeTxExec = func(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
		if strings.Contains(query, "INSERT INTO execution_events") {
			res, err := orig(ctx, tx, query, args...)
			if err != nil {
				return nil, err
			}
			return errRowsAffectedResult{res}, nil
		}
		return orig(ctx, tx, query, args...)
	}
	t.Cleanup(func() { storeTxExec = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "rows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEventWithID(t, priv, "tnt_r", "inst_r", "corr_r", 1, sentinel, "demo.action", "evt_r")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil || !strings.Contains(err.Error(), "rows affected") {
		t.Fatalf("err=%v", err)
	}
}

func TestStoreEventBodyMarshalFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "body_marshal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_bad_body",
		TenantID:      "tnt",
		InstanceID:    "inst",
		CorrelationID: "corr",
		ChainPosition: 1,
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Action:        "demo.action",
		Status:        "ok",
		Attributes:    map[string]any{"bad": make(chan int)},
		SpecVersion:   "v1",
	}
	_, err = StoreEvent(context.Background(), db, ev, []byte{1})
	if err == nil || !strings.Contains(err.Error(), "marshal event body") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadFlowEventsQueryCancelled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "load_flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = LoadFlowEvents(ctx, db, "tnt", "corr")
	if err == nil {
		t.Fatal("expected cancelled query error")
	}
}

func TestFlowBoundsAndModeIterateCancelled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds_cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = FlowBoundsAndMode(ctx, db, "tnt", "corr")
	if err == nil || !strings.Contains(err.Error(), "query bounds") {
		t.Fatalf("err=%v", err)
	}
}
