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
)

func TestStoreEventInsertExecFailure(t *testing.T) {
	orig := storeTxExec
	storeTxExec = func(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
		if strings.Contains(query, "INSERT INTO execution_events") {
			return nil, errors.New("insert fail")
		}
		return orig(ctx, tx, query, args...)
	}
	t.Cleanup(func() { storeTxExec = orig })

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "insert.db"))
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
	ev := mustSignedEventWithID(t, priv, "tnt_i", "inst_i", "corr_i", 1, sentinel, "demo.action", "evt_i")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil || !strings.Contains(err.Error(), "insert event") {
		t.Fatalf("err=%v", err)
	}
}

func TestOpenDBSchemaSQLExecFailure(t *testing.T) {
	orig := storeDBExec
	storeDBExec = func(db *sql.DB, query string) (sql.Result, error) {
		if strings.Contains(query, "CREATE TABLE") {
			return nil, errors.New("schema fail")
		}
		return orig(db, query)
	}
	t.Cleanup(func() { storeDBExec = orig })

	_, err := OpenDB(filepath.Join(t.TempDir(), "schema.db"))
	if err == nil || !strings.Contains(err.Error(), "migrate schema") {
		t.Fatalf("err=%v", err)
	}
}
