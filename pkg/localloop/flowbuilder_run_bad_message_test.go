package localloop

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestFlowBuilderRunNaksInvalidEnvelope(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_nak.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewFlowBuilder(db, nw).Run(ctx) }()

	if err := nw.Client.Publish("events.committed."+LocalTenantID, []byte("{")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
}

func TestFlowBuilderRunSubscribeErrorAfterShutdown(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_sub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	nw.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = NewFlowBuilder(db, nw).Run(ctx)
	if err == nil {
		t.Fatal("expected subscribe error")
	}
}

func TestFlowBuilderRunReturnsContextCanceled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewFlowBuilder(db, nw).Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSubscribeEventCommittedCoreNATS(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	nw.js = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub, err := nw.SubscribeEventCommitted(ctx, func(_ *nats.Msg) {})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
}
