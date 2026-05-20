package localloop

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFlowBuilderRunStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fb_run.db"))
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
	go func() {
		done <- NewFlowBuilder(db, nw).Run(ctx)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
