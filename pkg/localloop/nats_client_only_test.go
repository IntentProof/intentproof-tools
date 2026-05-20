package localloop

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSWrapperClientOnlyPublishAndSubscribe(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	nw.js = nil

	env := CommitEnvelope{TenantID: LocalTenantID, EventID: "evt_client", CorrelationID: "corr"}
	got := make(chan []byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = nw.SubscribeEventCommitted(ctx, func(msg *nats.Msg) {
		got <- msg.Data
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nw.PublishEventCommitted(env); err != nil {
		t.Fatal(err)
	}
	if err := nw.Client.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-got:
		var decoded CommitEnvelope
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.EventID != env.EventID {
			t.Fatalf("got %+v", decoded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestNATSWrapperURLNilServer(t *testing.T) {
	var nw NATSWrapper
	if got := nw.URL(); got != "" {
		t.Fatalf("url=%q", got)
	}
}

func TestNATSWrapperShutdownNil(t *testing.T) {
	var nw *NATSWrapper
	nw.Shutdown()
}

func TestNATSPublishFlowMaterializedRejectsBadTenant(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	if err := nw.PublishFlowMaterialized("bad*tenant", []byte("{}")); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestNATSEnsureEventsStreamAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	if err := ensureEventsStream(nw.js, defaultEventsStream); err != nil {
		t.Fatal(err)
	}
}

func TestNATSPublishEventCommittedConcurrent(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	var wg sync.WaitGroup
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func(n int) {
			defer wg.Done()
			_ = nw.PublishEventCommitted(CommitEnvelope{
				TenantID: LocalTenantID,
				EventID:  "evt_batch",
			})
		}(i)
	}
	wg.Wait()
}
