package localloop

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSPublishAndSubscribeFlowMaterialized(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	if nw.URL() == "" {
		t.Fatal("expected url")
	}

	payload := []byte(`{"flow_id":"f1"}`)

	var wg sync.WaitGroup
	wg.Add(1)
	_, err = nw.SubscribeFlowMaterialized(func(msg *nats.Msg) {
		if string(msg.Data) != string(payload) {
			t.Errorf("payload mismatch")
		}
		wg.Done()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nw.PublishFlowMaterialized(LocalTenantID, payload); err != nil {
		t.Fatal(err)
	}
	if err := nw.Client.Flush(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for flow materialized message")
	}
}

func TestNATSPublishEventCommittedAndSubscribe(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	env := CommitEnvelope{TenantID: LocalTenantID, EventID: "evt_1"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan []byte, 1)
	_, err = nw.SubscribeEventCommitted(ctx, func(msg *nats.Msg) {
		got <- msg.Data
		if msg.Reply != "" {
			_ = msg.Ack()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nw.PublishEventCommitted(env); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-got:
		var decoded CommitEnvelope
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.EventID != "evt_1" {
			t.Fatalf("got %+v", decoded)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestNATSPublishRejectsBadTenantID(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	if err := nw.PublishEventCommitted(CommitEnvelope{TenantID: "bad.tenant"}); err == nil {
		t.Fatal("expected tenant validation error")
	}
	if err := validateTenantID("has.dot"); err == nil {
		t.Fatal("expected illegal char")
	}
}
