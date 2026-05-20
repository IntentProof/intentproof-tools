package localloop

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestStartEmbeddedNATSNewServerError(t *testing.T) {
	orig := natsNewServer
	natsNewServer = func(*server.Options) (*server.Server, error) {
		return nil, errors.New("new server fail")
	}
	t.Cleanup(func() { natsNewServer = orig })

	_, err := StartEmbeddedNATS(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "create nats server") {
		t.Fatalf("err=%v", err)
	}
}

func TestStartEmbeddedNATSServerReadyTimeout(t *testing.T) {
	orig := natsServerReady
	natsServerReady = func(*server.Server, time.Duration) bool { return false }
	t.Cleanup(func() { natsServerReady = orig })

	_, err := StartEmbeddedNATS(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "did not start in time") {
		t.Fatalf("err=%v", err)
	}
}

func TestStartEmbeddedNATSConnectClientError(t *testing.T) {
	orig := natsConnectClient
	natsConnectClient = func(string, ...nats.Option) (*nats.Conn, error) {
		return nil, errors.New("connect fail")
	}
	t.Cleanup(func() { natsConnectClient = orig })

	_, err := StartEmbeddedNATS(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "connect nats client") {
		t.Fatalf("err=%v", err)
	}
}

func TestStartEmbeddedNATSJetStreamError(t *testing.T) {
	orig := natsOpenJetStream
	natsOpenJetStream = func(*nats.Conn) (nats.JetStreamContext, error) {
		return nil, errors.New("jetstream fail")
	}
	t.Cleanup(func() { natsOpenJetStream = orig })

	_, err := StartEmbeddedNATS(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "jetstream") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureEventsStreamInfoUnexpectedError(t *testing.T) {
	orig := natsStreamInfo
	natsStreamInfo = func(nats.JetStreamContext, string) (*nats.StreamInfo, error) {
		return nil, errors.New("info boom")
	}
	t.Cleanup(func() { natsStreamInfo = orig })

	dir := t.TempDir()
	_, err := StartEmbeddedNATS(dir)
	if err == nil || !strings.Contains(err.Error(), "stream info") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureEventsStreamAddStreamError(t *testing.T) {
	origInfo := natsStreamInfo
	origAdd := natsAddStream
	natsStreamInfo = func(nats.JetStreamContext, string) (*nats.StreamInfo, error) {
		return nil, nats.ErrStreamNotFound
	}
	natsAddStream = func(nats.JetStreamContext, *nats.StreamConfig) (*nats.StreamInfo, error) {
		return nil, errors.New("add stream fail")
	}
	t.Cleanup(func() {
		natsStreamInfo = origInfo
		natsAddStream = origAdd
	})

	_, err := StartEmbeddedNATS(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "add stream") {
		t.Fatalf("err=%v", err)
	}
}

func TestPublishFlowMaterializedPublishError(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	nw.Shutdown()
	nw.Client = nil
	err = nw.PublishFlowMaterialized(LocalTenantID, []byte("{}"))
	if err == nil {
		t.Fatal("expected publish error on shutdown client")
	}
}
