package localloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const defaultEventsStream = "INTENTPROOF_EVENTS"

// NATSWrapper manages an embedded NATS server and client connections.
type NATSWrapper struct {
	Server *server.Server
	Client *nats.Conn
	js     nats.JetStreamContext
}

// StartEmbeddedNATS starts an embedded NATS server with JetStream enabled,
// ensures the events stream exists, and connects a client. jetStreamRoot is
// the directory used for JetStream file storage (typically the local data dir).
func StartEmbeddedNATS(jetStreamRoot string) (*NATSWrapper, error) {
	jsDir := filepath.Join(jetStreamRoot, "jetstream")
	if err := os.MkdirAll(jsDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir jetstream store: %w", err)
	}
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  jsDir,
		NoLog:     true,
		NoSigs:    true,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("create nats server: %w", err)
	}
	ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return nil, fmt.Errorf("nats server did not start in time")
	}

	client, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		return nil, fmt.Errorf("connect nats client: %w", err)
	}

	js, err := client.JetStream()
	if err != nil {
		_ = client.Drain()
		ns.Shutdown()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	if err := ensureEventsStream(js, defaultEventsStream); err != nil {
		_ = client.Drain()
		ns.Shutdown()
		return nil, err
	}

	return &NATSWrapper{Server: ns, Client: client, js: js}, nil
}

func ensureEventsStream(js nats.JetStreamContext, streamName string) error {
	_, err := js.StreamInfo(streamName)
	if err == nil {
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("stream info: %w", err)
	}
	_, err = js.AddStream(&nats.StreamConfig{
		Name:      streamName,
		Subjects:  []string{"events.committed.*"},
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		Replicas:  1,
		MaxAge:    24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("add stream %s: %w", streamName, err)
	}
	return nil
}

// URL returns the NATS client URL.
func (n *NATSWrapper) URL() string {
	if n.Server == nil {
		return ""
	}
	return n.Server.ClientURL()
}

func validateTenantID(tenant string) error {
	if tenant == "" {
		return fmt.Errorf("tenant_id is empty")
	}
	for _, r := range tenant {
		if r == '.' || r == '*' || r == '>' {
			return fmt.Errorf("tenant_id contains illegal NATS character %q", r)
		}
	}
	return nil
}

// PublishEventCommitted publishes a committed event envelope.
func (n *NATSWrapper) PublishEventCommitted(env CommitEnvelope) error {
	if err := validateTenantID(env.TenantID); err != nil {
		return fmt.Errorf("publish event committed: %w", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if n.js != nil {
		if _, err := n.js.Publish("events.committed."+env.TenantID, data); err != nil {
			return err
		}
		return nil
	}
	return n.Client.Publish("events.committed."+env.TenantID, data)
}

// SubscribeEventCommitted subscribes to events.committed.* (JetStream when
// available). The handler must Ack or Nak each JetStream message.
func (n *NATSWrapper) SubscribeEventCommitted(ctx context.Context, handler nats.MsgHandler) (*nats.Subscription, error) {
	if n.js != nil {
		return n.js.Subscribe("events.committed.*", handler,
			nats.Context(ctx),
			nats.Durable("intentproof-local-flow"),
			nats.ManualAck(),
		)
	}
	return n.Client.Subscribe("events.committed.*", handler)
}

// PublishFlowMaterialized publishes a materialized flow.
func (n *NATSWrapper) PublishFlowMaterialized(tenantID string, data []byte) error {
	if err := validateTenantID(tenantID); err != nil {
		return fmt.Errorf("publish flow materialized: %w", err)
	}
	return n.Client.Publish("flows.materialized."+tenantID, data)
}

// SubscribeFlowMaterialized subscribes to flows.materialized.*.
func (n *NATSWrapper) SubscribeFlowMaterialized(handler nats.MsgHandler) (*nats.Subscription, error) {
	return n.Client.Subscribe("flows.materialized.*", handler)
}

// Shutdown cleanly stops the NATS server and client.
func (n *NATSWrapper) Shutdown() {
	if n == nil {
		return
	}
	if n.Client != nil {
		_ = n.Client.Drain()
		n.Client.Close()
		n.Client = nil
	}
	if n.Server != nil {
		n.Server.Shutdown()
		n.Server.WaitForShutdown()
		n.Server = nil
	}
	n.js = nil
}
