package localloop

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// NATSWrapper manages an embedded NATS server and client connections.
type NATSWrapper struct {
	Server *server.Server
	Client *nats.Conn
}

// StartEmbeddedNATS starts an embedded NATS server on a free port and
// connects a client to it. The returned wrapper must be Shutdown when done.
func StartEmbeddedNATS() (*NATSWrapper, error) {
	opts := &server.Options{
		Port:    -1, // random free port
		Host:    "127.0.0.1",
		NoLog:   true,
		NoSigs:  true,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("create nats server: %w", err)
	}
	ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		return nil, fmt.Errorf("nats server did not start in time")
	}

	client, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		return nil, fmt.Errorf("connect nats client: %w", err)
	}

	return &NATSWrapper{Server: ns, Client: client}, nil
}

// URL returns the NATS client URL.
func (n *NATSWrapper) URL() string {
	if n.Server == nil {
		return ""
	}
	return n.Server.ClientURL()
}

// PublishEventCommitted publishes a committed event envelope.
func (n *NATSWrapper) PublishEventCommitted(env CommitEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return n.Client.Publish("events.committed."+env.TenantID, data)
}

// SubscribeEventCommitted subscribes to events.committed.*.
func (n *NATSWrapper) SubscribeEventCommitted(handler nats.MsgHandler) (*nats.Subscription, error) {
	return n.Client.Subscribe("events.committed.*", handler)
}

// PublishFlowMaterialized publishes a materialized flow.
func (n *NATSWrapper) PublishFlowMaterialized(tenantID string, data []byte) error {
	return n.Client.Publish("flows.materialized."+tenantID, data)
}

// SubscribeFlowMaterialized subscribes to flows.materialized.*.
func (n *NATSWrapper) SubscribeFlowMaterialized(handler nats.MsgHandler) (*nats.Subscription, error) {
	return n.Client.Subscribe("flows.materialized.*", handler)
}

// Shutdown cleanly stops the NATS server and client.
func (n *NATSWrapper) Shutdown() {
	if n.Client != nil {
		_ = n.Client.Drain()
		n.Client.Close()
	}
	if n.Server != nil {
		n.Server.Shutdown()
	}
}
