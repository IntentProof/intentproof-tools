package localloop

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
)

// FlowBuilder consumes committed events from NATS and materializes flows.
type FlowBuilder struct {
	db   *sql.DB
	nats *NATSWrapper
}

// NewFlowBuilder creates a new flow builder.
func NewFlowBuilder(db *sql.DB, nats *NATSWrapper) *FlowBuilder {
	return &FlowBuilder{db: db, nats: nats}
}

// Run starts the flow builder subscription. It blocks until the context is
// cancelled.
func (fb *FlowBuilder) Run(ctx context.Context) error {
	sub, err := fb.nats.SubscribeEventCommitted(ctx, func(msg *nats.Msg) {
		if err := fb.handle(ctx, msg.Data); err != nil {
			fmt.Printf("flowbuilder: handle error: %v\n", err)
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer sub.Unsubscribe()

	<-ctx.Done()
	return ctx.Err()
}

func (fb *FlowBuilder) handle(ctx context.Context, data []byte) error {
	var env CommitEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.TenantID == "" || env.CorrelationID == "" || env.EventID == "" {
		return fmt.Errorf("missing envelope fields")
	}

	events, err := LoadFlowEvents(ctx, fb.db, env.TenantID, env.CorrelationID)
	if err != nil {
		return fmt.Errorf("load events: %w", err)
	}
	if len(events) == 0 {
		return fmt.Errorf("no events for correlation")
	}

	root := ComputeMerkleRoot(events)
	openedAt, closedAt, mode, err := FlowBoundsAndMode(ctx, fb.db, env.TenantID, env.CorrelationID)
	if err != nil {
		return fmt.Errorf("bounds: %w", err)
	}

	flowID := fmt.Sprintf("flow_%s_%s", env.CorrelationID, env.EventID)
	snapshotURI := fmt.Sprintf("local://snapshot/%s", flowID)

	snapshotEvents := make([]SnapshotEvent, 0, len(events))
	for i, e := range events {
		snapshotEvents = append(snapshotEvents, SnapshotEvent{
			EventID: e.EventID,
			Ordinal: i,
			Hash:    HexRoot(e.Hash),
		})
	}

	snap := FlowSnapshot{
		Schema:        "intentproof.flow.v1",
		FlowID:        flowID,
		TenantID:      env.TenantID,
		CorrelationID: env.CorrelationID,
		Window: SnapshotWindow{
			OpenedAt:      openedAt,
			ClosedAt:      closedAt,
			ClosureReason: "event_committed",
		},
		Events:              snapshotEvents,
		InstrumentationMode: mode,
		FlowMerkleRoot:      HexRoot(root),
		SnapshotURI:         snapshotURI,
	}

	if err := UpsertFlow(ctx, fb.db, snap); err != nil {
		return fmt.Errorf("upsert flow: %w", err)
	}

	msg := map[string]any{
		"tenant_id":      env.TenantID,
		"flow_id":        flowID,
		"correlation_id": env.CorrelationID,
		"event_count":    len(events),
		"snapshot_uri":   snapshotURI,
	}
	body, _ := json.Marshal(msg)
	if fb.nats != nil {
		if err := fb.nats.PublishFlowMaterialized(env.TenantID, body); err != nil {
			return fmt.Errorf("publish flow: %w", err)
		}
	}
	return nil
}
