package localloop

import "time"

// Signature is the Ed25519 event envelope.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// ExecutionEvent mirrors the intentproof.event.v1 schema.
type ExecutionEvent struct {
	Schema        string         `json:"schema"`
	EventID       string         `json:"event_id"`
	TenantID      string         `json:"tenant_id"`
	InstanceID    string         `json:"instance_id"`
	CorrelationID string         `json:"correlation_id"`
	PrevEventHash string         `json:"prev_event_hash"`
	ChainPosition int            `json:"chain_position"`
	Intent        string         `json:"intent"`
	Action        string         `json:"action"`
	Status        string         `json:"status"`
	StartedAt     time.Time      `json:"started_at"`
	CompletedAt   time.Time      `json:"completed_at"`
	DurationMS    int            `json:"duration_ms"`
	Inputs        any            `json:"inputs"`
	Output        any            `json:"output"`
	Error         any            `json:"error"`
	Attributes    map[string]any `json:"attributes"`
	SpecVersion   string         `json:"spec_version"`
	SDKVersion    string         `json:"sdk_version"`
	Signature     Signature      `json:"signature"`
}

// CommitEnvelope is the lightweight NATS message sent after ingest.
type CommitEnvelope struct {
	TenantID      string `json:"tenant_id"`
	EventID       string `json:"event_id"`
	CorrelationID string `json:"correlation_id"`
	Action        string `json:"action"`
}

// SnapshotEvent is a single event inside a flow snapshot.
type SnapshotEvent struct {
	EventID string `json:"event_id"`
	Ordinal int    `json:"ordinal"`
	Hash    string `json:"hash"`
}

// SnapshotWindow captures the time bounds of a flow.
type SnapshotWindow struct {
	OpenedAt      time.Time `json:"opened_at"`
	ClosedAt      time.Time `json:"closed_at"`
	ClosureReason string    `json:"closure_reason"`
}

// FlowSnapshot is the canonical JSON representation of a materialized flow.
type FlowSnapshot struct {
	Schema              string          `json:"schema"`
	FlowID              string          `json:"flow_id"`
	TenantID            string          `json:"tenant_id"`
	CorrelationID       string          `json:"correlation_id"`
	Window              SnapshotWindow  `json:"window"`
	Events              []SnapshotEvent `json:"events"`
	InstrumentationMode string          `json:"instrumentation_mode"`
	FlowMerkleRoot      string          `json:"flow_merkle_root"`
	SnapshotURI         string          `json:"snapshot_uri"`
}
