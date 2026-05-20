package localloop

import (
	"testing"
)

func TestEventChainDigestRejectsInvalidEventBody(t *testing.T) {
	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_bad",
		TenantID:      "tnt",
		InstanceID:    "inst",
		CorrelationID: "corr",
		ChainPosition: 1,
		Attributes:    map[string]any{"bad": make(chan int)},
	}
	if _, err := EventChainDigest(ev); err == nil {
		t.Fatal("expected canonicalize error")
	}
}
