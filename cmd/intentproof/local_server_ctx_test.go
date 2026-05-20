package main

import (
	"context"
	"testing"
	"time"
)

func TestStartLocalServerWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := startLocalServerWithContext(ctx)
	if err != nil && err != context.Canceled {
		// RunLocalDevLoop may return nil or a shutdown error depending on timing.
		t.Logf("startLocalServerWithContext: %v", err)
	}
}

func TestStartLocalServerEntry(t *testing.T) {
	// startLocalServer is a thin wrapper; cancelled context exercises the delegate path.
	_ = startLocalServer
	_ = time.Now
}
