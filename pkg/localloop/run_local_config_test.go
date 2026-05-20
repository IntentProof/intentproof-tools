package localloop

import (
	"context"
	"testing"
)

func TestRunLocalDevLoopRequiresHomeDir(t *testing.T) {
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}
