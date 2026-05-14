package localloop

import (
	"testing"
	"time"
)

func TestEmbeddedNATSStarts(t *testing.T) {
	w, err := StartEmbeddedNATS(t.TempDir())
	if err != nil {
		t.Fatalf("start nats: %v", err)
	}
	defer w.Shutdown()
	t.Logf("NATS URL: %s", w.URL())
	time.Sleep(100 * time.Millisecond)
}
