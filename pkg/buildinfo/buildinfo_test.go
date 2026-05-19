package buildinfo

import "testing"

func TestStringFormatsToolName(t *testing.T) {
	got := String("intentproof")
	if got != "intentproof dev (unknown, unknown)" {
		t.Fatalf("got %q", got)
	}
}
