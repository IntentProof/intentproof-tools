package localloop

import "testing"

func TestFormatChainHashAndReduceFlowMode(t *testing.T) {
	var d [32]byte
	d[0] = 0xab
	got := FormatChainHash(d)
	if got != "sha256:ab00000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("hash=%s", got)
	}
	if reduceFlowMode([]string{modeFull, modeMinimal}) != modeMinimal {
		t.Fatalf("reduce=%s", reduceFlowMode([]string{modeFull, modeMinimal}))
	}
	if modeRank(modeMinimal) >= modeRank(modeFull) {
		t.Fatal("minimal should rank lower than full")
	}
}

func TestReduceFlowModeDefaultForUnknown(t *testing.T) {
	if got := reduceFlowMode([]string{"custom"}); got != defaultMode {
		t.Fatalf("got %s", got)
	}
	if got := reduceFlowMode(nil); got != defaultMode {
		t.Fatalf("empty got %s", got)
	}
}
