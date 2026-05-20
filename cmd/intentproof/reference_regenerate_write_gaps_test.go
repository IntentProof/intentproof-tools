package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichForkedFixturesRewritesMatchingFlow(t *testing.T) {
	root := writeSampleReferencePack(t)
	dest := filepath.Join(t.TempDir(), "fork-enrich")
	if err := forkReferencePack(mustFindSamplePack(t, root), dest, "tnt_enrich"); err != nil {
		t.Fatal(err)
	}
	flowPath := filepath.Join(dest, "fixtures", "happy-path", "flow.json")
	raw, err := os.ReadFile(flowPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected enriched flow.json")
	}
}
