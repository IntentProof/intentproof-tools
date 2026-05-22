package main

import (
	"path/filepath"
	"testing"
)

func FuzzJCSCrossLanguage(f *testing.F) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		f.Skipf("repo root: %v", err)
	}
	cfg := defaultConfig()
	cfg.ScriptsDir = filepath.Join(repoRoot, "cmd", "jcs-differential-fuzz", "scripts")
	if _, err := resolveConfig(cfg); err != nil {
		f.Skipf("sdk layout unavailable: %v", err)
	}

	f.Add([]byte("jcs-diff-fuzz-seed"))
	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) == 0 {
			seed = []byte("empty")
		}
		raw := buildEventFromSeed(seed)
		if err := compareInput(t.Context(), cfg, raw); err != nil {
			t.Fatalf("divergence: %v", err)
		}
	})
}
