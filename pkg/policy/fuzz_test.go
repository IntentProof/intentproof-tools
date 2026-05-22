package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/fuzzcorpus"
)

var compileSeeds = [][]byte{
	[]byte(`policy_id: tnt.test
tenant_id: tnt
scope:
  match_action: demo.action
rules:
  - id: r1
    type: required
    action: demo.action
    min: 1
`),
	[]byte(`not: valid: yaml: [[`),
	[]byte(""),
}

func FuzzCompile(f *testing.F) {
	for _, seed := range compileSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Compile(data)
	})
}

func TestCompileSpecCorpus(t *testing.T) {
	dir := fuzzcorpus.Dir(t, "policy")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var ran int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read corpus: %v", err)
			}
			if _, err := Compile(data); err != nil {
				t.Fatalf("Compile golden corpus: %v", err)
			}
		})
	}
	if ran == 0 {
		t.Fatalf("no YAML corpus files under %s", dir)
	}
}
