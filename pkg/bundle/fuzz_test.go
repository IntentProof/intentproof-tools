package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/internal/fuzzcorpus"
)

var bundleSeeds = [][]byte{
	{},
	{0x00, 0x01, 0x02, 0x03},
	{0x28, 0xb5, 0x2f, 0xfd},
}

func FuzzBundleVerify(f *testing.F) {
	for _, seed := range bundleSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Verify(bytes.NewReader(data), nil)
	})
}

func TestBundleVerifySpecCorpus(t *testing.T) {
	dir := fuzzcorpus.Dir(t, "bundle")
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
		if filepath.Ext(name) != ".bin" {
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read corpus: %v", err)
			}
			if _, err := Verify(bytes.NewReader(data), nil); err != nil {
				t.Fatalf("Verify golden corpus: %v", err)
			}
		})
	}
	if ran == 0 {
		t.Fatalf("no .bin corpus files under %s", dir)
	}
}
