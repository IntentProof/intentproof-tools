package initdetect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDetectBlankRootUsesGetwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Detect("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Root != wd {
		t.Fatalf("root=%q wd=%q", p.Root, wd)
	}
}

func TestDetectRejectsFileRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file-root")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Detect(path)
	if err == nil {
		t.Fatal("expected not-a-directory error")
	}
}

func TestDetectStripeCLIWhenPresent(t *testing.T) {
	if _, err := exec.LookPath("stripe"); err != nil {
		t.Skip("stripe CLI not on PATH")
	}
	item := detectStripeCLI()
	if item == nil || item.Label == "" {
		t.Fatalf("item=%v", item)
	}
}
