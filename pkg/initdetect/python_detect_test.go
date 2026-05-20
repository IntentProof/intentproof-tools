package initdetect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectPythonPyproject(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("stripe\nfastapi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items, ok := detectPython(root)
	if !ok {
		t.Fatal("expected detection")
	}
	text := formatItems(items)
	if !strings.Contains(text, "Stripe") || !strings.Contains(text, "FastAPI") {
		t.Fatalf("items=%v", items)
	}
}

func TestDetectPythonFromUVLock(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "uv.lock"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	items, ok := detectPython(root)
	if !ok {
		t.Fatal("expected uv.lock detection")
	}
	if !strings.Contains(items[1].Detail, "uv") {
		t.Fatalf("pm=%s", items[1].Detail)
	}
}

func TestDetectPythonFromFilesWithRequirements(t *testing.T) {
	root := t.TempDir()
	reqs := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(reqs, []byte("celery\nflask\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items := detectPythonFromFiles(root, "pip")
	if len(items) < 3 {
		t.Fatalf("items=%v", items)
	}
}

func formatItems(items []Item) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.Label)
		b.WriteString(it.Detail)
	}
	return b.String()
}
