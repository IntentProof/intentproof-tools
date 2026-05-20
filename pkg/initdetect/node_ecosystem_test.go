package initdetect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectNodeWithFullEcosystem(t *testing.T) {
	root := t.TempDir()
	pkg := `{
  "engines": {"node": ">=20"},
  "packageManager": "pnpm@9.0.0",
  "dependencies": {
    "stripe": "14.0.0",
    "@opentelemetry/api": "1.8.0",
    "express": "4.19.0",
    "vitest": "1.5.0"
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	items, ok := detectNode(root)
	if !ok {
		t.Fatal("expected node detection")
	}
	joined := joinDetectItems(items)
	for _, want := range []string{"Node.js", "Package manager", "Stripe SDK", "OpenTelemetry", "Express", "Vitest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
}

func TestDetectNodeEcosystemPackageManagerFromLockfiles(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
		{"bun.lockb", "bun"},
	}
	for _, tc := range cases {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"demo"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, tc.file), []byte("lock"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := detectNodePackageManager(root, packageJSON{})
		if !strings.Contains(got, tc.want) {
			t.Fatalf("file=%s got=%q", tc.file, got)
		}
	}
}

func TestDetectNodeInvalidJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	items, ok := detectNode(root)
	if !ok || len(items) == 0 || !strings.Contains(items[0].Detail, "invalid JSON") {
		t.Fatalf("items=%+v", items)
	}
}

func joinDetectItems(items []Item) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.Label)
		b.WriteByte(' ')
		b.WriteString(it.Detail)
		b.WriteByte(';')
	}
	return b.String()
}
