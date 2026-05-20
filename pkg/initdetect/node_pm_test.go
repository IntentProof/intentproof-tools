package initdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectNodePackageManagerFromLockfiles(t *testing.T) {
	root := t.TempDir()
	pkg := packageJSON{PackageManager: "pnpm@9.0.0"}
	if got := detectNodePackageManager(root, pkg); got != "pnpm@9.0.0 (package.json packageManager)" {
		t.Fatalf("packageManager: %s", got)
	}
	pkg.PackageManager = ""
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectNodePackageManager(root, pkg); got != "pnpm (pnpm-lock.yaml)" {
		t.Fatalf("pnpm: %s", got)
	}
}
