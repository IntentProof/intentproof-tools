package demo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenDemoRootFromEnv(t *testing.T) {
	spec := filepath.Join("..", "..", "..", "intentproof-spec")
	abs, err := filepath.Abs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "golden", "demo")); err != nil {
		t.Skip("intentproof-spec golden/demo not present")
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", abs)
	root, err := GoldenDemoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("root=%q", root)
	}
}

func TestGoldenDemoRootMissingEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_DIR", t.TempDir())
	if _, err := GoldenDemoRoot(); err == nil {
		t.Fatal("expected error for missing golden/demo")
	}
}

func TestLoadReasonCopyMissing(t *testing.T) {
	if _, err := LoadReasonCopy("fail.not.a.real.code"); err == nil {
		t.Fatal("expected missing reason error")
	}
}

func TestLoadRefundScenarioMissingFiles(t *testing.T) {
	root := t.TempDir()
	demoRoot := filepath.Join(root, "golden", "demo")
	if err := os.MkdirAll(filepath.Join(demoRoot, "scenarios"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(demoRoot, "scenarios", "refund.json"), []byte(`{"happy_path":{},"divergent_path":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INTENTPROOF_SPEC_DIR", root)
	if _, err := LoadRefundScenario(); err == nil {
		t.Fatal("expected missing correlation error")
	}
}

func TestSpecSemanticsPath(t *testing.T) {
	path, err := SpecSemanticsPath()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected path")
	}
}

func TestExpectedBundleHashPath(t *testing.T) {
	path, err := ExpectedBundleHashPath()
	if err != nil {
		t.Skip(err)
	}
	if path == "" {
		t.Fatal("expected path")
	}
}

func TestModuleRootWalk(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("missing go.mod in %s", root)
	}
}

func TestModuleRootFromChdirOutsideModule(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("missing go.mod in %s", root)
	}
}

func TestModuleRootFromSourceFileDirect(t *testing.T) {
	root, err := moduleRootFromSourceFile()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("missing go.mod in %s", root)
	}
}
