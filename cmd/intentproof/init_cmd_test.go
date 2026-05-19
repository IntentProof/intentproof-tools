package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCommandDetectsNodeProject(t *testing.T) {
	root := t.TempDir()
	writeInitTestFile(t, filepath.Join(root, "package.json"), `{
  "dependencies": {"stripe": "^15.0.0"},
  "devDependencies": {"vitest": "^1.0.0"}
}`)
	writeInitTestFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: ci\n")

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	}()

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"init"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"IntentProof init",
		"Stripe SDK",
		"GitHub Actions",
		"Recommended setup",
		"@intentproof/codegen wrap --action payments.refund.execute",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestInitCommandTemplateStripeRefund(t *testing.T) {
	root := t.TempDir()
	writeInitTestFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"stripe":"^15.0.0"}}`)

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	}()

	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"init", "--template", "stripe-refund"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Path 3 wedge steps") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestInitCommandRejectsUnknownTemplate(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := run([]string{"init", "--template", "bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "unknown init template: bogus") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func writeInitTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
