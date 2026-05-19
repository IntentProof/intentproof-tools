package initdetect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectNodeStripeGitHubActions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
  "engines": {"node": "20.x"},
  "packageManager": "pnpm@9.0.0",
  "dependencies": {
    "stripe": "^15.0.0",
    "express": "^4.18.0",
    "@opentelemetry/api": "^1.8.0"
  },
  "devDependencies": {"vitest": "^1.0.0"}
}`)
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: ci\n")

	project, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := FormatReport(project)
	for _, want := range []string{
		"Node.js: 20.x",
		"Stripe SDK: stripe@^15.0.0",
		"CI: GitHub Actions",
		"Install the SDK: pnpm add @intentproof/sdk",
		"npx @intentproof/codegen wrap --action payments.refund.execute",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDetectUnknownProjectExplainsWhatWasChecked(t *testing.T) {
	project, err := Detect(t.TempDir())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := FormatReport(project)
	if project.Primary != "unknown" {
		t.Fatalf("primary=%q", project.Primary)
	}
	if !strings.Contains(out, "supported project manifest") {
		t.Fatalf("expected missing manifest note, got:\n%s", out)
	}
}

func TestRecommendPythonInstallCommands(t *testing.T) {
	tests := []struct {
		pm   string
		want string
	}{
		{"pip", "pip install intentproof"},
		{"pipenv", "pipenv install intentproof"},
		{"poetry", "poetry add intentproof"},
		{"uv", "uv add intentproof"},
		{"uv (uv.lock)", "uv add intentproof"},
	}
	for _, tc := range tests {
		got := pythonInstallCommand(pythonPackageManagerName(tc.pm))
		if got != tc.want {
			t.Fatalf("pm %q: got %q want %q", tc.pm, got, tc.want)
		}
	}
}

func TestDetectPythonPoetryAndUV(t *testing.T) {
	poetryRoot := t.TempDir()
	writeFile(t, filepath.Join(poetryRoot, "pyproject.toml"), "[project]\nname = \"demo\"\n")
	writeFile(t, filepath.Join(poetryRoot, "poetry.lock"), "")

	uvRoot := t.TempDir()
	writeFile(t, filepath.Join(uvRoot, "pyproject.toml"), "[project]\nname = \"demo\"\n")
	writeFile(t, filepath.Join(uvRoot, "uv.lock"), "")

	poetryProject, err := Detect(poetryRoot)
	if err != nil {
		t.Fatalf("Detect poetry: %v", err)
	}
	if !strings.Contains(FormatReport(poetryProject), "poetry add intentproof") {
		t.Fatalf("poetry report:\n%s", FormatReport(poetryProject))
	}

	uvProject, err := Detect(uvRoot)
	if err != nil {
		t.Fatalf("Detect uv: %v", err)
	}
	if !strings.Contains(FormatReport(uvProject), "uv add intentproof") {
		t.Fatalf("uv report:\n%s", FormatReport(uvProject))
	}
}

func TestStripeRefundTemplateIsPreviewOutline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"stripe":"^15.0.0"}}`)

	project, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := FormatStripeRefundTemplate(project)
	for _, want := range []string{
		"Stripe Refund Proof",
		"Path 3 wedge steps",
		"Wrap the refund call",
		"hosted reconciliation gates close",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
