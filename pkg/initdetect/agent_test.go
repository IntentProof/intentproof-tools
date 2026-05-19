package initdetect

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatAgentMarkdownNodeProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
  "dependencies": {"stripe": "^15.0.0"},
  "packageManager": "pnpm@9.0.0"
}`)
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: ci\n")

	project, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := FormatAgentMarkdown(project)
	for _, want := range []string{
		"# IntentProof implementation guide",
		"## Detected environment",
		"**Stripe SDK:**",
		"## Do next (in order)",
		"```bash",
		"pnpm add @intentproof/sdk",
		"## Constraints",
		"do not infer intent",
		"intentproof demo refund",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatStripeRefundAgentMarkdown(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), "[project]\nname = \"demo\"\n")
	writeFile(t, filepath.Join(root, "poetry.lock"), "")

	project, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := FormatStripeRefundAgentMarkdown(project)
	if !strings.Contains(out, "poetry add intentproof") {
		t.Fatalf("expected poetry install command, got:\n%s", out)
	}
	if !strings.Contains(out, "## Path 3 wedge steps") {
		t.Fatalf("expected path 3 section, got:\n%s", out)
	}
}

func TestAgentCommandFromStep(t *testing.T) {
	desc, cmd, ok := agentCommandFromStep("Install the SDK: poetry add intentproof")
	if !ok || desc != "Install the SDK" || cmd != "poetry add intentproof" {
		t.Fatalf("got desc=%q cmd=%q ok=%v", desc, cmd, ok)
	}
	_, _, ok = agentCommandFromStep("Use intent 'Issue refund to customer' for the first wrapped refund call")
	if ok {
		t.Fatal("expected prose line to not extract shell command")
	}
}
