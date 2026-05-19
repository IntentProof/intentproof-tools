package initdetect

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectGoModuleWithStripe(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module example.com/demo

go 1.22

require github.com/stripe/stripe-go/v78 v78.0.0
`)
	project, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if project.Primary != "go" {
		t.Fatalf("primary=%q", project.Primary)
	}
	out := FormatReport(project)
	if !strings.Contains(out, "go mod") || !strings.Contains(out, "stripe-go") {
		t.Fatalf("report:\n%s", out)
	}
}

func TestDetectGoAgentMarkdown(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module demo\n\ngo 1.22\n")
	project, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	out := FormatAgentMarkdown(project)
	if !strings.Contains(out, "Primary stack") {
		t.Fatalf("agent markdown:\n%s", out)
	}
}
