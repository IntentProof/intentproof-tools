package initdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectGitLabCIConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitlab-ci.yml"), []byte("test:\n  script: echo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items := detectCI(root)
	if len(items) == 0 {
		t.Fatal("expected gitlab ci detection")
	}
}

func TestDetectCircleCIConfig(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".circleci")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("version: 2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	items := detectCI(root)
	if len(items) == 0 {
		t.Fatal("expected circle ci detection")
	}
}

func TestNodeInstallCommandForYarn(t *testing.T) {
	if got := nodeInstallCommand("yarn"); got != "yarn add @intentproof/sdk" {
		t.Fatalf("got=%q", got)
	}
}

func TestNodeInstallCommandForBun(t *testing.T) {
	if got := nodeInstallCommand("bun"); got != "bun add @intentproof/sdk" {
		t.Fatalf("got=%q", got)
	}
}

func TestDetectEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"demo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	project, err := Detect("")
	if err != nil {
		t.Fatal(err)
	}
	if project.Primary != "node" {
		t.Fatalf("project=%+v", project)
	}
}

func TestAgentCommandFromStepWholeLineShell(t *testing.T) {
	_, cmd, ok := agentCommandFromStep("npm install")
	if !ok || cmd != "npm install" {
		t.Fatalf("cmd=%q ok=%v", cmd, ok)
	}
}

func TestLooksShellCommandRejectsEmpty(t *testing.T) {
	if looksShellCommand("") {
		t.Fatal("expected false")
	}
}
