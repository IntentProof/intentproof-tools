package initdetect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Project is the detected developer environment under Root.
type Project struct {
	Root      string
	Primary   string // node, python, go, unknown
	Detected  []Item
	NotFound  []string
	Recommend []string
}

// Item is one detected signal.
type Item struct {
	Label  string
	Detail string
}

// Detect scans root (typically the working directory) read-only.
func Detect(root string) (Project, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return Project{}, err
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		return Project{}, err
	}
	if !info.IsDir() {
		return Project{}, fmt.Errorf("%s is not a directory", root)
	}

	p := Project{Root: root}
	if node, ok := detectNode(root); ok {
		p.Primary = "node"
		p.Detected = append(p.Detected, node...)
	}
	if py, ok := detectPython(root); ok {
		if p.Primary == "" {
			p.Primary = "python"
		}
		p.Detected = append(p.Detected, py...)
	}
	if goItems, ok := detectGo(root); ok {
		if p.Primary == "" {
			p.Primary = "go"
		}
		p.Detected = append(p.Detected, goItems...)
	}
	if ci := detectCI(root); len(ci) > 0 {
		p.Detected = append(p.Detected, ci...)
	}
	if stripeCLI := detectStripeCLI(); stripeCLI != nil {
		p.Detected = append(p.Detected, *stripeCLI)
	} else {
		p.NotFound = append(p.NotFound, "Stripe CLI on PATH (stripe)")
	}

	if p.Primary == "" {
		p.Primary = "unknown"
		p.NotFound = append(p.NotFound, "supported project manifest (package.json, pyproject.toml, go.mod)")
	}
	p.Recommend = recommend(p)
	return p, nil
}

func detectStripeCLI() *Item {
	if _, err := exec.LookPath("stripe"); err != nil {
		return nil
	}
	return &Item{Label: "Stripe CLI", Detail: "stripe on PATH"}
}

func detectCI(root string) []Item {
	var out []Item
	if matchesGlob(root, ".github/workflows/*.yml") || matchesGlob(root, ".github/workflows/*.yaml") {
		out = append(out, Item{Label: "CI", Detail: "GitHub Actions (.github/workflows)"})
	}
	for _, path := range []struct {
		file  string
		label string
	}{
		{".gitlab-ci.yml", "GitLab CI"},
		{".circleci/config.yml", "CircleCI"},
		{"buildkite.yml", "Buildkite"},
	} {
		if fileExists(filepath.Join(root, path.file)) {
			out = append(out, Item{Label: "CI", Detail: path.label})
		}
	}
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func matchesGlob(root, pattern string) bool {
	matches, err := filepath.Glob(filepath.Join(root, pattern))
	return err == nil && len(matches) > 0
}

// FormatReport renders Detect output for the CLI.
func FormatReport(p Project) string {
	var b strings.Builder
	b.WriteString("IntentProof init\n\n")
	b.WriteString("Detected:\n")
	if len(p.Detected) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, item := range p.Detected {
			b.WriteString(fmt.Sprintf("  - %s: %s\n", item.Label, item.Detail))
		}
	}
	if len(p.NotFound) > 0 {
		b.WriteString("\nNot detected (looked for):\n")
		for _, line := range p.NotFound {
			b.WriteString("  - " + line + "\n")
		}
	}
	b.WriteString("\nRecommended setup:\n")
	for i, line := range p.Recommend {
		b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, line))
	}
	b.WriteString("\nNext:\n")
	b.WriteString("  intentproof demo refund\n")
	if p.Primary == "node" || hasStripe(p) {
		b.WriteString("  intentproof init --template stripe-refund   (guided wedge outline)\n")
	}
	return b.String()
}

func hasStripe(p Project) bool {
	for _, item := range p.Detected {
		if strings.Contains(strings.ToLower(item.Label), "stripe") {
			return true
		}
	}
	return false
}

func recommend(p Project) []string {
	switch p.Primary {
	case "node":
		return recommendNode(p)
	case "python":
		return recommendPython(p)
	case "go":
		return recommendGo(p)
	default:
		return []string{
			"Run from a project root with package.json, pyproject.toml, or go.mod",
			"Try the offline demo: intentproof demo refund",
		}
	}
}

func recommendNode(p Project) []string {
	pm := "npm"
	for _, item := range p.Detected {
		if item.Label == "Package manager" {
			pm = nodePackageManagerName(strings.Fields(item.Detail)[0])
		}
	}
	lines := []string{
		"Install the SDK: " + nodeInstallCommand(pm),
		"Wrap your refund handler: npx @intentproof/codegen wrap --action payments.refund.execute",
		"Use intent 'Issue refund to customer' for the first wrapped refund call",
		"Export INTENTPROOF_USE_LOCAL_INGEST=1 and run: intentproof local",
		"Call the wrapped refund function once, then run: intentproof reference list",
	}
	return lines
}

func nodePackageManagerName(detail string) string {
	if i := strings.Index(detail, "@"); i > 0 {
		return detail[:i]
	}
	return detail
}

func nodeInstallCommand(pm string) string {
	switch pm {
	case "pnpm":
		return "pnpm add @intentproof/sdk"
	case "yarn":
		return "yarn add @intentproof/sdk"
	case "bun":
		return "bun add @intentproof/sdk"
	default:
		return "npm install @intentproof/sdk"
	}
}

func recommendPython(p Project) []string {
	pm := "pip"
	for _, item := range p.Detected {
		if item.Label == "Package manager" {
			pm = pythonPackageManagerName(strings.Fields(item.Detail)[0])
		}
	}
	return []string{
		"Install the SDK: " + pythonInstallCommand(pm),
		"Wrap your refund handler with intentproof.wrap(intent=..., action='payments.refund.execute', fn=...)",
		"Export INTENTPROOF_USE_LOCAL_INGEST=1, run intentproof local, then invoke the wrapped function once",
	}
}

func pythonPackageManagerName(detail string) string {
	pm := strings.ToLower(strings.TrimSpace(detail))
	if i := strings.Index(pm, " "); i > 0 {
		pm = pm[:i]
	}
	if i := strings.Index(pm, "("); i > 0 {
		pm = strings.TrimSpace(pm[:i])
	}
	return pm
}

func pythonInstallCommand(pm string) string {
	switch pm {
	case "poetry":
		return "poetry add intentproof"
	case "uv":
		return "uv add intentproof"
	case "pipenv":
		return "pipenv install intentproof"
	default:
		return "pip install intentproof"
	}
}

func recommendGo(p Project) []string {
	return []string{
		"Add github.com/intentproof/intentproof-sdk-go when published for your module",
		"Wrap refund logic with the Go SDK wrap helper and action payments.refund.execute",
		"Export INTENTPROOF_USE_LOCAL_INGEST=1, run intentproof local, then invoke the wrapped function once",
	}
}

// FormatStripeRefundTemplate prints the Path 3 wedge outline (UX shell).
func FormatStripeRefundTemplate(p Project) string {
	var b strings.Builder
	b.WriteString("IntentProof init - Stripe Refund Proof (guided outline)\n\n")
	b.WriteString(FormatReport(p))
	b.WriteString("\n")
	b.WriteString("Path 3 wedge steps (complete when reconciliation adapters are live):\n")
	steps := []string{
		"Wrap the refund call (payments.refund.execute)",
		"Confirm correlation ID propagation (traceparent or run_with_correlation_id)",
		"Connect Stripe webhook (stripe listen or hosted tunnel)",
		"Verify webhook HMAC with: intentproof sources test <source_id>",
		"Activate preset: reference.payments.refund-with-notification.v1",
		"Run a test refund in Stripe test mode",
		"Trigger a deliberate divergence (see wedge MVP failure modes)",
		"Open the finding in the dashboard or: intentproof findings show <id>",
		"Export proof bundle: intentproof bundle export <run_id>",
	}
	for i, step := range steps {
		b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step))
	}
	b.WriteString("\n")
	b.WriteString("Note: end-to-end Path 3 against a live Stripe test account ships when\n")
	b.WriteString("hosted reconciliation gates close. Use intentproof demo refund today.\n")
	return b.String()
}
