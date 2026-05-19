package initdetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type packageJSON struct {
	Engines         map[string]string `json:"engines"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	PackageManager  string            `json:"packageManager"`
}

func detectNode(root string) ([]Item, bool) {
	path := filepath.Join(root, "package.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var pkg packageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return []Item{{Label: "Node.js", Detail: "package.json present but invalid JSON"}}, true
	}

	var out []Item
	if v := strings.TrimSpace(pkg.Engines["node"]); v != "" {
		out = append(out, Item{Label: "Node.js", Detail: v + " (package.json engines)"})
	} else {
		out = append(out, Item{Label: "Node.js", Detail: "project (package.json)"})
	}

	out = append(out, Item{Label: "Package manager", Detail: detectNodePackageManager(root, pkg)})

	deps := mergeDeps(pkg.Dependencies, pkg.DevDependencies)
	if v, ok := deps["stripe"]; ok {
		out = append(out, Item{Label: "Stripe SDK", Detail: "stripe@" + v})
	}
	if v, ok := deps["@opentelemetry/api"]; ok {
		out = append(out, Item{Label: "OpenTelemetry", Detail: "@opentelemetry/api@" + v})
	}
	for _, dep := range []struct {
		name  string
		label string
	}{
		{"express", "Express"},
		{"fastify", "Fastify"},
		{"next", "Next.js"},
		{"@nestjs/core", "NestJS"},
		{"bull", "Bull queue"},
		{"bullmq", "BullMQ queue"},
	} {
		if v, ok := deps[dep.name]; ok {
			out = append(out, Item{Label: "Framework", Detail: dep.label + " (" + dep.name + "@" + v + ")"})
		}
	}
	for _, dep := range []struct {
		name  string
		label string
	}{
		{"vitest", "Vitest"},
		{"jest", "Jest"},
	} {
		if v, ok := deps[dep.name]; ok {
			out = append(out, Item{Label: "Test runner", Detail: dep.label + " (" + dep.name + "@" + v + ")"})
		}
	}
	return out, true
}

func detectNodePackageManager(root string, pkg packageJSON) string {
	if pm := strings.TrimSpace(pkg.PackageManager); pm != "" {
		return pm + " (package.json packageManager)"
	}
	switch {
	case fileExists(filepath.Join(root, "pnpm-lock.yaml")):
		return "pnpm (pnpm-lock.yaml)"
	case fileExists(filepath.Join(root, "yarn.lock")):
		return "yarn (yarn.lock)"
	case fileExists(filepath.Join(root, "package-lock.json")):
		return "npm (package-lock.json)"
	case fileExists(filepath.Join(root, "bun.lockb")):
		return "bun (bun.lockb)"
	default:
		return "npm (default)"
	}
}

func mergeDeps(parts ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range parts {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
