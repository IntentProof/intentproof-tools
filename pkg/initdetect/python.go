package initdetect

import (
	"os"
	"path/filepath"
	"strings"
)

func detectPython(root string) ([]Item, bool) {
	pyproject := filepath.Join(root, "pyproject.toml")
	reqs := filepath.Join(root, "requirements.txt")
	if !fileExists(pyproject) && !fileExists(reqs) {
		if fileExists(filepath.Join(root, "uv.lock")) {
			return detectPythonFromFiles(root, "uv (uv.lock)"), true
		}
		return nil, false
	}

	var out []Item
	pm := "pip"
	if fileExists(filepath.Join(root, "uv.lock")) {
		pm = "uv"
	} else if fileExists(filepath.Join(root, "poetry.lock")) {
		pm = "poetry"
	} else if fileExists(filepath.Join(root, "Pipfile.lock")) {
		pm = "pipenv"
	}
	out = append(out, Item{Label: "Python", Detail: "project"})
	out = append(out, Item{Label: "Package manager", Detail: pm})

	text := ""
	if fileExists(pyproject) {
		raw, err := os.ReadFile(pyproject)
		if err == nil {
			text += string(raw) + "\n"
		}
	}
	if fileExists(reqs) {
		raw, err := os.ReadFile(reqs)
		if err == nil {
			text += string(raw) + "\n"
		}
	}
	out = append(out, scanPythonDeps(text)...)
	return out, true
}

func detectPythonFromFiles(root, pm string) []Item {
	out := []Item{
		{Label: "Python", Detail: "project"},
		{Label: "Package manager", Detail: pm},
	}
	reqs := filepath.Join(root, "requirements.txt")
	if fileExists(reqs) {
		raw, _ := os.ReadFile(reqs)
		out = append(out, scanPythonDeps(string(raw))...)
	}
	return out
}

func scanPythonDeps(text string) []Item {
	var out []Item
	lower := strings.ToLower(text)
	if strings.Contains(lower, "stripe") {
		out = append(out, Item{Label: "Stripe SDK", Detail: "stripe (dependency)"})
	}
	if strings.Contains(lower, "opentelemetry-api") {
		out = append(out, Item{Label: "OpenTelemetry", Detail: "opentelemetry-api (dependency)"})
	}
	for _, dep := range []struct {
		name  string
		label string
	}{
		{"fastapi", "FastAPI"},
		{"flask", "Flask"},
		{"django", "Django"},
	} {
		if strings.Contains(lower, dep.name) {
			out = append(out, Item{Label: "Framework", Detail: dep.label + " (" + dep.name + ")"})
		}
	}
	if strings.Contains(lower, "celery") {
		out = append(out, Item{Label: "Queue", Detail: "Celery"})
	}
	return out
}
