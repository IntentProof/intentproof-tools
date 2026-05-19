package initdetect

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func detectGo(root string) ([]Item, bool) {
	path := filepath.Join(root, "go.mod")
	if !fileExists(path) {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var out []Item
	out = append(out, Item{Label: "Go", Detail: "module (go.mod)"})
	out = append(out, Item{Label: "Package manager", Detail: "go mod"})

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "github.com/stripe/stripe-go") {
			out = append(out, Item{Label: "Stripe SDK", Detail: strings.TrimPrefix(line, "require ")})
			break
		}
	}
	return out, true
}
