package demo

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type reasonCatalog struct {
	Version string        `json:"version"`
	Reasons []reasonEntry `json:"reasons"`
}

type reasonEntry struct {
	Code                string   `json:"code"`
	Description         string   `json:"description"`
	Title               string   `json:"title"`
	TypicalCauses       []string `json:"typical_causes"`
	RemediationTemplate string   `json:"remediation_template"`
	DocumentationURL    string   `json:"documentation_url"`
}

// ReasonCopy is catalog-authored finding copy for CLI rendering.
type ReasonCopy struct {
	Code             string
	Title            string
	Description      string
	TypicalCauses    []string
	Remediation      string
	DocumentationURL string
}

// LoadReasonCopy loads signed catalog copy for a reason code.
func LoadReasonCopy(code string) (ReasonCopy, error) {
	path, err := SpecSemanticsPath()
	if err != nil {
		return ReasonCopy{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ReasonCopy{}, fmt.Errorf("read reason catalog: %w", err)
	}
	var cat reasonCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return ReasonCopy{}, fmt.Errorf("decode reason catalog: %w", err)
	}
	for _, entry := range cat.Reasons {
		if entry.Code != code {
			continue
		}
		title := entry.Title
		if title == "" {
			title = entry.Description
		}
		return ReasonCopy{
			Code:             entry.Code,
			Title:            title,
			Description:      entry.Description,
			TypicalCauses:    append([]string(nil), entry.TypicalCauses...),
			Remediation:      entry.RemediationTemplate,
			DocumentationURL: entry.DocumentationURL,
		}, nil
	}
	return ReasonCopy{}, fmt.Errorf("reason code %q not found in catalog", code)
}

// FormatFindingCopy renders catalog copy for terminal output.
func FormatFindingCopy(copy ReasonCopy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Finding: %s\n", copy.Code)
	fmt.Fprintf(&b, "  %s\n", copy.Title)
	if copy.Description != "" && copy.Description != copy.Title {
		fmt.Fprintf(&b, "\n  %s\n", copy.Description)
	}
	if len(copy.TypicalCauses) > 0 {
		fmt.Fprintf(&b, "\n  Why it matters\n")
		for _, cause := range copy.TypicalCauses {
			fmt.Fprintf(&b, "    - %s\n", cause)
		}
	}
	if copy.DocumentationURL != "" {
		fmt.Fprintf(&b, "\n  Docs: %s\n", copy.DocumentationURL)
	}
	return b.String()
}
