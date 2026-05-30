package demo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type refundScenarioFile struct {
	Schema        string       `json:"schema"`
	Scenario      string       `json:"scenario"`
	HappyPath     scenarioPath `json:"happy_path"`
	DivergentPath scenarioPath `json:"divergent_path"`
}

type scenarioPath struct {
	CorrelationID  string   `json:"correlation_id"`
	Actions        []string `json:"actions"`
	StripeDemo     bool     `json:"stripe_demo"`
	ExpectedReason string   `json:"expected_reason"`
}

// RefundScenario is the loaded golden demo refund scenario.
type RefundScenario struct {
	Root          string
	PolicyYAML    []byte
	HappyPath     scenarioPath
	DivergentPath scenarioPath
	StripeBody    []byte
	StripeHeaders map[string]string
}

// LoadRefundScenario reads golden/demo fixtures for the refund demo.
func LoadRefundScenario() (RefundScenario, error) {
	root, err := GoldenDemoRoot()
	if err != nil {
		return RefundScenario{}, err
	}

	scenarioPath := filepath.Join(root, "scenarios", "refund.json")
	raw, err := os.ReadFile(scenarioPath)
	if err != nil {
		return RefundScenario{}, fmt.Errorf("read refund scenario: %w", err)
	}
	var doc refundScenarioFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return RefundScenario{}, fmt.Errorf("decode refund scenario: %w", err)
	}
	if doc.HappyPath.CorrelationID == "" || doc.DivergentPath.CorrelationID == "" {
		return RefundScenario{}, fmt.Errorf("refund scenario missing correlation ids")
	}

	policyPath := filepath.Join(root, "policies", "refund-with-notification.yaml")
	policyYAML, err := os.ReadFile(policyPath)
	if err != nil {
		return RefundScenario{}, fmt.Errorf("read demo policy: %w", err)
	}

	body, err := os.ReadFile(filepath.Join(root, "stripe", "refund-created.bytes"))
	if err != nil {
		return RefundScenario{}, fmt.Errorf("read stripe demo body: %w", err)
	}
	headersRaw, err := os.ReadFile(filepath.Join(root, "stripe", "refund-created.headers.json"))
	if err != nil {
		return RefundScenario{}, fmt.Errorf("read stripe demo headers: %w", err)
	}
	var headers map[string]string
	if err := json.Unmarshal(headersRaw, &headers); err != nil {
		return RefundScenario{}, fmt.Errorf("decode stripe demo headers: %w", err)
	}

	return RefundScenario{
		Root:          root,
		PolicyYAML:    policyYAML,
		HappyPath:     doc.HappyPath,
		DivergentPath: doc.DivergentPath,
		StripeBody:    body,
		StripeHeaders: headers,
	}, nil
}

// ExpectedBundleHashPath returns the golden expected bundle hash file when present.
func ExpectedBundleHashPath() (string, error) {
	root, err := GoldenDemoRoot()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "fixtures", "divergent-missing-notify", "expected-bundle-sha256.txt")
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}
