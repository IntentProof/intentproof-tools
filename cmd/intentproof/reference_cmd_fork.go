package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
	"gopkg.in/yaml.v3"
)

func runReferenceFork(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof reference fork <reference_id> --to <path> --tenant <tenant_id>")
		return 1
	}

	referenceID := strings.TrimSpace(args[0])
	toPath := ""
	tenantID := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--to":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintln(stderr, "--to requires a value")
				return 1
			}
			toPath = args[i+1]
			i++
		case "--tenant":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintln(stderr, "--tenant requires a value")
				return 1
			}
			tenantID = strings.TrimSpace(args[i+1])
			i++
		default:
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(stderr, "unknown flag: %s\n", args[i])
				return 1
			}
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			return 1
		}
	}
	if referenceID == "" {
		fmt.Fprintln(stderr, "reference_id is required")
		return 1
	}
	if toPath == "" {
		fmt.Fprintln(stderr, "--to is required")
		return 1
	}
	if tenantID == "" {
		fmt.Fprintln(stderr, "--tenant is required")
		return 1
	}

	pack, err := findReferencePack(referenceID)
	if err != nil {
		fmt.Fprintf(stderr, "reference fork failed: %v\n", err)
		return 1
	}
	if err := forkReferencePack(pack, toPath, tenantID); err != nil {
		fmt.Fprintf(stderr, "reference fork failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "forked %s to %s for tenant %s\n", referenceID, toPath, tenantID)
	return 0
}

func forkReferencePack(pack referencePack, dest string, tenantID string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := copyDir(pack.Dir, dest); err != nil {
		return err
	}

	policyYAMLRel := pack.Manifest.PolicyYAML
	if policyYAMLRel == "" {
		policyYAMLRel = "policy.yaml"
	}
	policyYAMLPath := filepath.Join(dest, policyYAMLRel)
	newPolicyID, compiled, err := stampPolicyYAML(policyYAMLPath, tenantID)
	if err != nil {
		return err
	}

	policyJSONRel := pack.Manifest.Policy
	if policyJSONRel == "" {
		policyJSONRel = "policy.json"
	}
	if err := writeCanonicalPolicyJSON(filepath.Join(dest, policyJSONRel), compiled); err != nil {
		return err
	}
	fixturesRoot := filepath.Join(dest, "fixtures")
	if err := stampFixtureTenants(fixturesRoot, tenantID); err != nil {
		return err
	}
	if err := enrichForkedFixtures(fixturesRoot, compiled); err != nil {
		return err
	}
	if err := regenerateExpectedRuns(dest, compiled); err != nil {
		return err
	}
	_ = newPolicyID
	return nil
}

func copyDir(src string, dest string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
}

func stampPolicyYAML(path string, tenantID string) (string, *policy.CompileResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", nil, fmt.Errorf("parse policy yaml: %w", err)
	}
	oldID, _ := doc["policy_id"].(string)
	newID := tenantPolicyID(oldID, tenantID)
	doc["tenant_id"] = tenantID
	doc["policy_id"] = newID

	withoutFingerprint, err := yaml.Marshal(doc)
	if err != nil {
		return "", nil, err
	}
	compiled, err := policy.Compile(withoutFingerprint)
	if err != nil {
		return "", nil, err
	}
	doc["policy_fingerprint"] = compiled.Fingerprint
	stamped, err := yaml.Marshal(doc)
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(path, stamped, 0o644); err != nil {
		return "", nil, err
	}
	return newID, compiled, nil
}

func tenantPolicyID(referenceID string, tenantID string) string {
	referenceID = strings.TrimSpace(referenceID)
	if strings.HasPrefix(referenceID, "reference.") {
		return tenantID + "." + strings.TrimPrefix(referenceID, "reference.")
	}
	if referenceID == "" {
		return tenantID + ".policy"
	}
	return tenantID + "." + referenceID
}

func writeCanonicalPolicyJSON(path string, compiled *policy.CompileResult) error {
	raw, err := json.MarshalIndent(compiled.Policy, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func stampFixtureTenants(fixturesRoot string, tenantID string) error {
	return filepath.WalkDir(fixturesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "flow.json" {
			return nil
		}
		return updateJSONFile(path, func(doc map[string]any) {
			doc["tenant_id"] = tenantID
		})
	})
}

func enrichForkedFixtures(fixturesRoot string, compiled *policy.CompileResult) error {
	fixtureDirs, err := listFixtureDirs(fixturesRoot)
	if err != nil {
		return err
	}
	for _, dir := range fixtureDirs {
		if err := enrichForkedFixture(dir, compiled); err != nil {
			return err
		}
	}
	return nil
}

func enrichForkedFixture(dir string, compiled *policy.CompileResult) error {
	expectedPath := filepath.Join(dir, "expected-run.json")
	raw, err := os.ReadFile(expectedPath)
	if err != nil {
		return err
	}
	var expected struct {
		Findings []struct {
			RuleID           string   `json:"rule_id"`
			Reason           string   `json:"reason"`
			EvidenceEventIDs []string `json:"evidence_event_ids"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		return fmt.Errorf("parse %s: %w", expectedPath, err)
	}

	eventActions := map[string]string{}
	temporalReasons := map[string]string{}
	rulesByID := map[string]policy.CanonicalRule{}
	for _, rule := range compiled.Policy.Rules {
		rulesByID[rule.ID] = rule
	}
	for _, finding := range expected.Findings {
		rule, ok := rulesByID[finding.RuleID]
		if !ok {
			continue
		}
		assignEvidenceActions(rule, finding.EvidenceEventIDs, eventActions)
		if rule.Category == "temporal" && len(finding.EvidenceEventIDs) >= 2 {
			temporalReasons[finding.EvidenceEventIDs[1]] = finding.Reason
		}
	}
	if len(eventActions) == 0 {
		return nil
	}

	flowPath := filepath.Join(dir, "flow.json")
	return updateJSONFile(flowPath, func(doc map[string]any) {
		events, _ := doc["events"].([]any)
		base := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC)
		for i, eventAny := range events {
			event, _ := eventAny.(map[string]any)
			if event == nil {
				continue
			}
			eventID, _ := event["event_id"].(string)
			action := eventActions[eventID]
			if action == "" {
				continue
			}
			event["action"] = action
			event["status"] = "ok"
			offset := time.Duration(i) * time.Minute
			if strings.HasPrefix(temporalReasons[eventID], "fail.temporal.") {
				offset = 30 * time.Minute
			}
			ts := base.Add(offset).Format(time.RFC3339)
			event["started_at"] = ts
			event["completed_at"] = base.Add(offset + time.Second).Format(time.RFC3339)
		}
	})
}

func assignEvidenceActions(rule policy.CanonicalRule, eventIDs []string, out map[string]string) {
	if len(eventIDs) == 0 {
		return
	}
	switch rule.Category {
	case "required", "forbidden", "cardinality":
		action, _ := rule.Spec["action"].(string)
		for _, eventID := range eventIDs {
			if action != "" {
				out[eventID] = action
			}
		}
	case "ordering":
		before, _ := rule.Spec["before"].(string)
		after, _ := rule.Spec["after"].(string)
		if len(eventIDs) > 0 && before != "" {
			out[eventIDs[0]] = before
		}
		if len(eventIDs) > 1 && after != "" {
			out[eventIDs[1]] = after
		}
	case "temporal":
		from, _ := rule.Spec["from"].(map[string]any)
		to, _ := rule.Spec["to"].(map[string]any)
		fromAction, _ := from["action"].(string)
		toAction, _ := to["action"].(string)
		if len(eventIDs) > 0 && fromAction != "" {
			out[eventIDs[0]] = fromAction
		}
		if len(eventIDs) > 1 && toAction != "" {
			out[eventIDs[1]] = toAction
		}
	}
}

func updateJSONFile(path string, update func(map[string]any)) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	update(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func regenerateExpectedRuns(packDir string, compiled *policy.CompileResult) error {
	policyJSON, err := json.Marshal(compiled.Policy)
	if err != nil {
		return err
	}
	fixtureDirs, err := listFixtureDirs(filepath.Join(packDir, "fixtures"))
	if err != nil {
		return err
	}
	for _, dir := range fixtureDirs {
		flowBytes, err := os.ReadFile(filepath.Join(dir, "flow.json"))
		if err != nil {
			return err
		}
		attBytes, err := os.ReadFile(filepath.Join(dir, "attestations.jsonl"))
		if err != nil {
			return err
		}
		run, err := verifier.Verify(flowBytes, policyJSON, attBytes)
		if err != nil {
			return err
		}
		runBytes, err := json.MarshalIndent(run, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "expected-run.json"), append(runBytes, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}
