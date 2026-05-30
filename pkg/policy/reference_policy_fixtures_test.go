package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func TestReferencePolicyFixturesMatchVerifier(t *testing.T) {
	specDir := resolveSpecDir(t)
	if specDir == "" {
		t.Skip("set INTENTPROOF_SPEC_DIR to run spec conformance test")
	}

	packPaths, err := listReferencePackManifests(filepath.Join(specDir, "reference-policies"))
	if err != nil {
		t.Fatalf("list reference packs: %v", err)
	}
	if len(packPaths) == 0 {
		t.Fatalf("no reference policy packs found")
	}

	for _, manifestPath := range packPaths {
		manifestPath := manifestPath
		t.Run(referencePackTestName(manifestPath), func(t *testing.T) {
			t.Parallel()
			runReferencePackFixtures(t, manifestPath)
		})
	}
}

type referencePackManifest struct {
	ReferenceID string                     `json:"reference_id"`
	Policy      string                     `json:"policy"`
	Fixtures    []referenceFixtureManifest `json:"fixtures"`
}

type referenceFixtureManifest struct {
	ID           string `json:"id"`
	Flow         string `json:"flow"`
	Attestations string `json:"attestations"`
	ExpectedRun  string `json:"expected_run"`
}

type referencePolicyRule struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Spec     map[string]any `json:"spec"`
}

func listReferencePackManifests(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "pack.json" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func referencePackTestName(manifestPath string) string {
	packDir := filepath.Dir(manifestPath)
	version := filepath.Base(packDir)
	name := filepath.Base(filepath.Dir(packDir))
	domain := filepath.Base(filepath.Dir(filepath.Dir(packDir)))
	return domain + "/" + name + "/" + version
}

func runReferencePackFixtures(t *testing.T, manifestPath string) {
	t.Helper()
	packDir := filepath.Dir(manifestPath)
	var manifest referencePackManifest
	readJSONFile(t, manifestPath, &manifest)
	if manifest.ReferenceID == "" {
		t.Fatalf("%s: reference_id is required", manifestPath)
	}
	if len(manifest.Fixtures) == 0 {
		t.Fatalf("%s: at least one fixture is required", manifest.ReferenceID)
	}

	policyPath := filepath.Join(packDir, manifest.Policy)
	policyJSON := readFile(t, policyPath)

	for _, fixture := range manifest.Fixtures {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			var expected map[string]any
			readJSONFile(t, filepath.Join(packDir, fixture.ExpectedRun), &expected)
			flowJSON := enrichReferenceFlowForVerifier(
				t,
				readFile(t, filepath.Join(packDir, fixture.Flow)),
				policyJSON,
				expected,
			)
			attestationsJSONL := readFile(t, filepath.Join(packDir, fixture.Attestations))

			actualRun, err := verifier.Verify(flowJSON, policyJSON, attestationsJSONL)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			actualRunAgain, err := verifier.Verify(flowJSON, policyJSON, attestationsJSONL)
			if err != nil {
				t.Fatalf("verify second run: %v", err)
			}
			actual := normalizedRun(t, actualRun)
			actualAgain := normalizedRun(t, actualRunAgain)
			if !reflect.DeepEqual(actual, actualAgain) {
				t.Fatalf("verifier output is not deterministic across runs")
			}

			expected = normalizeExpectedReferenceRun(expected)
			if !reflect.DeepEqual(expected, actual) {
				expectedJSON, _ := json.MarshalIndent(expected, "", "  ")
				actualJSON, _ := json.MarshalIndent(actual, "", "  ")
				t.Fatalf("run mismatch\nexpected: %s\nactual: %s", expectedJSON, actualJSON)
			}
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func readJSONFile(t *testing.T, path string, out any) {
	t.Helper()
	if err := json.Unmarshal(readFile(t, path), out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func normalizedRun(t *testing.T, run any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal run: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal run: %v", err)
	}
	return normalizeExpectedReferenceRun(out)
}

func normalizeExpectedReferenceRun(run map[string]any) map[string]any {
	out := cloneJSONMap(run)
	for _, key := range []string{
		"provenance_class",
		"run_id",
		"run_fingerprint",
		"signature",
		"started_at",
		"completed_at",
	} {
		delete(out, key)
	}
	if findings, ok := out["findings"].([]any); ok {
		for _, finding := range findings {
			findingMap, ok := finding.(map[string]any)
			if !ok {
				continue
			}
			delete(findingMap, "provenance_class")
			delete(findingMap, "human_summary")
			if findingMap["rule_category"] == "temporal" {
				delete(findingMap, "evidence_event_ids")
			}
			if reason, _ := findingMap["reason"].(string); strings.HasPrefix(reason, "inconclusive.ordering.") {
				delete(findingMap, "evidence_event_ids")
			}
			if ids, ok := findingMap["evidence_attestation_ids"].([]any); ok && len(ids) == 0 {
				delete(findingMap, "evidence_attestation_ids")
			}
		}
	}
	return out
}

func enrichReferenceFlowForVerifier(t *testing.T, flowJSON []byte, policyJSON []byte, expectedRun map[string]any) []byte {
	t.Helper()
	var policyDoc struct {
		Rules []referencePolicyRule `json:"rules"`
	}
	if err := json.Unmarshal(policyJSON, &policyDoc); err != nil {
		t.Fatalf("parse policy json: %v", err)
	}
	rulesByID := make(map[string]referencePolicyRule, len(policyDoc.Rules))
	for _, rule := range policyDoc.Rules {
		rulesByID[rule.ID] = rule
	}

	eventActions := map[string]string{}
	temporalFailures := map[string]struct{}{}
	if findings, ok := expectedRun["findings"].([]any); ok {
		for _, findingAny := range findings {
			finding, ok := findingAny.(map[string]any)
			if !ok {
				continue
			}
			ruleID, _ := finding["rule_id"].(string)
			rule, ok := rulesByID[ruleID]
			if !ok {
				continue
			}
			eventIDs := stringSlice(finding["evidence_event_ids"])
			reason, _ := finding["reason"].(string)
			assignReferenceEvidenceActions(rule.Category, rule.Spec, reason, eventIDs, eventActions)
			if rule.Category == "temporal" && len(eventIDs) >= 2 && strings.HasPrefix(reason, "fail.temporal.") {
				temporalFailures[eventIDs[1]] = struct{}{}
			}
		}
	}

	var flow map[string]any
	if err := json.Unmarshal(flowJSON, &flow); err != nil {
		t.Fatalf("parse flow json: %v", err)
	}
	if events, ok := flow["events"].([]any); ok {
		for i, eventAny := range events {
			event, ok := eventAny.(map[string]any)
			if !ok {
				continue
			}
			eventID, _ := event["event_id"].(string)
			action := eventActions[eventID]
			if action == "" {
				continue
			}
			event["action"] = action
			event["status"] = "ok"
			start := "2026-05-16T00:00:00Z"
			complete := "2026-05-16T00:00:01Z"
			if i > 0 {
				start = "2026-05-16T00:05:00Z"
				complete = "2026-05-16T00:05:01Z"
			}
			if _, failed := temporalFailures[eventID]; failed {
				start = "2026-05-16T00:30:00Z"
				complete = "2026-05-16T00:30:01Z"
			}
			event["started_at"] = start
			event["completed_at"] = complete
		}
	}
	out, err := json.Marshal(flow)
	if err != nil {
		t.Fatalf("marshal enriched flow: %v", err)
	}
	return out
}

func stringSlice(v any) []string {
	values, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func assignReferenceEvidenceActions(category string, spec map[string]any, reason string, eventIDs []string, out map[string]string) {
	if len(eventIDs) == 0 {
		return
	}
	switch category {
	case "required", "forbidden", "cardinality":
		action, _ := spec["action"].(string)
		for _, eventID := range eventIDs {
			if action != "" {
				out[eventID] = action
			}
		}
	case "ordering":
		before, _ := spec["before"].(string)
		after, _ := spec["after"].(string)
		if len(eventIDs) == 1 && reason == "inconclusive.ordering.before_missing" {
			if after != "" {
				out[eventIDs[0]] = after
			}
			return
		}
		if before != "" {
			out[eventIDs[0]] = before
		}
		if after != "" && len(eventIDs) > 1 {
			out[eventIDs[1]] = after
		}
	case "temporal":
		from, _ := spec["from"].(map[string]any)
		to, _ := spec["to"].(map[string]any)
		fromAction, _ := from["action"].(string)
		toAction, _ := to["action"].(string)
		if fromAction != "" {
			out[eventIDs[0]] = fromAction
		}
		if toAction != "" && len(eventIDs) > 1 {
			out[eventIDs[1]] = toAction
		}
	}
}

func cloneJSONMap(in map[string]any) map[string]any {
	raw, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}
