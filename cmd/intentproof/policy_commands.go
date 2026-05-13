package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func runPolicyLint(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof policy lint <policy.yaml>")
		return 1
	}

	result, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "lint failed: %v\n", err)
		return 1
	}

	parts := make([]string, 0, len(result.RuleCounts))
	for _, c := range result.RuleCounts {
		parts = append(parts, fmt.Sprintf("%s:%d", c.Category, c.Count))
	}

	fmt.Fprintln(stdout, "schema: OK")
	fmt.Fprintln(stdout, "semantic: OK")
	fmt.Fprintf(stdout, "rule count: %d (%s)\n", len(result.Policy.Rules), strings.Join(parts, ", "))
	fmt.Fprintf(stdout, "fingerprint: %s\n", result.Fingerprint)

	canonical, err := json.MarshalIndent(result.Policy, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "render canonical policy: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(canonical))

	return 0
}

func runPolicyTest(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof policy test <dir>")
		return 1
	}

	root := args[0]
	policyPath, err := findSinglePolicyYAML(root)
	if err != nil {
		fmt.Fprintf(stderr, "policy test failed: %v\n", err)
		return 1
	}

	compiled, err := policy.CompileFile(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy compile failed: %v\n", err)
		return 1
	}
	policyJSON, err := json.Marshal(compiled.Policy)
	if err != nil {
		fmt.Fprintf(stderr, "marshal canonical policy: %v\n", err)
		return 1
	}

	fixturesRoot := filepath.Join(root, "fixtures")
	fixtureDirs, err := listFixtureDirs(fixturesRoot)
	if err != nil {
		fmt.Fprintf(stderr, "policy test failed: %v\n", err)
		return 1
	}

	passed := 0
	generated := 0
	for _, dir := range fixtureDirs {
		name := filepath.Base(dir)
		ok, wasGenerated, runErr := runOneFixture(dir, policyJSON)
		if runErr != nil {
			fmt.Fprintf(stdout, "  x %s (%v)\n", name, runErr)
			continue
		}
		if ok {
			fmt.Fprintf(stdout, "  + %s\n", name)
			passed++
		} else {
			fmt.Fprintf(stdout, "  x %s (run mismatch)\n", name)
		}
		if wasGenerated {
			generated++
		}
	}

	fmt.Fprintf(stdout, "%d fixtures, %d passed", len(fixtureDirs), passed)
	if generated > 0 {
		fmt.Fprintf(stdout, ", %d generated", generated)
	}
	fmt.Fprintln(stdout)

	if passed != len(fixtureDirs) {
		return 1
	}
	return 0
}

func runOneFixture(dir string, policyJSON []byte) (bool, bool, error) {
	flowBytes, err := os.ReadFile(filepath.Join(dir, "flow.json"))
	if err != nil {
		return false, false, fmt.Errorf("read flow.json: %w", err)
	}
	attBytes, err := os.ReadFile(filepath.Join(dir, "attestations.jsonl"))
	if err != nil {
		return false, false, fmt.Errorf("read attestations.jsonl: %w", err)
	}

	run, err := verifier.Verify(flowBytes, policyJSON, attBytes)
	if err != nil {
		return false, false, err
	}
	runBytes, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return false, false, err
	}

	expectedPath := filepath.Join(dir, "expected-run.json")
	expectedBytes, err := os.ReadFile(expectedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if writeErr := os.WriteFile(expectedPath, append(runBytes, '\n'), 0o644); writeErr != nil {
				return false, false, writeErr
			}
			return true, true, nil
		}
		return false, false, err
	}

	var expected any
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		return false, false, fmt.Errorf("parse expected-run.json: %w", err)
	}
	var actual any
	if err := json.Unmarshal(runBytes, &actual); err != nil {
		return false, false, fmt.Errorf("parse actual run json: %w", err)
	}

	return jsonEqualIgnoreTimestamps(expected, actual), false, nil
}

func jsonEqualIgnoreTimestamps(expected, actual any) bool {
	expectedMap, _ := expected.(map[string]interface{})
	actualMap, _ := actual.(map[string]interface{})
	if expectedMap == nil || actualMap == nil {
		expectedNorm, _ := json.Marshal(expected)
		actualNorm, _ := json.Marshal(actual)
		return bytes.Equal(expectedNorm, actualNorm)
	}

	for _, key := range []string{"started_at", "completed_at"} {
		if _, ok := expectedMap[key]; !ok {
			return false
		}
		if _, ok := actualMap[key]; !ok {
			return false
		}
	}

	expectedClone := make(map[string]interface{}, len(expectedMap))
	for k, v := range expectedMap {
		expectedClone[k] = v
	}
	actualClone := make(map[string]interface{}, len(actualMap))
	for k, v := range actualMap {
		actualClone[k] = v
	}
	const sentinel = "<ignored>"
	expectedClone["started_at"] = sentinel
	expectedClone["completed_at"] = sentinel
	actualClone["started_at"] = sentinel
	actualClone["completed_at"] = sentinel

	expectedNorm, _ := json.Marshal(expectedClone)
	actualNorm, _ := json.Marshal(actualClone)
	return bytes.Equal(expectedNorm, actualNorm)
}

func listFixtureDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read fixtures directory: %w", err)
	}
	dirs := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		return nil, errors.New("no fixture directories found")
	}
	return dirs, nil
}

func findSinglePolicyYAML(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.Join(root, name))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", errors.New("no policy yaml file found in directory root")
	}
	if len(files) > 1 {
		return "", fmt.Errorf("multiple policy yaml files found: %s", strings.Join(files, ", "))
	}
	return files[0], nil
}

func runPolicyPublish(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof policy publish <policy.yaml>")
		return 1
	}

	result, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "compile failed: %v\n", err)
		return 1
	}

	// Optionally sign the policy if a signer is configured.
	bodyMap, err := maybeSignPolicy(result)
	if err != nil {
		fmt.Fprintf(stderr, "sign failed: %v\n", err)
		return 1
	}

	body, err := json.Marshal(bodyMap)
	if err != nil {
		fmt.Fprintf(stderr, "marshal policy: %v\n", err)
		return 1
	}

	record := struct {
		TenantID      string          `json:"tenant_id"`
		PolicyID      string          `json:"policy_id"`
		PolicyVersion int             `json:"policy_version"`
		Body          json.RawMessage `json:"body"`
	}{
		TenantID:      result.Policy.TenantID,
		PolicyID:      result.Policy.PolicyID,
		PolicyVersion: result.Policy.PolicyVersion,
		Body:          body,
	}

	payload, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(stderr, "marshal request: %v\n", err)
		return 1
	}

	apiURL := strings.TrimSpace(os.Getenv("INTENTPROOF_QUERY_API_URL"))
	if apiURL == "" {
		apiURL = "http://localhost:8090"
	}
	apiURL = strings.TrimRight(apiURL, "/")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/policies", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(stderr, "publish failed: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "publish failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(stdout, "published %s v%d\n", record.PolicyID, record.PolicyVersion)
		return 0
	case http.StatusBadRequest:
		fmt.Fprintf(stderr, "publish rejected: %s\n", strings.TrimSpace(string(respBody)))
		return 1
	default:
		fmt.Fprintf(stderr, "publish failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return 1
	}
}

// maybeSignPolicy injects signature and signed_at into the policy body when a
// signer is configured via environment. Returns the policy as a generic map.
func maybeSignPolicy(result *policy.CompileResult) (map[string]any, error) {
	raw, err := json.Marshal(result.Policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	var bodyMap map[string]any
	if err := json.Unmarshal(raw, &bodyMap); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}

	signer, err := crypto.NewPolicySignerFromEnv()
	if err != nil {
		return nil, fmt.Errorf("init signer: %w", err)
	}
	if signer == nil {
		return bodyMap, nil
	}

	payload, err := crypto.BuildPolicySignPayload(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("build sign payload: %w", err)
	}
	digest := sha256.Sum256(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env, err := signer.Sign(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	signedAt, err := crypto.ParseRFC3339OrNow("")
	if err != nil {
		return nil, fmt.Errorf("signed_at: %w", err)
	}

	bodyMap["signature"] = map[string]any{
		"alg":     env.Alg,
		"key_id":  env.KeyID,
		"value":   env.Value,
	}
	bodyMap["signed_at"] = signedAt.Format(time.RFC3339)
	return bodyMap, nil
}

func runPolicyDiff(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "Usage: intentproof policy diff <left.yaml> <right.yaml>")
		return 1
	}

	left, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "compile left failed: %v\n", err)
		return 1
	}

	right, err := policy.CompileFile(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "compile right failed: %v\n", err)
		return 1
	}

	diff := policy.Diff(left, right)
	fmt.Fprint(stdout, policy.FormatDiff(diff))

	if diff.Same {
		return 0
	}
	return 1
}

func runPolicyActivate(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "Usage: intentproof policy activate <policy_id> <version> --scope <scope> [--effective-at <RFC3339>] [--tenant-id <tenant_id>]")
		return 1
	}

	policyID := strings.TrimSpace(args[0])
	versionStr := strings.TrimSpace(args[1])
	version, err := strconv.Atoi(versionStr)
	if err != nil || version < 1 {
		fmt.Fprintf(stderr, "invalid policy version: %q\n", versionStr)
		return 1
	}

	scope := ""
	effectiveAt := time.Now().UTC().Format(time.RFC3339)
	tenantID := ""

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--scope":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--scope requires a value\n")
				return 1
			}
			scope = strings.TrimSpace(args[i+1])
			i++
		case "--effective-at":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--effective-at requires a value\n")
				return 1
			}
			effectiveAt = strings.TrimSpace(args[i+1])
			i++
		case "--tenant-id":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--tenant-id requires a value\n")
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

	if scope == "" {
		fmt.Fprintln(stderr, "--scope is required")
		return 1
	}
	if tenantID == "" {
		parts := strings.SplitN(policyID, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			tenantID = parts[0]
		}
	}
	if tenantID == "" {
		fmt.Fprintln(stderr, "tenant_id is required (extract from policy_id or use --tenant-id)")
		return 1
	}

	if _, err := time.Parse(time.RFC3339, effectiveAt); err != nil {
		fmt.Fprintf(stderr, "invalid effective-at: %v\n", err)
		return 1
	}

	payload, err := json.Marshal(map[string]interface{}{
		"tenant_id":      tenantID,
		"scope":          scope,
		"policy_id":      policyID,
		"policy_version": version,
		"effective_at":   effectiveAt,
	})
	if err != nil {
		fmt.Fprintf(stderr, "marshal request: %v\n", err)
		return 1
	}

	apiURL := strings.TrimSpace(os.Getenv("INTENTPROOF_QUERY_API_URL"))
	if apiURL == "" {
		apiURL = "http://localhost:8090"
	}
	apiURL = strings.TrimRight(apiURL, "/")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/policy-bindings", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(stderr, "activate failed: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "activate failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(stdout, "activated %s v%d for scope %q effective %s\n", policyID, version, scope, effectiveAt)
		return 0
	case http.StatusBadRequest:
		fmt.Fprintf(stderr, "activate rejected: %s\n", strings.TrimSpace(string(respBody)))
		return 1
	default:
		fmt.Fprintf(stderr, "activate failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return 1
	}
}
