package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

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
	policyJSON, err := policyCmdJSONMarshal(compiled.Policy)
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
	runBytes, err := policyCmdJSONMarshalIndent(run, "", "  ")
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
