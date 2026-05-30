package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestRunExplainReplayOnBundle(t *testing.T) {
	t.Setenv("INTENTPROOF_DETERMINISTIC_TIME", "1")
	path := writeExplainTestBundle(t)

	var explainOut, explainErr strings.Builder
	if code := run([]string{"explain", path}, &explainOut, &explainErr); code != 0 {
		t.Fatalf("explain code=%d stderr=%s", code, explainErr.String())
	}
	if !strings.Contains(explainOut.String(), "bundle.verify_pass") {
		t.Fatalf("explain out=%s", explainOut.String())
	}

	var replayOut, replayErr strings.Builder
	if code := run([]string{"replay", path}, &replayOut, &replayErr); code != 0 {
		t.Fatalf("replay code=%d stderr=%s", code, replayErr.String())
	}
	if !strings.Contains(replayOut.String(), `"status": "pass"`) {
		t.Fatalf("replay out=%s", replayOut.String())
	}
}

func TestRunExplainReplayHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"explain", "--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("explain help code=%d", code)
	}
	if code := run([]string{"replay", "--help"}, &stdout, &stderr); code != 1 {
		t.Fatalf("replay help code=%d", code)
	}
}

func writeExplainTestBundle(t *testing.T) string {
	t.Helper()
	flowJSON, _ := json.Marshal(map[string]interface{}{
		"flow_id":          "flow_cli",
		"tenant_id":        "tnt_test",
		"flow_merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	eventsJSONL := []byte("{\"event_id\":\"evt_1\",\"action\":\"pay\",\"status\":\"ok\"}\n")
	policyJSON := []byte(`{"policy_id":"p1","tenant_id":"tnt_test","policy_version":1,"rules":[]}`)
	runJSON := []byte(`{"status":"pass","findings":[]}`)

	var buf bytes.Buffer
	if err := bundle.Create(&buf, bundle.CreateOptions{
		BundleID:    "bnd_cli",
		FlowID:      "flow_cli",
		TenantID:    "tnt_test",
		FlowJSON:    flowJSON,
		EventsJSONL: eventsJSONL,
		PolicyJSON:  policyJSON,
		RunJSON:     runJSON,
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.proof.tar.zst")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
