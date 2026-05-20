package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeHealthRejectsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := probeHealth(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected non-200 error")
	}
}

func TestProbeHealthUsesDefaultClientWhenNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := probeHealth(context.Background(), nil, srv.URL); err != nil {
		t.Fatal(err)
	}
}

func TestResolveReferencePoliciesDirHonorsEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("INTENTPROOF_REFERENCE_POLICIES_DIR", root)
	got, err := ResolveReferencePoliciesDir("")
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Fatalf("got=%s", got)
	}
}

func TestRequireDirRejectsRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := requireDir(f); err == nil {
		t.Fatal("expected not-a-directory error")
	}
}

func TestFormatAgentMarkdownIncludesFailureStatus(t *testing.T) {
	report := Report{
		Checks: []Check{
			{Name: "sdk config", Status: StatusFail, Detail: "broken", Hint: "fix it"},
		},
	}
	out := FormatAgentMarkdown(report)
	if !strings.Contains(out, "failed") || !strings.Contains(out, "fix it") {
		t.Fatalf("out=%s", out)
	}
}

func TestAdvisePresetNoRefundPresetMatch(t *testing.T) {
	msg := advisePreset(map[string]struct{}{"unknown.action": {}})
	if msg.Status != StatusWarn {
		t.Fatalf("status=%s summary=%s", msg.Status, msg.Summary)
	}
}

func TestCheckSDKConfigWarnsRemoteIngestWithoutToken(t *testing.T) {
	t.Setenv("INTENTPROOF_INGEST_URL", "https://ingest.example/v1/events")
	t.Setenv("INTENTPROOF_USE_LOCAL_INGEST", "")
	t.Setenv("INTENTPROOF_INGEST_TOKEN", "")
	checks := checkSDKConfig()
	found := false
	for _, c := range checks {
		if c.Name == "ingest auth" && c.Status == StatusWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("checks=%+v", checks)
	}
}
