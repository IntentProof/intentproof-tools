package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Status is the outcome of a single diagnostic check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Check is one row in a doctor report.
type Check struct {
	Name   string
	Status Status
	Detail string
	Hint   string
}

// Report is the full output of doctor.Run.
type Report struct {
	Checks []Check
}

// HasFailures is true when any check failed.
func (r Report) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// Options configures doctor.Run.
type Options struct {
	HomeDir string
	Cwd     string
	Client  *http.Client
}

// Run collects diagnostics for SDK configuration and the local loop.
func Run(ctx context.Context, opts Options) Report {
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 3 * time.Second}
	}
	home := strings.TrimSpace(opts.HomeDir)
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Report{Checks: []Check{{
				Name:   "environment",
				Status: StatusFail,
				Detail: "home directory: " + err.Error(),
			}}}
		}
	}
	cwd := strings.TrimSpace(opts.Cwd)
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return Report{Checks: []Check{{
				Name:   "environment",
				Status: StatusFail,
				Detail: "working directory: " + err.Error(),
			}}}
		}
	}

	checks := make([]Check, 0, 16)
	checks = append(checks, checkSDKConfig()...)
	checks = append(checks, checkReferencePolicies(cwd)...)
	checks = append(checks, checkLocalData(ctx, home)...)
	checks = append(checks, checkLocalLoop(ctx, opts.Client)...)
	return Report{Checks: checks}
}

func checkSDKConfig() []Check {
	var out []Check

	ingestURL, source := ResolveIngestURL()
	if ingestURL == "" {
		out = append(out, Check{
			Name:   "sdk ingest",
			Status: StatusWarn,
			Detail: "no ingest URL configured",
			Hint:   "set INTENTPROOF_INGEST_URL or INTENTPROOF_USE_LOCAL_INGEST=1, then run intentproof local",
		})
	} else {
		out = append(out, Check{
			Name:   "sdk ingest",
			Status: StatusOK,
			Detail: ingestURL + " (from " + source + ")",
		})
	}

	token := strings.TrimSpace(os.Getenv("INTENTPROOF_INGEST_TOKEN"))
	if token == "" {
		if source == "INTENTPROOF_USE_LOCAL_INGEST" || strings.Contains(ingestURL, "127.0.0.1") || strings.Contains(ingestURL, "localhost") {
			out = append(out, Check{
				Name:   "ingest auth",
				Status: StatusOK,
				Detail: "INTENTPROOF_INGEST_TOKEN unset (not required for local ingest)",
			})
		} else if ingestURL != "" {
			out = append(out, Check{
				Name:   "ingest auth",
				Status: StatusWarn,
				Detail: "INTENTPROOF_INGEST_TOKEN unset",
				Hint:   "hosted ingest usually requires a tenant ingest token",
			})
		}
	} else {
		out = append(out, Check{
			Name:   "ingest auth",
			Status: StatusOK,
			Detail: "INTENTPROOF_INGEST_TOKEN is set",
		})
	}

	if tenant := strings.TrimSpace(os.Getenv("INTENTPROOF_TENANT_ID")); tenant != "" {
		out = append(out, Check{
			Name:   "sdk tenant",
			Status: StatusOK,
			Detail: "INTENTPROOF_TENANT_ID=" + tenant,
		})
	}

	return out
}

func checkReferencePolicies(cwd string) []Check {
	dir, err := ResolveReferencePoliciesDir(cwd)
	if err != nil {
		return []Check{{
			Name:   "reference policies",
			Status: StatusWarn,
			Detail: err.Error(),
			Hint:   "clone intentproof-spec or set INTENTPROOF_REFERENCE_POLICIES_DIR for policy tooling",
		}}
	}
	return []Check{{
		Name:   "reference policies",
		Status: StatusOK,
		Detail: dir,
	}}
}

func checkLocalData(ctx context.Context, home string) []Check {
	dataDir := LocalDataDir(home)
	dbPath := filepath.Join(dataDir, "local.db")
	keyPath := SDKKeypairPath(home)

	var out []Check

	if _, err := os.Stat(dataDir); err != nil {
		if os.IsNotExist(err) {
			out = append(out, Check{
				Name:   "local data",
				Status: StatusWarn,
				Detail: "data directory missing: " + dataDir,
				Hint:   "run intentproof local or intentproof demo refund to create it",
			})
		} else {
			out = append(out, Check{
				Name:   "local data",
				Status: StatusFail,
				Detail: "data directory: " + err.Error(),
			})
		}
	} else {
		out = append(out, Check{
			Name:   "local data",
			Status: StatusOK,
			Detail: dataDir,
		})
	}

	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			out = append(out, Check{
				Name:   "sdk keypair",
				Status: StatusWarn,
				Detail: "Node SDK keypair not found: " + keyPath,
				Hint:   "run your app once with @intentproof/sdk so the local loop can register the instance",
			})
		} else {
			out = append(out, Check{
				Name:   "sdk keypair",
				Status: StatusFail,
				Detail: err.Error(),
			})
		}
	} else {
		out = append(out, Check{
			Name:   "sdk keypair",
			Status: StatusOK,
			Detail: keyPath,
		})
	}

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			out = append(out, Check{
				Name:   "local database",
				Status: StatusSkip,
				Detail: "no local.db yet (local loop not started or no events ingested)",
			})
			out = append(out, presetCheck(presetAdvice{
				Status:  StatusSkip,
				Summary: "skipped (no local database)",
			}))
			return out
		}
		out = append(out, Check{
			Name:   "local database",
			Status: StatusFail,
			Detail: err.Error(),
		})
		return out
	}

	dbCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		dbCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	snap, err := inspectLocalDB(dbCtx, dbPath)
	if err != nil {
		out = append(out, Check{
			Name:   "local database",
			Status: StatusFail,
			Detail: "read " + dbPath + ": " + err.Error(),
		})
		return out
	}

	detail := fmt.Sprintf(
		"%d events, %d flows, %d registered SDK instances",
		snap.EventCount,
		snap.FlowCount,
		snap.SDKInstanceCount,
	)
	if snap.LastEventAt != "" {
		detail += "; last event " + formatLastEventAge(snap.LastEventAt)
	}
	status := StatusOK
	if snap.EventCount == 0 {
		status = StatusWarn
	}
	hint := ""
	if snap.EventCount == 0 {
		hint = "wrap a function and run your code, or try: intentproof demo refund"
	}
	out = append(out, Check{
		Name:   "local database",
		Status: status,
		Detail: detail,
		Hint:   hint,
	})

	observed := make(map[string]struct{}, len(snap.Actions))
	for action := range snap.Actions {
		observed[action] = struct{}{}
	}
	out = append(out, presetCheck(advisePreset(observed)))
	return out
}

func presetCheck(advice presetAdvice) Check {
	return Check{
		Name:   "flow preset hint",
		Status: advice.Status,
		Detail: advice.Summary,
		Hint:   advice.Hint,
	}
}

func checkLocalLoop(ctx context.Context, client *http.Client) []Check {
	ingestBase, verifierBase, dashboardBase := LocalLoopEndpoints()
	services := []struct {
		name string
		base string
	}{
		{"local ingest", ingestBase},
		{"local verifier", verifierBase},
		{"local dashboard", dashboardBase},
	}

	var out []Check
	anyReachable := false
	for _, svc := range services {
		err := probeHealth(ctx, client, svc.base)
		if err != nil {
			out = append(out, Check{
				Name:   svc.name,
				Status: StatusWarn,
				Detail: svc.base + " not reachable: " + err.Error(),
				Hint:   "start the local loop: intentproof local",
			})
			continue
		}
		anyReachable = true
		out = append(out, Check{
			Name:   svc.name,
			Status: StatusOK,
			Detail: svc.base + " healthy",
		})
	}
	if !anyReachable {
		return out
	}

	ingestURL, _ := ResolveIngestURL()
	if ingestURL == "" {
		out = append(out, Check{
			Name:   "ingest alignment",
			Status: StatusWarn,
			Detail: "local loop is up but SDK ingest URL is not configured",
			Hint:   "export INTENTPROOF_USE_LOCAL_INGEST=1 or INTENTPROOF_INGEST_URL=" + ingestBase + "/v1/events",
		})
		return out
	}

	want := strings.TrimRight(ingestBase, "/") + "/v1/events"
	if !ingestURLsEquivalent(ingestURL, want) {
		out = append(out, Check{
			Name:   "ingest alignment",
			Status: StatusWarn,
			Detail: fmt.Sprintf("SDK posts to %s but local ingest listens at %s", ingestURL, want),
			Hint:   "export INTENTPROOF_USE_LOCAL_INGEST=1 or INTENTPROOF_INGEST_URL=" + want,
		})
	} else {
		out = append(out, Check{
			Name:   "ingest alignment",
			Status: StatusOK,
			Detail: "SDK ingest URL matches the local loop",
		})
	}
	return out
}

// FormatReport renders a human-readable doctor report.
func FormatReport(r Report) string {
	var b strings.Builder
	b.WriteString("IntentProof doctor\n\n")
	for _, c := range r.Checks {
		b.WriteString(formatCheckLine(c))
		b.WriteByte('\n')
	}
	b.WriteString("\n")
	if r.HasFailures() {
		b.WriteString("Some checks failed. Fix the [fail] items above, then re-run: intentproof doctor\n")
	} else {
		b.WriteString("No blocking failures. Next: wrap a function, run your app, or try: intentproof demo refund\n")
	}
	b.WriteString("For agent-oriented output: intentproof doctor --agent\n")
	return b.String()
}

func formatCheckLine(c Check) string {
	line := fmt.Sprintf("[%s] %s: %s", string(c.Status), c.Name, c.Detail)
	if c.Hint != "" {
		line += "\n      → " + c.Hint
	}
	return line
}
