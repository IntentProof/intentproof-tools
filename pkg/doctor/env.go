package doctor

import (
	"os"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

const defaultLocalIngestEventsURL = "http://127.0.0.1:9787/v1/events"

// ResolveIngestURL mirrors the Node SDK ingest URL resolution.
func ResolveIngestURL() (url string, source string) {
	if raw := strings.TrimSpace(os.Getenv("INTENTPROOF_INGEST_URL")); raw != "" {
		return normalizeIngestURL(raw), "INTENTPROOF_INGEST_URL"
	}
	if isTruthy(os.Getenv("INTENTPROOF_USE_LOCAL_INGEST")) {
		return defaultLocalIngestEventsURL, "INTENTPROOF_USE_LOCAL_INGEST"
	}
	return "", ""
}

func normalizeIngestURL(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasSuffix(trimmed, "/v1/events") {
		return trimmed
	}
	return trimmed + "/v1/events"
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// LocalLoopEndpoints returns public base URLs for the local loop services.
func LocalLoopEndpoints() (ingest, verifier, dashboard string) {
	ingestAddr := ":9787"
	if v := strings.TrimSpace(os.Getenv("INTENTPROOF_LOCAL_INGEST_ADDR")); v != "" {
		ingestAddr = v
	}
	verifierAddr := ":9788"
	if v := strings.TrimSpace(os.Getenv("INTENTPROOF_LOCAL_VERIFIER_ADDR")); v != "" {
		verifierAddr = v
	}
	dashboardAddr := ":9789"
	if v := strings.TrimSpace(os.Getenv("INTENTPROOF_LOCAL_DASHBOARD_ADDR")); v != "" {
		dashboardAddr = v
	}
	return localloop.LocalPublicBaseURL(ingestAddr),
		localloop.LocalPublicBaseURL(verifierAddr),
		localloop.LocalPublicBaseURL(dashboardAddr)
}

// LocalDataDir is ~/.intentproof/local.
func LocalDataDir(homeDir string) string {
	return strings.TrimRight(homeDir, "/") + "/.intentproof/local"
}

// SDKKeypairPath is the default Node SDK key file used by the local loop.
func SDKKeypairPath(homeDir string) string {
	return strings.TrimRight(homeDir, "/") + "/.intentproof/sdk-node/keypair.json"
}
