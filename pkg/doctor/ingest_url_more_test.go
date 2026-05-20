package doctor

import "testing"

func TestNormalizeIngestEndpointVariants(t *testing.T) {
	if got := normalizeIngestEndpoint("http://localhost/v1/events"); got != "http://local-loop:80/v1/events" {
		t.Fatalf("localhost: %s", got)
	}
	if got := normalizeIngestEndpoint("https://127.0.0.1/v1/events"); got != "https://local-loop:443/v1/events" {
		t.Fatalf("https: %s", got)
	}
	if got := normalizeIngestEndpoint("not a url"); got != "not a url" {
		t.Fatalf("fallback: %s", got)
	}
}

func TestIngestURLsEquivalentLoopback(t *testing.T) {
	a := "http://127.0.0.1:9787/v1/events"
	b := "http://localhost:9787/v1/events"
	if !ingestURLsEquivalent(a, b) {
		t.Fatal("expected equivalent loopback ingest URLs")
	}
}
