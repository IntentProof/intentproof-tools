package doctor

import "testing"

func TestIsLocalIngestURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:9787/v1/events", true},
		{"http://localhost:9787/v1/events", true},
		{"http://[::1]:9787/v1/events", true},
		{"http://localhost.example.com:9787/v1/events", false},
		{"http://evil-127.0.0.1.fake:9787/v1/events", false},
		{"https://ingest.example.com/v1/events", false},
		{"not-a-url", false},
	}
	for _, tc := range tests {
		if got := isLocalIngestURL(tc.url); got != tc.want {
			t.Errorf("isLocalIngestURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
