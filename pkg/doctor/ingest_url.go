package doctor

import (
	"net"
	"net/url"
	"strings"
)

// ingestURLsEquivalent reports whether two ingest event endpoints target the
// same service, treating localhost and 127.0.0.1 as equivalent.
func ingestURLsEquivalent(a, b string) bool {
	return normalizeIngestEndpoint(a) == normalizeIngestEndpoint(b)
}

func normalizeIngestEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		port = ""
	}
	host = strings.ToLower(host)
	switch host {
	case "localhost", "127.0.0.1", "::1":
		host = "local-loop"
	}
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://" + host + ":" + port + path
}
