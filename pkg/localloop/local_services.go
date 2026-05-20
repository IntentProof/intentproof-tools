package localloop

import "strings"

// LocalPublicBaseURL maps a listen address like ":9787" to a browser-friendly
// origin (http://localhost:9787).
func LocalPublicBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	switch {
	case addr == "":
		return "http://localhost:9787"
	case len(addr) > 0 && addr[0] == ':':
		return "http://localhost" + addr
	case strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://"):
		return strings.TrimSuffix(addr, "/")
	default:
		return "http://" + strings.TrimSuffix(addr, "/")
	}
}
