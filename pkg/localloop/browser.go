package localloop

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// EnvLocalOpenBrowser controls whether `intentproof local` opens the dashboard
// in the default browser after startup. Set to "0", "false", "no", or "off" to
// skip. The process CI environment variable (non-empty) also disables opens.
const EnvLocalOpenBrowser = "INTENTPROOF_LOCAL_OPEN_BROWSER"

// MaybeOpenLocalDashboard schedules opening the dashboard URL in the system
// default browser. It is non-blocking and no-ops when disabled or on
// unsupported configurations.
func MaybeOpenLocalDashboard(dashboardOrigin string) {
	if !localOpenBrowserEnabled() {
		return
	}
	url := strings.TrimSuffix(strings.TrimSpace(dashboardOrigin), "/") + "/"
	time.AfterFunc(400*time.Millisecond, func() {
		_ = openDefaultBrowser(url)
	})
}

func localOpenBrowserEnabled() bool {
	if strings.TrimSpace(os.Getenv("CI")) != "" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvLocalOpenBrowser)))
	switch v {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func openDefaultBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// LocalDashboardAutoOpenEnabled reports whether startup will try to open the
// dashboard in the system browser (see MaybeOpenLocalDashboard).
func LocalDashboardAutoOpenEnabled() bool {
	return localOpenBrowserEnabled()
}
