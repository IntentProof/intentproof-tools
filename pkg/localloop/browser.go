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

// OpenLocalDashboardBrowser opens the dashboard URL in the default browser
// immediately when auto-open is enabled. Use this for short-lived commands
// that call os.Exit right after return: MaybeOpenLocalDashboard waits 400ms and
// the process may exit before the timer runs.
// The first return value reports whether a launch was attempted (false when
// disabled by CI or INTENTPROOF_LOCAL_OPEN_BROWSER).
func OpenLocalDashboardBrowser(dashboardOrigin string) (attempted bool, err error) {
	if !localOpenBrowserEnabled() {
		return false, nil
	}
	url := strings.TrimSuffix(strings.TrimSpace(dashboardOrigin), "/") + "/"
	return true, openDefaultBrowser(url)
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
