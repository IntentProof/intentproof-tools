package localloop

import (
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	prev := launchBrowser
	launchBrowser = func(string) error { return nil }
	code := m.Run()
	launchBrowser = prev
	os.Exit(code)
}

func withBrowserRecorder(t *testing.T) (called *string, restore func()) {
	t.Helper()
	prev := launchBrowser
	url := ""
	launchBrowser = func(u string) error {
		url = u
		return nil
	}
	return &url, func() { launchBrowser = prev }
}

func waitForScheduledBrowserOpen(t *testing.T) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
}
