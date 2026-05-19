package localloop

import (
	"os"
	"sync"
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

func withBrowserRecorder(t *testing.T) (getURL func() string, restore func()) {
	t.Helper()
	prev := launchBrowser
	var mu sync.Mutex
	var url string
	launchBrowser = func(u string) error {
		mu.Lock()
		url = u
		mu.Unlock()
		return nil
	}
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return url
	}, func() { launchBrowser = prev }
}

func waitForScheduledBrowserOpen(t *testing.T) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
}
