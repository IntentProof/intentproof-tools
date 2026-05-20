package localloop

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	restore := SetLaunchBrowserHook(func(string) error { return nil })
	code := m.Run()
	restore()
	os.Exit(code)
}

func withBrowserRecorder(t *testing.T) (getURL func() string, restore func()) {
	t.Helper()
	var mu sync.Mutex
	var url string
	restoreHook := SetLaunchBrowserHook(func(u string) error {
		mu.Lock()
		url = u
		mu.Unlock()
		return nil
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return url
	}, restoreHook
}

func waitForScheduledBrowserOpen(t *testing.T) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
}
