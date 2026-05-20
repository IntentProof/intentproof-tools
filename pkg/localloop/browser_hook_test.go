package localloop

import (
	"os"
	"testing"
	"time"
)

func TestSetLaunchBrowserHook(t *testing.T) {
	called := false
	restore := SetLaunchBrowserHook(func(string) error {
		called = true
		return nil
	})
	defer restore()
	if err := launchBrowser("http://localhost:1/"); err != nil || !called {
		t.Fatalf("called=%v err=%v", called, err)
	}
	restoreNil := SetLaunchBrowserHook(nil)
	defer restoreNil()
}

func TestMaybeOpenLocalDashboardUsesHook(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "1")
	done := make(chan string, 1)
	restore := SetLaunchBrowserHook(func(url string) error {
		done <- url
		return nil
	})
	defer restore()
	MaybeOpenLocalDashboard("http://localhost:9789")
	select {
	case url := <-done:
		if url != "http://localhost:9789/" {
			t.Fatalf("url=%s", url)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestOpenLocalDashboardBrowserDisabledInCI(t *testing.T) {
	t.Setenv("CI", "true")
	attempted, err := OpenLocalDashboardBrowser("http://localhost:9789")
	if err != nil || attempted {
		t.Fatalf("attempted=%v err=%v", attempted, err)
	}
}

func TestLocalDashboardAutoOpenEnabledRespectsEnv(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "off")
	if LocalDashboardAutoOpenEnabled() {
		t.Fatal("expected disabled")
	}
	t.Setenv(EnvLocalOpenBrowser, "")
	if LocalDashboardAutoOpenEnabled() {
		t.Fatal("expected disabled by default under go test")
	}
	t.Setenv(EnvLocalOpenBrowser, "1")
	if !LocalDashboardAutoOpenEnabled() {
		t.Fatal("expected enabled when explicitly enabled")
	}
	_ = os.Unsetenv(EnvLocalOpenBrowser)
}
