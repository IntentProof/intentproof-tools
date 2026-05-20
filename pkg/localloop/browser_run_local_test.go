package localloop

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestMaybeOpenLocalDashboardInvokesHook(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "1")

	var called bool
	restore := SetLaunchBrowserHook(func(u string) error {
		called = true
		if u != "http://127.0.0.1:9999/" {
			t.Fatalf("url=%s", u)
		}
		return nil
	})
	defer restore()

	MaybeOpenLocalDashboard("http://127.0.0.1:9999")
	time.Sleep(600 * time.Millisecond)
	if !called {
		t.Fatal("expected browser hook call")
	}
}

func TestLocalOpenBrowserEnabledExplicitOn(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "yes")
	if !localOpenBrowserEnabled() {
		t.Fatal("expected enabled")
	}
}

func TestLocalOpenBrowserDisabledValues(t *testing.T) {
	t.Setenv("CI", "")
	for _, v := range []string{"0", "false", "no", "off"} {
		t.Setenv(EnvLocalOpenBrowser, v)
		if localOpenBrowserEnabled() {
			t.Fatalf("value %q should disable", v)
		}
	}
}

func TestRunLocalDevLoopRequiresHome(t *testing.T) {
	err := RunLocalDevLoop(context.Background(), LocalDevConfig{})
	if err == nil {
		t.Fatal("expected home dir error")
	}
}

func TestRunLocalDevLoopOpenBrowserPath(t *testing.T) {
	home := t.TempDir()
	ingestPort := freeTCPPortForBrowser(t)
	verifierPort := freeTCPPortForBrowser(t)
	dashboardPort := freeTCPPortForBrowser(t)

	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "1")
	var opened bool
	restore := SetLaunchBrowserHook(func(string) error {
		opened = true
		return nil
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunLocalDevLoop(ctx, LocalDevConfig{
			HomeDir:       home,
			IngestAddr:    "127.0.0.1:" + strconv.Itoa(ingestPort),
			VerifierAddr:  "127.0.0.1:" + strconv.Itoa(verifierPort),
			DashboardAddr: "127.0.0.1:" + strconv.Itoa(dashboardPort),
			OpenBrowser:   true,
			Stdout:        func(string) {},
		})
	}()
	time.Sleep(700 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
	if !opened {
		t.Fatal("expected open browser path")
	}
}

func freeTCPPortForBrowser(t *testing.T) int {
	t.Helper()
	return freeTCPPort(t)
}
