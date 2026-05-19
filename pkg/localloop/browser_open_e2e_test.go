package localloop

import "testing"

func TestMaybeOpenLocalDashboardEnabled(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "1")
	if !LocalDashboardAutoOpenEnabled() {
		t.Fatal("expected enabled")
	}

	called, restore := withBrowserRecorder(t)
	defer restore()

	attempted, err := OpenLocalDashboardBrowser("http://127.0.0.1:19999")
	if err != nil {
		t.Fatal(err)
	}
	if !attempted {
		t.Fatal("expected launch attempt")
	}
	if *called != "http://127.0.0.1:19999/" {
		t.Fatalf("url=%q", *called)
	}

	called2, restore2 := withBrowserRecorder(t)
	defer restore2()
	MaybeOpenLocalDashboard("http://127.0.0.1:19998")
	waitForScheduledBrowserOpen(t)
	if *called2 != "http://127.0.0.1:19998/" {
		t.Fatalf("scheduled url=%q", *called2)
	}
}

func TestLocalOpenBrowserDisabledInCI(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv(EnvLocalOpenBrowser, "1")
	if localOpenBrowserEnabled() {
		t.Fatal("expected disabled in CI")
	}
}
