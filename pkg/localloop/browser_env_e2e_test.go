package localloop

import "testing"

func TestLocalOpenBrowserDisabledVariants(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv(EnvLocalOpenBrowser, "off")
	if localOpenBrowserEnabled() || LocalDashboardAutoOpenEnabled() {
		t.Fatal("expected off")
	}
	attempted, err := OpenLocalDashboardBrowser("http://127.0.0.1:1")
	if err != nil || attempted {
		t.Fatalf("attempted=%v err=%v", attempted, err)
	}

	t.Setenv(EnvLocalOpenBrowser, "false")
	if localOpenBrowserEnabled() {
		t.Fatal("expected false")
	}
}
