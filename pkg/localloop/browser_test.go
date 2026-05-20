package localloop

import (
	"testing"
)

func TestLocalOpenBrowserEnabled(t *testing.T) {
	t.Run("ci disables", func(t *testing.T) {
		t.Setenv("CI", "true")
		t.Setenv(EnvLocalOpenBrowser, "")
		if localOpenBrowserEnabled() {
			t.Fatal("expected disabled when CI is set")
		}
	})
	t.Run("explicit off", func(t *testing.T) {
		t.Setenv("CI", "")
		for _, v := range []string{"0", "false", "no", "off", "FALSE"} {
			t.Run(v, func(t *testing.T) {
				t.Setenv(EnvLocalOpenBrowser, v)
				if localOpenBrowserEnabled() {
					t.Fatalf("expected disabled for %q", v)
				}
			})
		}
	})
	t.Run("explicit on without ci", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv(EnvLocalOpenBrowser, "1")
		if !localOpenBrowserEnabled() || !LocalDashboardAutoOpenEnabled() {
			t.Fatal("expected enabled when explicitly enabled")
		}
	})
	t.Run("default off under go test", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv(EnvLocalOpenBrowser, "")
		if localOpenBrowserEnabled() {
			t.Fatal("expected disabled by default under go test")
		}
	})
}
