package localloop

import (
	"testing"
)

func TestSetLaunchBrowserHookRestoreDefault(t *testing.T) {
	restore := SetLaunchBrowserHook(func(string) error { return nil })
	restore()
	restoreNil := SetLaunchBrowserHook(nil)
	defer restoreNil()
	if launchBrowser == nil {
		t.Fatal("expected default launcher after nil restore")
	}
}

func TestOpenDefaultBrowserUnderTest(t *testing.T) {
	if err := openDefaultBrowser("http://127.0.0.1:9789/"); err != nil {
		t.Fatal(err)
	}
}
