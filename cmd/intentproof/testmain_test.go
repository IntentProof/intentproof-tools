package main

import (
	"os"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/localloop"
)

func TestMain(m *testing.M) {
	restore := localloop.SetLaunchBrowserHook(func(string) error { return nil })
	code := m.Run()
	restore()
	os.Exit(code)
}
