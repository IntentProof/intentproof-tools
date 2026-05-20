package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunPolicyActivateRejectedBadRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("rejected"))
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "--scope", "global"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate rejection")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("activate rejected")) {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunPolicyActivateUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "--scope", "global", "--unknown"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected unknown flag failure")
	}
}

func TestRunPolicyActivateInvalidEffectiveAtValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "--scope", "global", "--effective-at", "not-a-time"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected invalid effective-at failure")
	}
}

func TestRunPolicyActivateUnexpectedPositionalArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "extra", "--scope", "global"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected unexpected argument failure")
	}
}

func TestRunPolicyActivateInternalServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("INTENTPROOF_QUERY_API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"policy", "activate", "tnt_x.demo", "1", "--scope", "global"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected activate failure")
	}
}
