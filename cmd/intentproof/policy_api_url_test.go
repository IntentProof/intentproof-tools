package main

import (
	"testing"
)

func TestPolicyQueryAPIURLDefault(t *testing.T) {
	t.Setenv("INTENTPROOF_QUERY_API_URL", "")
	if got := policyQueryAPIURL(); got != "http://localhost:8090" {
		t.Fatalf("got %q", got)
	}
}

func TestPolicyQueryAPIURLTrimsWhitespaceAndSlash(t *testing.T) {
	t.Setenv("INTENTPROOF_QUERY_API_URL", "  https://api.example.com/v1/  ")
	if got := policyQueryAPIURL(); got != "https://api.example.com/v1" {
		t.Fatalf("got %q", got)
	}
}
