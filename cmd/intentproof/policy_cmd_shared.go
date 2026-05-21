package main

import (
	"encoding/json"
	"os"
	"strings"
)

var (
	policyCmdJSONMarshal       = json.Marshal
	policyCmdJSONMarshalIndent = json.MarshalIndent
)

func policyQueryAPIURL() string {
	apiURL := strings.TrimSpace(os.Getenv("INTENTPROOF_QUERY_API_URL"))
	if apiURL == "" {
		apiURL = "http://localhost:8090"
	}
	return strings.TrimRight(apiURL, "/")
}
