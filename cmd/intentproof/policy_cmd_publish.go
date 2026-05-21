package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/policysig"
)

func runPolicyPublish(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: intentproof policy publish <policy.yaml>")
		return 1
	}

	result, err := policy.CompileFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "compile failed: %v\n", err)
		return 1
	}

	bodyMap, err := maybeSignPolicy(result)
	if err != nil {
		fmt.Fprintf(stderr, "sign failed: %v\n", err)
		return 1
	}

	body, err := policyCmdJSONMarshal(bodyMap)
	if err != nil {
		fmt.Fprintf(stderr, "marshal policy: %v\n", err)
		return 1
	}

	record := struct {
		TenantID      string          `json:"tenant_id"`
		PolicyID      string          `json:"policy_id"`
		PolicyVersion int             `json:"policy_version"`
		Body          json.RawMessage `json:"body"`
	}{
		TenantID:      result.Policy.TenantID,
		PolicyID:      result.Policy.PolicyID,
		PolicyVersion: result.Policy.PolicyVersion,
		Body:          body,
	}

	payload, err := policyCmdJSONMarshal(record)
	if err != nil {
		fmt.Fprintf(stderr, "marshal request: %v\n", err)
		return 1
	}

	apiURL := policyQueryAPIURL()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/policies", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(stderr, "publish failed: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "publish failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(stdout, "published %s v%d\n", record.PolicyID, record.PolicyVersion)
		return 0
	case http.StatusBadRequest:
		fmt.Fprintf(stderr, "publish rejected: %s\n", strings.TrimSpace(string(respBody)))
		return 1
	default:
		fmt.Fprintf(stderr, "publish failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return 1
	}
}

// maybeSignPolicy injects signature and signed_at into the policy body when a
// signer is configured via environment. Returns the policy as a generic map.
func maybeSignPolicy(result *policy.CompileResult) (map[string]any, error) {
	raw, err := json.Marshal(result.Policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	var bodyMap map[string]any
	if err := json.Unmarshal(raw, &bodyMap); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}

	signer, err := crypto.NewPolicySignerFromEnv()
	if err != nil {
		return nil, fmt.Errorf("init signer: %w", err)
	}
	if signer == nil {
		return bodyMap, nil
	}

	payload, err := policysig.BuildPolicySignPayload(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("build sign payload: %w", err)
	}
	digest := sha256.Sum256(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env, err := signer.Sign(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	signedAt, err := crypto.ParseRFC3339OrNow("")
	if err != nil {
		return nil, fmt.Errorf("signed_at: %w", err)
	}

	bodyMap["signature"] = map[string]any{
		"alg":    env.Alg,
		"key_id": env.KeyID,
		"value":  env.Value,
	}
	bodyMap["signed_at"] = signedAt.Format(time.RFC3339)
	return bodyMap, nil
}
