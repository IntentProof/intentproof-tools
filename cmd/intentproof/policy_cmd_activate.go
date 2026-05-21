package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func runPolicyActivate(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "Usage: intentproof policy activate <policy_id> <version> --scope <scope> [--effective-at <RFC3339>] [--tenant-id <tenant_id>]")
		return 1
	}

	policyID := strings.TrimSpace(args[0])
	versionStr := strings.TrimSpace(args[1])
	version, err := strconv.Atoi(versionStr)
	if err != nil || version < 1 {
		fmt.Fprintf(stderr, "invalid policy version: %q\n", versionStr)
		return 1
	}

	scope := ""
	effectiveAt := time.Now().UTC().Format(time.RFC3339)
	tenantID := ""

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--scope":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--scope requires a value\n")
				return 1
			}
			scope = strings.TrimSpace(args[i+1])
			i++
		case "--effective-at":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--effective-at requires a value\n")
				return 1
			}
			effectiveAt = strings.TrimSpace(args[i+1])
			i++
		case "--tenant-id":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				fmt.Fprintf(stderr, "--tenant-id requires a value\n")
				return 1
			}
			tenantID = strings.TrimSpace(args[i+1])
			i++
		default:
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(stderr, "unknown flag: %s\n", args[i])
				return 1
			}
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			return 1
		}
	}

	if scope == "" {
		fmt.Fprintln(stderr, "--scope is required")
		return 1
	}
	if tenantID == "" {
		parts := strings.SplitN(policyID, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			tenantID = parts[0]
		}
	}
	if tenantID == "" {
		fmt.Fprintln(stderr, "tenant_id is required (extract from policy_id or use --tenant-id)")
		return 1
	}

	if _, err := time.Parse(time.RFC3339, effectiveAt); err != nil {
		fmt.Fprintf(stderr, "invalid effective-at: %v\n", err)
		return 1
	}

	payload, err := policyCmdJSONMarshal(map[string]interface{}{
		"tenant_id":      tenantID,
		"scope":          scope,
		"policy_id":      policyID,
		"policy_version": version,
		"effective_at":   effectiveAt,
	})
	if err != nil {
		fmt.Fprintf(stderr, "marshal request: %v\n", err)
		return 1
	}

	apiURL := policyQueryAPIURL()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/policy-bindings", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(stderr, "activate failed: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "activate failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(stdout, "activated %s v%d for scope %q effective %s\n", policyID, version, scope, effectiveAt)
		return 0
	case http.StatusBadRequest:
		fmt.Fprintf(stderr, "activate rejected: %s\n", strings.TrimSpace(string(respBody)))
		return 1
	default:
		fmt.Fprintf(stderr, "activate failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return 1
	}
}
