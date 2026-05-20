package demo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRunRefundUserHomeDirFailure(t *testing.T) {
	orig := refundUserHomeDir
	refundUserHomeDir = func() (string, error) {
		return "", errors.New("no home")
	}
	t.Cleanup(func() { refundUserHomeDir = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard, WorkDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "home dir") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundPolicyJSONMarshalFailure(t *testing.T) {
	withRefundHook(t, &refundJSONMarshal, func(any) ([]byte, error) {
		return nil, errors.New("marshal policy")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "marshal policy") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundRunJSONIndentFailure(t *testing.T) {
	withRefundHook(t, &refundJSONMarshalIndent, func(v any, prefix, indent string) ([]byte, error) {
		if _, ok := v.(map[string]any); !ok {
			return nil, errors.New("marshal run")
		}
		return json.MarshalIndent(v, prefix, indent)
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "marshal run") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundFlowIndentFailure(t *testing.T) {
	calls := 0
	withRefundHook(t, &refundJSONMarshalIndent, func(v any, prefix, indent string) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("flow indent")
		}
		return json.MarshalIndent(v, prefix, indent)
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "flow indent") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundPolicyIndentFailure(t *testing.T) {
	calls := 0
	withRefundHook(t, &refundJSONMarshalIndent, func(v any, prefix, indent string) ([]byte, error) {
		calls++
		if calls == 3 {
			return nil, errors.New("policy indent")
		}
		return json.MarshalIndent(v, prefix, indent)
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "policy indent") {
			t.Fatalf("err=%v", err)
		}
	})
}
