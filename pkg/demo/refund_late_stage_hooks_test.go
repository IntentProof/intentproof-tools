package demo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/intentproof/intentproof-tools/pkg/policy"
	"github.com/intentproof/intentproof-tools/pkg/verifier"
)

func runRefundLateStage(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	home := t.TempDir()
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	return RunRefund(ctx, Options{
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		HomeDir:        home,
		WorkDir:        work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
}

func withRefundHook[T any](t *testing.T, target *T, hook T, fn func()) {
	t.Helper()
	orig := *target
	*target = hook
	t.Cleanup(func() { *target = orig })
	fn()
}

func TestRunRefundLateStageCompilePolicyError(t *testing.T) {
	withRefundHook(t, &refundCompilePolicy, func([]byte) (*policy.CompileResult, error) {
		return nil, errors.New("injected compile")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "compile policy") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageBuildFlowJSONError(t *testing.T) {
	withRefundHook(t, &refundBuildFlowJSON, func(context.Context, *sql.DB, string, string) ([]byte, error) {
		return nil, errors.New("injected build flow")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "build flow json") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageVerifyFlowError(t *testing.T) {
	withRefundHook(t, &refundVerifyFlow, func([]byte, []byte, []byte) (*verifier.VerificationRun, error) {
		return nil, errors.New("injected verify")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "verify") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageUnexpectedPassStatus(t *testing.T) {
	withRefundHook(t, &refundVerifyFlow, func(flowJSON, policyJSON, cert []byte) (*verifier.VerificationRun, error) {
		return &verifier.VerificationRun{Status: "pass", FlowID: "flow_x"}, nil
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "expected verification status fail") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageMissingRequiredReason(t *testing.T) {
	withRefundHook(t, &refundVerifyFlow, func(flowJSON, policyJSON, cert []byte) (*verifier.VerificationRun, error) {
		return &verifier.VerificationRun{
			Status:   "fail",
			FlowID:   "flow_x",
			Findings: []map[string]any{{"reason": "other"}},
		}, nil
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "fail.required.missing") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageHappyPathVerifyFails(t *testing.T) {
	calls := 0
	withRefundHook(t, &refundVerifyFlow, func(flowJSON, policyJSON, cert []byte) (*verifier.VerificationRun, error) {
		calls++
		if calls == 1 {
			return verifier.Verify(flowJSON, policyJSON, cert)
		}
		return nil, errors.New("injected ok verify")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "verify ok path") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageHappyPathUnexpectedFail(t *testing.T) {
	calls := 0
	withRefundHook(t, &refundVerifyFlow, func(flowJSON, policyJSON, cert []byte) (*verifier.VerificationRun, error) {
		calls++
		if calls == 1 {
			return verifier.Verify(flowJSON, policyJSON, cert)
		}
		return &verifier.VerificationRun{Status: "fail", FlowID: "flow_ok"}, nil
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "expected verification pass") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageLoadEventsJSONLError(t *testing.T) {
	withRefundHook(t, &refundLoadEventsJSONL, func(context.Context, *sql.DB, string, string) ([]byte, error) {
		return nil, errors.New("injected events jsonl")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "load events jsonl") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageLoadPublicKeysError(t *testing.T) {
	withRefundHook(t, &refundLoadSDKPublicKeys, func(context.Context, *sql.DB, string, string) (map[string][]byte, error) {
		return nil, errors.New("injected public keys")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "load sdk public keys") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestRunRefundLateStageBundleCreateError(t *testing.T) {
	withRefundHook(t, &refundBundleCreate, func(io.Writer, bundle.CreateOptions) error {
		return fmt.Errorf("injected bundle create")
	}, func() {
		err := runRefundLateStage(t)
		if err == nil || !strings.Contains(err.Error(), "bundle create") {
			t.Fatalf("err=%v", err)
		}
	})
}
