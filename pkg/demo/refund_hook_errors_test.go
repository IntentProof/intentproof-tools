package demo

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunRefundLoadScenarioError(t *testing.T) {
	orig := refundLoadScenario
	defer func() { refundLoadScenario = orig }()
	refundLoadScenario = func() (RefundScenario, error) {
		return RefundScenario{}, errors.New("fixtures unavailable")
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "fixtures unavailable") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundListenIngestFails(t *testing.T) {
	orig := refundListenTCP
	defer func() { refundListenTCP = orig }()
	refundListenTCP = func(network, address string) (net.Listener, error) {
		return nil, errors.New("listen denied")
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "listen ingest") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundListenVerifierFails(t *testing.T) {
	orig := refundListenTCP
	defer func() { refundListenTCP = orig }()
	var calls int
	refundListenTCP = func(network, address string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return net.Listen(network, address)
		}
		return nil, errors.New("listen denied")
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "listen verifier") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundListenDashboardFails(t *testing.T) {
	orig := refundListenTCP
	defer func() { refundListenTCP = orig }()
	var calls int
	refundListenTCP = func(network, address string) (net.Listener, error) {
		calls++
		if calls <= 2 {
			return net.Listen(network, address)
		}
		return nil, errors.New("listen denied")
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "listen dashboard") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundPostHappyPathRejected(t *testing.T) {
	orig := refundNewHTTPClient
	defer func() { refundNewHTTPClient = orig }()
	var posts atomic.Int32
	refundNewHTTPClient = func() *http.Client {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost {
					if posts.Add(1) == 1 {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader("ingest down")),
							Header:     make(http.Header),
						}, nil
					}
				}
				return http.DefaultTransport.RoundTrip(req)
			}),
		}
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "post happy path") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundPostDivergentPathRejected(t *testing.T) {
	orig := refundNewHTTPClient
	defer func() { refundNewHTTPClient = orig }()
	var posts atomic.Int32
	refundNewHTTPClient = func() *http.Client {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost {
					n := posts.Add(1)
					if n == 5 {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader("ingest down")),
							Header:     make(http.Header),
						}, nil
					}
				}
				return http.DefaultTransport.RoundTrip(req)
			}),
		}
	}
	err := RunRefund(context.Background(), Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil || !strings.Contains(err.Error(), "post divergent path") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunRefundWaitFlowTimesOut(t *testing.T) {
	orig := refundNewHTTPClient
	defer func() { refundNewHTTPClient = orig }()
	refundNewHTTPClient = func() *http.Client {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost {
					return &http.Response{
						StatusCode: http.StatusAccepted,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				}
				return http.DefaultTransport.RoundTrip(req)
			}),
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: t.TempDir(), WorkDir: t.TempDir(),
		PrivateKeySeed: deterministicRefundSeed(),
	})
	if err == nil {
		t.Fatal("expected wait flow timeout")
	}
}

func TestRunRefundBundleCreateReadOnlyWorkDir(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "readonly-work")
	if err := os.Mkdir(work, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(work, 0o755) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err := RunRefund(ctx, Options{
		Stdout: io.Discard, Stderr: io.Discard,
		HomeDir: home, WorkDir: work,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "create bundle") {
		t.Fatalf("err=%v", err)
	}
}
