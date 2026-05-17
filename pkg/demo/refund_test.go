package demo

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
	"github.com/klauspost/compress/zstd"
)

func TestRunRefundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping demo integration in -short")
	}
	home := t.TempDir()
	work := t.TempDir()
	ctx := context.Background()
	opt := Options{
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		HomeDir:        home,
		WorkDir:        work,
		OpenBrowser:    false,
		PrivateKeySeed: deterministicRefundSeed(),
		FixedTime:      time.Date(2026, 5, 15, 12, 5, 0, 0, time.UTC),
	}
	if err := RunRefund(ctx, opt); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(work, "demo-refund.proof.tar.zst")
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := bundle.Verify(bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if vr.Status != "pass" {
		t.Fatalf("bundle status: %s reason=%s findings=%v", vr.Status, vr.Reason, vr.Findings)
	}
	if !hasBundleFinding(vr.Findings, "event.signature_valid") {
		t.Fatalf("expected event signature validation, findings=%v", vr.Findings)
	}
	if hasBundleFinding(vr.Findings, "event.signature_key_unavailable") {
		t.Fatalf("expected demo bundle to include event public keys, findings=%v", vr.Findings)
	}
	gotHash := canonicalBundleContentHash(t, raw)
	wantHash := readExpectedBundleHash(t)
	if got := gotHash; got != wantHash {
		t.Fatalf("bundle content sha256 mismatch: got %s want %s", got, wantHash)
	}
}

func canonicalBundleContentHash(t *testing.T, raw []byte) string {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode zstd bundle: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	files := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar header: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != 0 {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar file %s: %v", hdr.Name, err)
		}
		sum := sha256.Sum256(body)
		files[hdr.Name] = hex.EncodeToString(sum[:])
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		fmt.Fprintf(h, "%s\x00%s\n", name, files[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hasBundleFinding(findings []string, needle string) bool {
	for _, finding := range findings {
		if finding == needle {
			return true
		}
	}
	return false
}

func deterministicRefundSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

func readExpectedBundleHash(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "refund", "expected-bundle-sha256.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}
