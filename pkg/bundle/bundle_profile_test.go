package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCreateEmbedsVerificationProfile(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.SpecVersion = "v0.test"
	opts.ExportProfile = "counterparty"
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s reason=%s findings=%v", res.Status, res.Reason, res.Findings)
	}
	for _, want := range []string{
		"verification_profile.present",
		"verification_profile.verifier_version_supported",
		"verification_profile.run_id_valid",
	} {
		if !hasFinding(res.Findings, want) {
			t.Fatalf("missing finding %q in %v", want, res.Findings)
		}
	}
}

func TestVerifyRejectsMissingVerificationProfile(t *testing.T) {
	body := []byte(`{"schema":"intentproof.bundle.manifest.v1","bundle_id":"b1","created_at":"2026-05-12T00:00:00Z","flow_id":"f1","tenant_id":"tnt","files":[{"path":"run.json","sha256":"sha256:00"}]}`)
	var buf bytes.Buffer
	writeTarManifest(t, &buf, body)
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.verification_profile_missing" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestVerifyRejectsUnsupportedVerifierVersion(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.VerificationProfile = &VerificationProfile{
		SpecVersion:     "v0.test",
		VerifierVersion: "totally-bogus-verifier-9.9.9",
		PolicyVersions:  []string{"sha256:abc"},
		ExportProfile:   "counterparty",
		FlowSnapshotID:  "f1",
		RunID:           "run_f1",
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.verification_profile_unsupported" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestVerifyRejectsRunIDMismatch(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.VerificationProfile = &VerificationProfile{
		SpecVersion:     "v0.test",
		VerifierVersion: "dev",
		PolicyVersions:  []string{},
		ExportProfile:   "full",
		FlowSnapshotID:  "f1",
		RunID:           "run_wrong",
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.verification_profile_invalid" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestVerifyRejectsTamperedVerifierVersionInSignedBundle(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	opts := buildTestBundleOpts(t, priv)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	tampered, err := tamperManifestField(&buf, func(m *Manifest) {
		if m.VerificationProfile != nil {
			m.VerificationProfile.VerifierVersion = "totally-bogus-verifier-9.9.9"
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(tampered, pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.signature_invalid" && res.Reason != "bundle.verification_profile_unsupported" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestCreateRejectsInvalidPolicyJSONForProfile(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.PolicyJSON = []byte(`{not json`)
	var buf bytes.Buffer
	err := Create(&buf, opts)
	if err == nil {
		t.Fatal("expected create error for invalid policy json")
	}
}

func TestDeriveVerificationProfileFromRunJSON(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.RunID = ""
	opts.FlowSnapshotID = ""
	opts.SpecVersion = "v1.test"
	opts.ExportProfile = "auditor"
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status=%s reason=%s", res.Status, res.Reason)
	}
}

func TestVerifyRejectsMissingVerifierVersionInProfile(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.VerificationProfile = &VerificationProfile{
		SpecVersion:    "v0.test",
		ExportProfile:  "full",
		FlowSnapshotID: "f1",
		RunID:          "run_f1",
	}
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "bundle.verification_profile_invalid" {
		t.Fatalf("reason=%s findings=%v", res.Reason, res.Findings)
	}
}

func TestDeriveVerificationProfileUsesSpecRefEnv(t *testing.T) {
	t.Setenv("INTENTPROOF_SPEC_REF", "v0.env-spec")
	opts := buildTestBundleOpts(t, nil)
	opts.SpecVersion = ""
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	b := mustExtractBundle(t, &buf)
	if b.Manifest.VerificationProfile.SpecVersion != "v0.env-spec" {
		t.Fatalf("spec_version=%q", b.Manifest.VerificationProfile.SpecVersion)
	}
}

func TestPolicyVersionsFromJSONIncludesFingerprint(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.PolicyJSON = []byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	b := mustExtractBundle(t, &buf)
	if len(b.Manifest.VerificationProfile.PolicyVersions) != 1 {
		t.Fatalf("policy_versions=%v", b.Manifest.VerificationProfile.PolicyVersions)
	}
}

func TestCreateRejectsInvalidRunJSONForProfile(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.RunID = ""
	opts.RunJSON = []byte(`{bad run`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err == nil {
		t.Fatal("expected run json decode error")
	}
}

func TestCreateAllowsEmptyPolicyForProfile(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.PolicyJSON = nil
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	b := mustExtractBundle(t, &buf)
	if b.Manifest.VerificationProfile.PolicyVersions != nil {
		t.Fatalf("policy_versions=%v", b.Manifest.VerificationProfile.PolicyVersions)
	}
}

func TestCreateDerivesFlowSnapshotFromRunJSON(t *testing.T) {
	opts := buildTestBundleOpts(t, nil)
	opts.FlowID = ""
	opts.FlowSnapshotID = ""
	opts.RunJSON = []byte(`{"run_id":"run_f1","flow_id":"f1","status":"pass","findings":[]}`)
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	b := mustExtractBundle(t, &buf)
	if b.Manifest.VerificationProfile.FlowSnapshotID != "f1" {
		t.Fatalf("flow_snapshot_id=%q", b.Manifest.VerificationProfile.FlowSnapshotID)
	}
}

func TestCreateUsesExplicitVerificationProfile(t *testing.T) {
	custom := &VerificationProfile{
		SpecVersion: "custom", VerifierVersion: "dev", ExportProfile: "full",
		FlowSnapshotID: "f1", RunID: "run_f1",
	}
	opts := buildTestBundleOpts(t, nil)
	opts.VerificationProfile = custom
	var buf bytes.Buffer
	if err := Create(&buf, opts); err != nil {
		t.Fatal(err)
	}
	b := mustExtractBundle(t, &buf)
	if b.Manifest.VerificationProfile.SpecVersion != "custom" {
		t.Fatalf("spec_version=%q", b.Manifest.VerificationProfile.SpecVersion)
	}
}
