package localloop

import (
	"path/filepath"
	"testing"
)

func TestStartEmbeddedNATSReusesExistingStream(t *testing.T) {
	dir := t.TempDir()
	first, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.Shutdown()

	second, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()

	if err := second.PublishEventCommitted(CommitEnvelope{
		TenantID: LocalTenantID, CorrelationID: "corr", EventID: "e1",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublishEventCommittedValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nats-pub")
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	if err := nw.PublishEventCommitted(CommitEnvelope{}); err == nil {
		t.Fatal("expected validation error")
	}
}
