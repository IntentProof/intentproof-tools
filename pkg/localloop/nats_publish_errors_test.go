package localloop

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTenantIDRejectsIllegalChars(t *testing.T) {
	for _, tenant := range []string{"", "tnt.bad", "tnt*bad", "tnt>bad"} {
		if err := validateTenantID(tenant); err == nil {
			t.Fatalf("tenant %q should fail", tenant)
		}
	}
}

func TestPublishEventCommittedRejectsBadTenant(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	err = nw.PublishEventCommitted(CommitEnvelope{TenantID: "bad.tenant", EventID: "e1"})
	if err == nil || !strings.Contains(err.Error(), "publish event committed") {
		t.Fatalf("err=%v", err)
	}
}

func TestPublishFlowMaterializedRejectsBadTenant(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()
	err = nw.PublishFlowMaterialized("bad.tenant", []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "publish flow materialized") {
		t.Fatalf("err=%v", err)
	}
}

func TestNATSWrapperURLWithoutServer(t *testing.T) {
	nw := &NATSWrapper{}
	if nw.URL() != "" {
		t.Fatalf("url=%q", nw.URL())
	}
}

func TestPublishEventCommittedWithoutJetStream(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(filepath.Join(dir, "pub"))
	if err != nil {
		t.Fatal(err)
	}
	nw.js = nil
	if err := nw.PublishEventCommitted(CommitEnvelope{
		TenantID: "tnt_ok", EventID: "e1", CorrelationID: "c1", Action: "a",
	}); err != nil {
		t.Fatal(err)
	}
	nw.Shutdown()
}

func TestStartEmbeddedNATSSuccess(t *testing.T) {
	dir := t.TempDir()
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	if nw.URL() == "" {
		t.Fatal("expected client url")
	}
	nw.Shutdown()
}
