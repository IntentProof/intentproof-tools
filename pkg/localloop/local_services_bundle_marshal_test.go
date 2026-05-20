package localloop

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/intentproof/intentproof-tools/pkg/bundle"
)

func TestHandleVerifyBundleResponseMarshalFailure(t *testing.T) {
	var buf bytes.Buffer
	if err := bundle.Create(&buf, bundle.CreateOptions{
		BundleID: "b1", FlowID: "f1", TenantID: LocalTenantID,
		FlowJSON:   []byte(`{"flow_id":"f1","tenant_id":"` + LocalTenantID + `","flow_merkle_root":"sha256:0","events":[]}`),
		PolicyJSON: []byte(`{"policy_id":"p1","tenant_id":"` + LocalTenantID + `","policy_version":1,"rules":[]}`),
		RunJSON:    []byte(`{"status":"pass","findings":[]}`),
	}); err != nil {
		t.Fatal(err)
	}

	orig := localServicesJSONMarshal
	localServicesJSONMarshal = func(any) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { localServicesJSONMarshal = orig })

	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/bundle", bytes.NewReader(buf.Bytes()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
