package localloop

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleVerifyRunMarshalFailure(t *testing.T) {
	orig := localServicesJSONMarshal
	localServicesJSONMarshal = func(any) ([]byte, error) {
		return nil, errors.New("marshal fail")
	}
	t.Cleanup(func() { localServicesJSONMarshal = orig })

	body := []byte(`{"flow":{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000000000000000000000000000000000000000000000000000000000000000","events":[]},"policy":{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"spec_version":"1.0.0","rules":[]},"attestations":""}`)
	h := LocalVerifierHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
