package verifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/intentproof/intentproof-tools/internal/fuzzcorpus"
)

type verifyCorpusCase struct {
	Flow         json.RawMessage `json:"flow"`
	Policy       json.RawMessage `json:"policy"`
	Attestations json.RawMessage `json:"attestations"`
}

var verifySeeds = []struct {
	flow, policy, atts []byte
}{
	{
		[]byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[{"event_id":"e1","action":"pay","status":"ok","started_at":"2026-05-12T00:00:00Z","completed_at":"2026-05-12T00:00:01Z"}]}`),
		[]byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{"id":"r1","category":"required","severity":"medium","spec":{"action":"pay","min":1}}]}`),
		nil,
	},
	{
		[]byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`),
		[]byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[{"id":"r1","category":"required","severity":"high","spec":{"action":"pay","min":1}}]}`),
		nil,
	},
	{
		[]byte(`{"flow_id":"f1","tenant_id":"tnt","flow_merkle_root":"sha256:0000","events":[]}`),
		[]byte(`{"policy_id":"p1","tenant_id":"tnt","policy_version":1,"rules":[]}`),
		nil,
	},
}

func FuzzVerify(f *testing.F) {
	for _, seed := range verifySeeds {
		f.Add(seed.flow, seed.policy, seed.atts)
	}

	f.Fuzz(func(t *testing.T, flow, policy, atts []byte) {
		_, err := Verify(flow, policy, atts)
		if err != nil {
			return
		}
	})
}

func TestVerifySpecCorpus(t *testing.T) {
	dir := fuzzcorpus.Dir(t, "verifier")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var ran int
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		ran++
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("read corpus: %v", err)
			}
			var tc verifyCorpusCase
			if err := json.Unmarshal(data, &tc); err != nil {
				t.Fatalf("decode corpus case: %v", err)
			}
			atts := bytes.TrimSpace([]byte(tc.Attestations))
			if len(atts) == 0 || bytes.Equal(atts, []byte("null")) {
				atts = nil
			}
			if _, err := Verify([]byte(tc.Flow), []byte(tc.Policy), atts); err != nil {
				t.Fatalf("Verify golden corpus: %v", err)
			}
		})
	}
	if ran == 0 {
		t.Fatalf("no .json corpus files under %s", dir)
	}
}
