package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
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
			atts, err := attestationsFromCorpusJSON(tc.Attestations)
			if err != nil {
				t.Fatalf("decode corpus attestations: %v", err)
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

// attestationsFromCorpusJSON converts golden corpus attestations into the JSONL
// bytes expected by Verify. Corpus files store JSON null, a JSON array of
// attestation objects, a single JSON object, or raw JSONL lines.
func attestationsFromCorpusJSON(raw json.RawMessage) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	switch raw[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode attestations array: %w", err)
		}
		var buf bytes.Buffer
		for _, item := range items {
			item = bytes.TrimSpace(item)
			if len(item) == 0 {
				continue
			}
			buf.Write(item)
			buf.WriteByte('\n')
		}
		return buf.Bytes(), nil
	case '{':
		return append(append([]byte(nil), raw...), '\n'), nil
	default:
		return raw, nil
	}
}

func TestAttestationsFromCorpusJSON(t *testing.T) {
	t.Run("null", func(t *testing.T) {
		atts, err := attestationsFromCorpusJSON(json.RawMessage("null"))
		if err != nil {
			t.Fatalf("attestationsFromCorpusJSON: %v", err)
		}
		if atts != nil {
			t.Fatalf("got %q, want nil", atts)
		}
	})
	t.Run("array", func(t *testing.T) {
		atts, err := attestationsFromCorpusJSON(json.RawMessage(`[{"claim_id":"c1"},{"claim_id":"c2"}]`))
		if err != nil {
			t.Fatalf("attestationsFromCorpusJSON: %v", err)
		}
		want := "{\"claim_id\":\"c1\"}\n{\"claim_id\":\"c2\"}\n"
		if string(atts) != want {
			t.Fatalf("got %q, want %q", atts, want)
		}
		parsed, err := parseAttestations(atts)
		if err != nil {
			t.Fatalf("parseAttestations: %v", err)
		}
		if len(parsed) != 2 {
			t.Fatalf("got %d attestations, want 2", len(parsed))
		}
	})
	t.Run("object", func(t *testing.T) {
		atts, err := attestationsFromCorpusJSON(json.RawMessage(`{"claim_id":"c1"}`))
		if err != nil {
			t.Fatalf("attestationsFromCorpusJSON: %v", err)
		}
		if _, err := parseAttestations(atts); err != nil {
			t.Fatalf("parseAttestations: %v", err)
		}
	})
}
