package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/canon"
	ipcrypto "github.com/intentproof/intentproof-tools/pkg/crypto"
	"github.com/intentproof/intentproof-tools/pkg/merkle"
)

func parseJSONL(data []byte) []map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var out []map[string]interface{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(line, &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func jsonlBytes(items []map[string]interface{}) []byte {
	var buf bytes.Buffer
	for i, item := range items {
		if i > 0 {
			buf.WriteByte('\n')
		}
		b, _ := json.Marshal(item)
		buf.Write(b)
	}
	return buf.Bytes()
}

func mustMarshal(v map[string]interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func sha256hex(data []byte) string {
	return hex.EncodeToString(sha256sum(data))
}

func sha256sum(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

// canonicalManifestJSON returns deterministic JSON for signing/verifying.
func canonicalManifestJSON(m *Manifest) ([]byte, error) {
	// Copy to avoid mutating the original.
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var tmp map[string]interface{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return nil, err
	}
	delete(tmp, "signature")
	return canon.Marshal(tmp)
}

// computeItemMerkle builds a Merkle root from a list of JSON items using the
// "idField" as the leaf data (e.g. "event_id", "attestation_id").
func computeItemMerkle(items []map[string]interface{}, idField string) string {
	ids := make([]string, len(items))
	for i, item := range items {
		v, _ := item[idField].(string)
		ids[i] = v
	}
	if len(ids) == 0 {
		return merkle.RootHex(nil)
	}
	sort.Strings(ids)
	leaves := make([][]byte, len(ids))
	for i, id := range ids {
		leaves[i] = []byte(id)
	}
	return merkle.RootHex(leaves)
}

func verifyObjectSignatures(b *Bundle, findings []string) ([]string, error) {
	for _, ev := range b.Events {
		var err error
		findings, err = verifySignedMap(b, findings, "event", "signature", ev, []string{"signature"})
		if err != nil {
			return findings, err
		}
	}
	for _, att := range b.Attestations {
		var err error
		findings, err = verifySignedMap(b, findings, "attestation", "platform_signature", att, []string{"platform_signature"})
		if err != nil {
			return findings, err
		}
	}
	if b.Run != nil {
		var err error
		findings, err = verifySignedMap(b, findings, "run", "signature", b.Run, []string{
			"signature",
			"run_fingerprint",
			"started_at",
			"completed_at",
		})
		if err != nil {
			return findings, err
		}
	}
	if b.Certificate != nil {
		var err error
		findings, err = verifySignedMap(b, findings, "certificate", "signature", b.Certificate, []string{"signature"})
		if err != nil {
			return findings, err
		}
	}
	return findings, nil
}

func verifySignedMap(
	b *Bundle,
	findings []string,
	label string,
	signatureField string,
	doc map[string]interface{},
	excludedFields []string,
) ([]string, error) {
	env, ok, err := signatureEnvelopeFromMap(doc, signatureField)
	if err != nil {
		findings = append(findings, label+".signature_decode_failed")
		return findings, nil
	}
	if !ok || strings.TrimSpace(env.Value) == "" {
		return findings, nil
	}
	if env.Alg != "ed25519" {
		findings = append(findings, label+".signature_unsupported_alg")
		return findings, nil
	}
	pubRaw, ok := b.PublicKeys[env.KeyID]
	if !ok {
		findings = append(findings, label+".signature_key_unavailable")
		return findings, nil
	}
	pub, err := ipcrypto.ParseEd25519PublicKey(pubRaw)
	if err != nil {
		findings = append(findings, label+".signature_key_unavailable")
		return findings, nil
	}
	sig, err := decodeSignatureValue(env.Value)
	if err != nil {
		findings = append(findings, label+".signature_decode_failed")
		return findings, nil
	}
	payload, err := canonicalSignedMap(doc, excludedFields)
	if err != nil {
		return findings, fmt.Errorf("bundle.%s_signature_canonicalize: %w", label, err)
	}
	if !ed25519.Verify(pub, sha256sum(payload), sig) {
		findings = append(findings, label+".signature_invalid")
		return findings, nil
	}
	findings = append(findings, label+".signature_valid")
	return findings, nil
}

func signatureEnvelopeFromMap(doc map[string]interface{}, field string) (*SignatureEnvelope, bool, error) {
	raw, ok := doc[field]
	if !ok || raw == nil {
		return nil, false, nil
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return nil, true, err
	}
	var env SignatureEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, true, err
	}
	return &env, true, nil
}

func canonicalSignedMap(doc map[string]interface{}, excludedFields []string) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var copy map[string]interface{}
	if err := json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	for _, field := range excludedFields {
		delete(copy, field)
	}
	return canon.Marshal(copy)
}

func decodeSignatureValue(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if isEd25519HexSignature(value) {
		return hex.DecodeString(value)
	}
	if sig, err := base64.StdEncoding.DecodeString(value); err == nil {
		return sig, nil
	}
	return hex.DecodeString(value)
}

func isEd25519HexSignature(value string) bool {
	if len(value) != ed25519.SignatureSize*2 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
