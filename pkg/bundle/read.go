package bundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Read extracts a .proof.tar.zst (or plain tar) bundle without verification.
func Read(r io.Reader) (*Bundle, error) {
	tr, err := bundleTarReader(r)
	if err != nil {
		return nil, err
	}
	return readFromTar(tr)
}

func readFromTar(tr *tar.Reader) (*Bundle, error) {
	b := &Bundle{PublicKeys: map[string][]byte{}, RawFiles: map[string][]byte{}}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle.tar_read_failed: %w", err)
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, tr); err != nil {
			return nil, fmt.Errorf("bundle.tar_extract_failed: %w", err)
		}
		body := buf.Bytes()
		b.RawFiles[hdr.Name] = body

		switch hdr.Name {
		case "manifest.json":
			var m Manifest
			if err := json.Unmarshal(body, &m); err != nil {
				return nil, fmt.Errorf("bundle.manifest_decode_failed: %w", err)
			}
			b.Manifest = &m
		case "flow.json":
			json.Unmarshal(body, &b.Flow)
		case "events.jsonl":
			b.Events = parseJSONL(body)
		case "attestations.jsonl":
			b.Attestations = parseJSONL(body)
		case "policy.json":
			json.Unmarshal(body, &b.Policy)
		case "run.json":
			json.Unmarshal(body, &b.Run)
		case "certificate.json":
			json.Unmarshal(body, &b.Certificate)
		case "inclusion_proof.json":
			json.Unmarshal(body, &b.InclusionProof)
		default:
			if strings.HasPrefix(hdr.Name, "keys/") && strings.HasSuffix(hdr.Name, ".pub") {
				keyID := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "keys/"), ".pub")
				b.PublicKeys[keyID] = body
			}
		}
	}
	return b, nil
}
