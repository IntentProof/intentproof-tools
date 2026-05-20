package localloop

import (
	"encoding/hex"

	"github.com/intentproof/intentproof-tools/pkg/merkle"
)

func ComputeMerkleRoot(events []EventRow) []byte {
	hashes := make([][]byte, len(events))
	for i, e := range events {
		hashes[i] = e.Hash
	}
	return merkle.Root(hashes)
}

// HexRoot formats a raw hash with the sha256: prefix.
func HexRoot(root []byte) string {
	return "sha256:" + hex.EncodeToString(root)
}
