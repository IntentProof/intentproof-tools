// Package merkle implements RFC 6962 Merkle hash trees with domain-separated
// leaf and internal node hashing. It is suitable for building deterministic,
// second-preimage-resistant Merkle roots over arbitrary leaf data.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

// LeafPrefix is the 0x00 byte prepended to leaf data before hashing.
const LeafPrefix byte = 0x00

// InternalPrefix is the 0x01 byte prepended to internal node data before hashing.
const InternalPrefix byte = 0x01

// HashLeaf returns the leaf hash for a single data element:
//   SHA-256(0x00 || data)
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte{LeafPrefix})
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// HashInternal returns the hash of an internal node:
//   SHA-256(0x01 || left || right)
func HashInternal(left, right []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte{InternalPrefix})
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)
}

// Root computes the Merkle root over a slice of leaf data items.
// It applies RFC 6962 domain separation and handles odd-length levels by
// promoting the last node (no duplication).
// Returns nil for an empty leaf set.
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}

	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = HashLeaf(leaf)
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, HashInternal(level[i], level[i+1]))
			} else {
				// Odd number: promote the last node unchanged.
				next = append(next, level[i])
			}
		}
		level = next
	}
	return level[0]
}

// RootHex computes the Merkle root and formats it as a hex string with the
// "sha256:" prefix. Returns the all-zero sha256 string for an empty input.
func RootHex(leaves [][]byte) string {
	root := Root(leaves)
	if root == nil {
		return "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	}
	return "sha256:" + hex.EncodeToString(root)
}
