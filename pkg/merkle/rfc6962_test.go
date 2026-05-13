package merkle

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestRootEmpty(t *testing.T) {
	// RFC 6962 empty-tree hash is SHA-256 of empty input.
	want := sha256.Sum256(nil)
	root := Root([][]byte{})
	if !bytes.Equal(root, want[:]) {
		t.Fatalf("empty root mismatch: got %x, want %x", root, want)
	}
	if got := RootHex([][]byte{}); got != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("unexpected empty hex root: %s", got)
	}
}

func TestRootSingleLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("a")}
	root := Root(leaves)
	expected := HashLeaf([]byte("a"))
	if !bytes.Equal(root, expected) {
		t.Fatalf("single leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootTwoLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b")}
	root := Root(leaves)
	expected := HashInternal(HashLeaf([]byte("a")), HashLeaf([]byte("b")))
	if !bytes.Equal(root, expected) {
		t.Fatalf("two-leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootThreeLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	root := Root(leaves)
	// Level 0: H(a), H(b), H(c)
	// Level 1: I(H(a), H(b)), H(c) [promoted]
	// Level 2: I(I(H(a),H(b)), H(c))
	l0a := HashLeaf([]byte("a"))
	l0b := HashLeaf([]byte("b"))
	l0c := HashLeaf([]byte("c"))
	l1ab := HashInternal(l0a, l0b)
	expected := HashInternal(l1ab, l0c)
	if !bytes.Equal(root, expected) {
		t.Fatalf("three-leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootFourLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := Root(leaves)
	l0a := HashLeaf([]byte("a"))
	l0b := HashLeaf([]byte("b"))
	l0c := HashLeaf([]byte("c"))
	l0d := HashLeaf([]byte("d"))
	l1ab := HashInternal(l0a, l0b)
	l1cd := HashInternal(l0c, l0d)
	expected := HashInternal(l1ab, l1cd)
	if !bytes.Equal(root, expected) {
		t.Fatalf("four-leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootFiveLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	root := Root(leaves)
	l0a := HashLeaf([]byte("a"))
	l0b := HashLeaf([]byte("b"))
	l0c := HashLeaf([]byte("c"))
	l0d := HashLeaf([]byte("d"))
	l0e := HashLeaf([]byte("e"))
	l1ab := HashInternal(l0a, l0b)
	l1cd := HashInternal(l0c, l0d)
	l2abcd := HashInternal(l1ab, l1cd)
	// l0e promoted to l1e, then merged with l2abcd
	expected := HashInternal(l2abcd, l0e)
	if !bytes.Equal(root, expected) {
		t.Fatalf("five-leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootSevenLeaves(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
		[]byte("e"), []byte("f"), []byte("g"),
	}
	root := Root(leaves)
	l0a := HashLeaf([]byte("a"))
	l0b := HashLeaf([]byte("b"))
	l0c := HashLeaf([]byte("c"))
	l0d := HashLeaf([]byte("d"))
	l0e := HashLeaf([]byte("e"))
	l0f := HashLeaf([]byte("f"))
	l0g := HashLeaf([]byte("g"))
	l1ab := HashInternal(l0a, l0b)
	l1cd := HashInternal(l0c, l0d)
	l1ef := HashInternal(l0e, l0f)
	l2abcd := HashInternal(l1ab, l1cd)
	// l1ef promoted to l2ef, then merged with l0g
	l2efg := HashInternal(l1ef, l0g)
	expected := HashInternal(l2abcd, l2efg)
	if !bytes.Equal(root, expected) {
		t.Fatalf("seven-leaf root mismatch: got %x, want %x", root, expected)
	}
}

func TestRootDeterministic(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	r1 := Root(leaves)
	r2 := Root(leaves)
	if !bytes.Equal(r1, r2) {
		t.Fatal("root not deterministic")
	}
}

func TestRootTamperingChangesRoot(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	root := Root(leaves)
	leaves[1] = []byte("X")
	root2 := Root(leaves)
	if bytes.Equal(root, root2) {
		t.Fatal("tampered leaf should change root")
	}
}

func TestRootSecondPreimageResistance(t *testing.T) {
	// RFC 6962 domain separation prevents a leaf from being interpreted as an
	// internal node. If an attacker crafts a leaf whose data equals the hash of
	// an internal node (left || right), a non-domain-separated tree would treat
	// it as an internal node, allowing a second-preimage attack.
	// With 0x00/0x01 prefixes, the leaf hash and internal hash are distinct.
	left := []byte("left")
	right := []byte("right")
	// A "malicious" leaf that contains the concatenation of two valid hashes.
	craftedLeaf := append(HashLeaf(left), HashLeaf(right)...)

	// Tree A: two legitimate leaves.
	treeA := Root([][]byte{left, right})

	// Tree B: one leaf whose data happens to be the concatenation of the
	// two leaf hashes from tree A. Without domain separation, tree B's root
	// would equal tree A's root. With RFC 6962 prefixes, they must differ.
	treeB := Root([][]byte{craftedLeaf})

	if bytes.Equal(treeA, treeB) {
		t.Fatal("second-preimage attack possible: crafted leaf collides with internal node")
	}
}


