package localloop

import "testing"

func TestComputeMerkleRootEmptyAndSingle(t *testing.T) {
	if root := ComputeMerkleRoot(nil); len(root) != 32 {
		t.Fatalf("empty root len=%d", len(root))
	}
	one := ComputeMerkleRoot([]EventRow{{Hash: []byte{1, 2, 3}}})
	if len(one) != 32 {
		t.Fatalf("single root len=%d", len(one))
	}
}

func TestValidateTenantIDAcceptsLocal(t *testing.T) {
	if err := validateTenantID(LocalTenantID); err != nil {
		t.Fatal(err)
	}
}
