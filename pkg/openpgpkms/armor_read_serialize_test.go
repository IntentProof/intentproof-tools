package openpgpkms

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestArmoredClearSignReadFailure(t *testing.T) {
	priv := testRSAPrivateKey(t)
	entity, err := NewEntity(priv, EntityOptions{
		Name: "Test", Email: "t@example.com", CreatedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ArmoredClearSign(io.Discard, entity, errReadCloser{}, fixedTime())
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("err=%v", err)
	}
}
