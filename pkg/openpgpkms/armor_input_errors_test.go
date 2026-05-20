package openpgpkms

import (
	"bytes"
	"strings"
	"testing"
)

func TestArmoredClearSignRejectsNilEntity(t *testing.T) {
	if err := ArmoredClearSign(&bytes.Buffer{}, nil, strings.NewReader("x"), fixedTime()); err == nil {
		t.Fatal("expected nil entity error")
	}
}

func TestArmoredClearSignRejectsNilMessageReader(t *testing.T) {
	entity := testEntity(t)
	if err := ArmoredClearSign(&bytes.Buffer{}, entity, nil, fixedTime()); err == nil {
		t.Fatal("expected nil message error")
	}
}

func TestArmoredDetachSignRejectsNilMessageReader(t *testing.T) {
	entity := testEntity(t)
	if err := ArmoredDetachSign(&bytes.Buffer{}, entity, nil, fixedTime()); err == nil {
		t.Fatal("expected nil message error")
	}
}
