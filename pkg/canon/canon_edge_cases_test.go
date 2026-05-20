package canon

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeStringEscapesControlChars(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeString(&buf, "a\u000bb"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `\u000b`) {
		t.Fatalf("got %s", buf.String())
	}
}
