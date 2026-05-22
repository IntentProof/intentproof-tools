package canon

import (
	"encoding/json"
	"testing"
)

// marshalRawSeeds are deterministic inputs for FuzzMarshalRaw and the golden
// fuzz corpus under intentproof-spec/golden/fuzz-corpora/canon/.
var marshalRawSeeds = [][]byte{
	[]byte(`{"b":2,"a":1}`),
	[]byte(`{"b":"2","a":"1"}`),
	[]byte(`{"c":0,"b":[],"a":{}}`),
	[]byte(`{"11":"eleven","10":"ten","1":"one"}`),
	[]byte(`{"b":1.2,"a":1.0}`),
	[]byte(`{"b":true,"a":false}`),
	[]byte(`{"b":null,"a":null}`),
	[]byte(`{"b":[3,2,1],"a":[1,2,3]}`),
	[]byte(`{"unicode":"é","ascii":"e"}`),
	[]byte(`{"slash":"a/b","backslash":"a\\b"}`),
	[]byte(`{"z":{"b":2,"a":1},"a":[{"c":3,"b":2}]}`),
	[]byte(`{"\uE000":1,"\uD83D\uDE00":2}`),
	[]byte(`null`),
	[]byte(`true`),
	[]byte(`""`),
	[]byte(`{}`),
	[]byte(`[]`),
	[]byte(`1e22`),
	[]byte(`9007199254740992`),
	[]byte(`"\u0001"`),
}

func FuzzMarshalRaw(f *testing.F) {
	for _, seed := range marshalRawSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := MarshalRaw(json.RawMessage(data))
		if err != nil {
			return
		}
		assertMarshalRawIdempotent(t, out)
	})
}
