package ipgeo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const fuzzNextTraceAPIV3MaxBytes = 64 << 10

func FuzzDecodeNextTraceAPIV3Message(f *testing.F) {
	f.Add(`{"ip":"192.0.2.1","asnumber":"AS64500","domain":"edge.example","lat":"1.25","lng":"2.5","router":{"r":["a","b"]}}`)
	f.Add(`{"ip":"2001:db8::1","owner":"Example","router":"{\"r\":[\"x\"]}"}`)
	f.Add(`{"ip":`)
	f.Add(strings.Repeat("[", 20000) + strings.Repeat("]", 20000))

	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > fuzzNextTraceAPIV3MaxBytes {
			data = data[:fuzzNextTraceAPIV3MaxBytes]
		}
		ip, geo, err := decodeNextTraceAPIV3Message(data)
		if err != nil {
			if json.Valid([]byte(data)) {
				t.Fatalf("valid JSON returned decoder error: %v", err)
			}
			return
		}
		againIP, againGeo, err := decodeNextTraceAPIV3Message(data)
		if err != nil || againIP != ip || !reflect.DeepEqual(againGeo, geo) {
			t.Fatalf("v3 response decode is not deterministic: first=(%q, %+v) second=(%q, %+v, %v)", ip, geo, againIP, againGeo, err)
		}
	})
}
