package nali

import (
	"net/netip"
	"testing"
)

const fuzzNaliLineMaxBytes = 16 << 10

func FuzzFindIPSpans(f *testing.F) {
	f.Add([]byte("IP:1.1.1.1 [2001:db8::1]:443"))
	f.Add([]byte("dead:8.8.8.8 fe80::1%en0 invalid:::"))
	f.Add([]byte{0xff, '1', '.', '1', '.', '1', '.', '1'})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzNaliLineMaxBytes {
			data = data[:fuzzNaliLineMaxBytes]
		}
		line := string(data)
		spans := FindIPSpans(line)
		previousEnd := 0
		for i, span := range spans {
			if span.Start < previousEnd || span.Start < 0 || span.Start > span.End || span.End > span.InsertEnd || span.InsertEnd > len(line) {
				t.Fatalf("span[%d] has invalid or overlapping bounds: %+v after %d", i, span, previousEnd)
			}
			if line[span.Start:span.End] != span.Text {
				t.Fatalf("span[%d] text = %q, source = %q", i, span.Text, line[span.Start:span.End])
			}
			addr, err := netip.ParseAddr(span.LookupIP)
			if err != nil || !addr.IsValid() || addr.Zone() != "" {
				t.Fatalf("span[%d] lookup IP = %q: %v", i, span.LookupIP, err)
			}
			wantFamily := Family6
			if addr.Is4() {
				wantFamily = Family4
			}
			if span.Family != wantFamily {
				t.Fatalf("span[%d] family = %d, want %d", i, span.Family, wantFamily)
			}
			previousEnd = span.InsertEnd
		}
	})
}
