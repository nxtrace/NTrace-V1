package trace

import (
	"fmt"
	"strings"
	"testing"

	traceinternal "github.com/nxtrace/NTrace-core/trace/internal"
)

const fuzzMPLSMaxBytes = 4096

func FuzzExtractMPLS(f *testing.F) {
	f.Add([]byte{
		0x20, 0x00, 0x00, 0x00,
		0x00, 0x0c, 0x01, 0x01,
		0x03, 0xe8, 0x01, 0x3f,
		0x07, 0xd0, 0x00, 0x40,
	})
	f.Add([]byte("not an ICMP extension"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMPLSMaxBytes {
			data = data[:fuzzMPLSMaxBytes]
		}
		labels := extractMPLS(traceinternal.ReceivedMessage{Msg: data}, false)
		if len(labels) > len(data)/4 {
			t.Fatalf("decoded %d labels from %d bytes", len(labels), len(data))
		}
		for _, label := range labels {
			if !strings.HasPrefix(label, "[MPLS: ") || !strings.HasSuffix(label, "]") {
				t.Fatalf("invalid MPLS label format %q", label)
			}
			var lbl, tc, bottom, ttl int
			if n, err := fmt.Sscanf(label, "[MPLS: Lbl %d, TC %d, S %d, TTL %d]", &lbl, &tc, &bottom, &ttl); err != nil || n != 4 {
				t.Fatalf("parse MPLS label %q: matched=%d error=%v", label, n, err)
			}
			if lbl < 0 || lbl > 0xfffff || tc < 0 || tc > 7 || bottom < 0 || bottom > 1 || ttl < 0 || ttl > 255 {
				t.Fatalf("MPLS label fields outside protocol range: %q", label)
			}
		}
	})
}
