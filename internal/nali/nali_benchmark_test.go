package nali

import (
	"strings"
	"testing"
)

var naliBenchmarkSpansSink []Span

func BenchmarkFindIPSpans(b *testing.B) {
	line := strings.Repeat(
		" 1  192.0.2.1  1.25 ms  2  198.51.100.2:443  2.50 ms  3  [2001:db8::3]  3.75 ms  via fe80::1%en0\n",
		8,
	)
	if spans := FindIPSpans(line); len(spans) != 32 {
		b.Fatalf("FindIPSpans() found %d spans, want 32", len(spans))
	}
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()

	for b.Loop() {
		naliBenchmarkSpansSink = FindIPSpans(line)
	}
}
