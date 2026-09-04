package trace

import (
	"fmt"
	"net"
	"testing"
	"time"
)

const (
	mtrBenchmarkTTLCount  = 64
	mtrBenchmarkPathCount = 4
)

var (
	mtrBenchmarkStatsSink []MTRHopStat
	mtrBenchmarkCloneSink *MTRAggregator
)

func newMTRBenchmarkResult() *Result {
	res := &Result{Hops: make([][]Hop, mtrBenchmarkTTLCount)}
	for ttl := 1; ttl <= mtrBenchmarkTTLCount; ttl++ {
		attempts := make([]Hop, 0, mtrBenchmarkPathCount)
		for path := 1; path <= mtrBenchmarkPathCount; path++ {
			attempts = append(attempts, Hop{
				Success:  true,
				Address:  &net.IPAddr{IP: net.IPv4(198, 18, byte(ttl), byte(path))},
				Hostname: fmt.Sprintf("hop-%02d-path-%d.example", ttl, path),
				TTL:      ttl,
				RTT:      time.Duration(ttl*path) * time.Millisecond,
				MPLS: []string{
					fmt.Sprintf("[MPLS: Lbl %d, TC 0, S 0, TTL %d]", ttl*100+path, ttl),
					fmt.Sprintf("[MPLS: Lbl %d, TC 1, S 1, TTL %d]", ttl*1000+path, ttl),
				},
			})
		}
		res.Hops[ttl-1] = attempts
	}
	return res
}

func newMTRBenchmarkPartialResult(ttl int) *Result {
	full := newMTRBenchmarkResult()
	partial := &Result{Hops: make([][]Hop, len(full.Hops))}
	partial.Hops[ttl-1] = full.Hops[ttl-1]
	return partial
}

func newPopulatedMTRBenchmarkAggregator(res *Result) *MTRAggregator {
	agg := NewMTRAggregator()
	agg.Update(res, mtrBenchmarkPathCount)
	return agg
}

func BenchmarkMTRAggregatorUpdate64TTL4Paths(b *testing.B) {
	res := newMTRBenchmarkResult()
	agg := newPopulatedMTRBenchmarkAggregator(res)
	b.ReportAllocs()

	for b.Loop() {
		mtrBenchmarkStatsSink = agg.Update(res, mtrBenchmarkPathCount)
	}
}

func BenchmarkMTRAggregatorClone64TTL4Paths(b *testing.B) {
	res := newMTRBenchmarkResult()
	agg := newPopulatedMTRBenchmarkAggregator(res)
	b.ReportAllocs()

	for b.Loop() {
		mtrBenchmarkCloneSink = agg.Clone()
	}
}

func BenchmarkMTRAggregatorSnapshot64TTL4Paths(b *testing.B) {
	res := newMTRBenchmarkResult()
	agg := newPopulatedMTRBenchmarkAggregator(res)
	b.ReportAllocs()

	for b.Loop() {
		mtrBenchmarkStatsSink = agg.Snapshot()
	}
}

func BenchmarkMTRAggregatorPreviewCloneUpdate64TTL4Paths(b *testing.B) {
	res := newMTRBenchmarkResult()
	agg := newPopulatedMTRBenchmarkAggregator(res)
	partial := newMTRBenchmarkPartialResult(mtrBenchmarkTTLCount / 2)
	b.ReportAllocs()

	for b.Loop() {
		preview := agg.Clone()
		mtrBenchmarkStatsSink = preview.Update(partial, mtrBenchmarkPathCount)
	}
	b.ReportMetric(1, "affected-TTLs/op")
}
