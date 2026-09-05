package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

const pgoBenchmarkSeed = 20260905

var (
	pgoBenchmarkJSONSink    []byte
	pgoBenchmarkGeoDataSink *ipgeo.IPGeoData
)

type pgoBenchmarkProber struct {
	results [mtrBenchmarkTTLCount][mtrBenchmarkPathCount]mtrProbeResult
	initial [mtrBenchmarkTTLCount]uint8
	next    [mtrBenchmarkTTLCount]uint8
}

func newPGOBenchmarkProber(geo *ipgeo.IPGeoData) *pgoBenchmarkProber {
	p := &pgoBenchmarkProber{}
	for ttl := 1; ttl <= mtrBenchmarkTTLCount; ttl++ {
		p.initial[ttl-1] = uint8((pgoBenchmarkSeed + ttl) % mtrBenchmarkPathCount)
		for path := 1; path <= mtrBenchmarkPathCount; path++ {
			p.results[ttl-1][path-1] = mtrProbeResult{
				TTL:      ttl,
				Success:  true,
				Addr:     &net.IPAddr{IP: net.IPv4(198, 18, byte(ttl), byte(path))},
				RTT:      time.Duration(ttl*path) * time.Millisecond,
				Hostname: fmt.Sprintf("hop-%02d-path-%d.example", ttl, path),
				Geo:      geo,
				MPLS:     []string{fmt.Sprintf("[MPLS: Lbl %d, TC 0, S 1, TTL %d]", ttl*100+path, ttl)},
			}
		}
	}
	p.next = p.initial
	return p
}

func (p *pgoBenchmarkProber) ProbeTTL(ctx context.Context, ttl int) (mtrProbeResult, error) {
	if err := ctx.Err(); err != nil {
		return mtrProbeResult{}, err
	}
	if ttl < 1 || ttl > len(p.results) {
		return mtrProbeResult{}, fmt.Errorf("TTL %d outside benchmark fixture", ttl)
	}
	idx := ttl - 1
	path := int(p.next[idx] % mtrBenchmarkPathCount)
	p.next[idx]++
	return p.results[idx][path], nil
}

func (p *pgoBenchmarkProber) Reset() error {
	p.next = p.initial
	return nil
}

func (*pgoBenchmarkProber) Close() error { return nil }

func BenchmarkPGOTraceWorkload(b *testing.B) {
	geo := &ipgeo.IPGeoData{
		IP: "198.18.1.1", Asnumber: "64512", Country: "示例", CountryEn: "Example",
		Prov: "测试", ProvEn: "Test", City: "基准", CityEn: "Benchmark",
		Owner: "Example Network", Lat: 31.25, Lng: 121.5, Source: "fake-pgo-provider",
	}
	provider := ipgeo.Source(func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
		return geo, nil
	})
	cachedProviderCalls := 0
	cachedProvider := CachedGeoSource(ipgeo.SourceDescriptor{
		Source: func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
			cachedProviderCalls++
			return geo, nil
		},
		Namespace: ipgeo.SourceNamespaceIPSB,
		Backend:   ipgeo.SourceNamespaceIPSB,
	})
	const hotQuery = "198.18.1.1"
	coldQueries := make([]string, 4095)
	for idx := range coldQueries {
		coldQueries[idx] = fmt.Sprintf("198.19.%d.%d", idx>>8, idx&0xff)
	}
	ClearCaches()
	b.Cleanup(ClearCaches)
	prober := newPGOBenchmarkProber(geo)
	agg := NewMTRAggregator()
	result := &Result{Hops: make([][]Hop, mtrBenchmarkTTLCount)}

	if got, err := provider(hotQuery, time.Second, "en", false); err != nil || got != geo {
		b.Fatalf("fake geo provider = (%+v, %v), want fixture", got, err)
	}
	if got, err := cachedProvider(hotQuery, time.Second, "en", false); err != nil || got == nil {
		b.Fatalf("cached fake geo provider = (%+v, %v), want fixture", got, err)
	}
	if probe, err := prober.ProbeTTL(context.Background(), 1); err != nil || !probe.Success {
		b.Fatalf("fake prober = (%+v, %v), want success", probe, err)
	}
	_ = prober.Reset()

	b.ReportAllocs()
	b.ResetTimer()
	iteration := 0
	for b.Loop() {
		agg.Reset()
		if err := prober.Reset(); err != nil {
			b.Fatalf("reset fake prober: %v", err)
		}
		for idx := range result.Hops {
			result.Hops[idx] = result.Hops[idx][:0]
		}

		if _, err := provider(hotQuery, time.Second, "en", false); err != nil {
			b.Fatalf("fake geo provider: %v", err)
		}
		resolved, err := cachedProvider(hotQuery, time.Second, "en", false)
		if err != nil {
			b.Fatalf("cached fake geo provider: %v", err)
		}
		if iteration%64 == 0 {
			coldQuery := coldQueries[(iteration/64)%len(coldQueries)]
			if _, err := cachedProvider(coldQuery, time.Second, "en", false); err != nil {
				b.Fatalf("cached fake geo provider miss: %v", err)
			}
		}
		iteration++
		for ttl := 1; ttl <= mtrBenchmarkTTLCount; ttl++ {
			for range mtrBenchmarkPathCount {
				probe, err := prober.ProbeTTL(context.Background(), ttl)
				if err != nil {
					b.Fatalf("fake probe TTL %d: %v", ttl, err)
				}
				result.Hops[ttl-1] = append(result.Hops[ttl-1], Hop{
					Success: probe.Success, Address: probe.Addr, Hostname: probe.Hostname,
					TTL: probe.TTL, RTT: probe.RTT, Geo: resolved, Lang: "en", MPLS: probe.MPLS,
				})
			}
		}
		stats := agg.Update(result, mtrBenchmarkPathCount)
		encoded, err := json.Marshal(MTRSnapshot{Iteration: 10, Stats: stats})
		if err != nil {
			b.Fatalf("marshal MTR workload snapshot: %v", err)
		}
		pgoBenchmarkJSONSink = encoded
		pgoBenchmarkGeoDataSink = resolved
	}
	if err := prober.Close(); err != nil {
		b.Fatalf("close fake prober: %v", err)
	}
	if want := 1 + (iteration+63)/64; cachedProviderCalls != want {
		b.Fatalf("cached fake geo provider calls = %d, want %d", cachedProviderCalls, want)
	}
}
