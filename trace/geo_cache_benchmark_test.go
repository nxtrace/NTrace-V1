package trace

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

var (
	benchmarkGeoCacheDataSink *ipgeo.IPGeoData
	benchmarkGeoCacheOKSink   bool
)

func BenchmarkGeoCacheAccess(b *testing.B) {
	const epoch = 0
	now := time.Unix(1_700_000_000, 0)
	descriptor := geoCacheTestDescriptor(nil)
	hitKey := mustGeoCacheKey(b, descriptor, "1.1.1.1")
	missKey := mustGeoCacheKey(b, descriptor, "8.8.8.8")
	data := &ipgeo.IPGeoData{IP: "1.1.1.1", Asnumber: "13335"}

	b.Run("Hit", func(b *testing.B) {
		cache := newGeoCacheRuntime(geoCacheCapacity, geoCacheTTL, func() time.Time { return now })
		cache.storeAtEpoch(hitKey, data, epoch)
		b.ReportAllocs()
		var value *ipgeo.IPGeoData
		var ok bool
		for b.Loop() {
			value, _, ok = cache.load(hitKey)
		}
		if !ok || value == nil {
			b.Fatal("geo cache hit benchmark did not load the seeded value")
		}
		benchmarkGeoCacheDataSink = value
		benchmarkGeoCacheOKSink = ok
	})

	b.Run("Miss", func(b *testing.B) {
		cache := newGeoCacheRuntime(geoCacheCapacity, geoCacheTTL, func() time.Time { return now })
		b.ReportAllocs()
		var value *ipgeo.IPGeoData
		var ok bool
		for b.Loop() {
			value, _, ok = cache.load(missKey)
		}
		if ok {
			b.Fatal("geo cache miss benchmark unexpectedly loaded a value")
		}
		benchmarkGeoCacheDataSink = value
		benchmarkGeoCacheOKSink = ok
	})

	b.Run("Eviction", func(b *testing.B) {
		cache := newGeoCacheRuntime(geoCacheCapacity, geoCacheTTL, func() time.Time { return now })
		keys := make([]geoCacheKey, geoCacheCapacity*2)
		for i := range keys {
			keys[i] = benchmarkGeoCacheKey(uint32(i))
		}
		b.ReportAllocs()
		index := 0
		for b.Loop() {
			cache.storeAtEpoch(keys[index], data, epoch)
			index++
			if index == len(keys) {
				index = 0
			}
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		cache := newGeoCacheRuntime(geoCacheCapacity, geoCacheTTL, func() time.Time { return now })
		cache.storeAtEpoch(hitKey, data, epoch)
		b.ReportAllocs()
		b.RunParallel(func(parallel *testing.PB) {
			for parallel.Next() {
				cache.load(hitKey)
			}
		})
		b.StopTimer()
		benchmarkGeoCacheDataSink, _, benchmarkGeoCacheOKSink = cache.load(hitKey)
	})

	b.Run("LookupHit", func(b *testing.B) {
		ClearCaches()
		b.Cleanup(ClearCaches)
		lookupDescriptor := descriptor
		lookupDescriptor.Source = func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
			return data, nil
		}
		source := CachedGeoSource(lookupDescriptor)
		if _, err := source("1.1.1.1", time.Second, "en", false); err != nil {
			b.Fatalf("seed geo cache: %v", err)
		}
		b.ReportAllocs()
		var value *ipgeo.IPGeoData
		var err error
		for b.Loop() {
			value, err = source("1.1.1.1", time.Second, "en", false)
		}
		if err != nil || value == nil {
			b.Fatalf("cached source hit = (%+v, %v), want value", value, err)
		}
		benchmarkGeoCacheDataSink = value
	})

	b.Run("ParallelLookupHit", func(b *testing.B) {
		ClearCaches()
		b.Cleanup(ClearCaches)
		lookupDescriptor := descriptor
		lookupDescriptor.Source = func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
			return data, nil
		}
		source := CachedGeoSource(lookupDescriptor)
		if _, err := source("1.1.1.1", time.Second, "en", false); err != nil {
			b.Fatalf("seed geo cache: %v", err)
		}
		b.ReportAllocs()
		var failed atomic.Bool
		b.RunParallel(func(parallel *testing.PB) {
			for parallel.Next() {
				value, err := source("1.1.1.1", time.Second, "en", false)
				if err != nil || value == nil {
					failed.Store(true)
				}
			}
		})
		b.StopTimer()
		if failed.Load() {
			b.Fatal("cached source parallel hit failed")
		}
		var err error
		benchmarkGeoCacheDataSink, err = source("1.1.1.1", time.Second, "en", false)
		if err != nil {
			b.Fatalf("cached source final hit: %v", err)
		}
	})
}

func benchmarkGeoCacheKey(value uint32) geoCacheKey {
	return geoCacheKey{
		namespace: ipgeo.SourceNamespaceIPSB,
		backend:   ipgeo.SourceNamespaceIPSB,
		addr: netip.AddrFrom4([4]byte{
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}),
		language: "en",
	}
}
