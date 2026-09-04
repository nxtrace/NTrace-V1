package trace

import (
	"testing"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

var (
	benchmarkGeoCacheDataSink  *ipgeo.IPGeoData
	benchmarkGeoCacheValueSink any
	benchmarkGeoCacheOKSink    bool
)

func BenchmarkGeoCacheAccess(b *testing.B) {
	const (
		hitKey  = "benchmark-geo-cache-hit"
		missKey = "benchmark-geo-cache-miss"
	)
	geoCache.Store(hitKey, &ipgeo.IPGeoData{IP: "1.1.1.1", Asnumber: "13335"})
	geoCache.Delete(missKey)
	b.Cleanup(func() {
		geoCache.Delete(hitKey)
		geoCache.Delete(missKey)
	})

	b.Run("Hit", func(b *testing.B) {
		b.ReportAllocs()
		var (
			data *ipgeo.IPGeoData
			ok   bool
		)
		for b.Loop() {
			value, loaded := geoCache.Load(hitKey)
			if loaded {
				data, ok = value.(*ipgeo.IPGeoData)
			} else {
				data, ok = nil, false
			}
		}
		if !ok || data == nil {
			b.Fatal("geo cache hit benchmark did not load the seeded value")
		}
		benchmarkGeoCacheDataSink = data
		benchmarkGeoCacheOKSink = ok
	})

	b.Run("Miss", func(b *testing.B) {
		b.ReportAllocs()
		var (
			value any
			ok    bool
		)
		for b.Loop() {
			value, ok = geoCache.Load(missKey)
		}
		if ok {
			b.Fatal("geo cache miss benchmark unexpectedly loaded a value")
		}
		benchmarkGeoCacheValueSink = value
		benchmarkGeoCacheOKSink = ok
	})
}
