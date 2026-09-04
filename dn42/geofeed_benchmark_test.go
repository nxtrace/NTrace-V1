package dn42

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const benchmarkGeoFeedEntryCount = 4096

var (
	benchmarkGeoFeedRowsSink  []GeoFeedRow
	benchmarkGeoFeedRowSink   GeoFeedRow
	benchmarkGeoFeedFoundSink bool
)

func BenchmarkReadGeoFeedCSV(b *testing.B) {
	content := buildBenchmarkGeoFeedCSV(false, benchmarkGeoFeedEntryCount/2) +
		buildBenchmarkGeoFeedCSV(true, benchmarkGeoFeedEntryCount/2)
	setBenchmarkGeoFeedPath(b, writeBenchmarkGeoFeed(b, content))

	b.ReportAllocs()
	var (
		rows []GeoFeedRow
		err  error
	)
	for b.Loop() {
		rows, err = ReadGeoFeed()
		if err != nil {
			b.Fatalf("ReadGeoFeed() error = %v", err)
		}
	}
	benchmarkGeoFeedRowsSink = rows
}

func BenchmarkFindGeoFeedRow(b *testing.B) {
	for _, tc := range []struct {
		name string
		ipv6 bool
	}{
		{name: "IPv4", ipv6: false},
		{name: "IPv6", ipv6: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			content := buildBenchmarkGeoFeedCSV(tc.ipv6, benchmarkGeoFeedEntryCount)
			setBenchmarkGeoFeedPath(b, writeBenchmarkGeoFeed(b, content))
			rows, err := ReadGeoFeed()
			if err != nil {
				b.Fatalf("ReadGeoFeed() setup error = %v", err)
			}
			if len(rows) != benchmarkGeoFeedEntryCount {
				b.Fatalf("ReadGeoFeed() rows = %d, want %d", len(rows), benchmarkGeoFeedEntryCount)
			}

			lookupCases := []struct {
				name     string
				target   string
				wantCIDR string
				wantHit  bool
			}{
				{
					name:     "HeadHit",
					target:   rows[0].IPNet.IP.String(),
					wantCIDR: rows[0].CIDR,
					wantHit:  true,
				},
				{
					name:     "MiddleHit",
					target:   rows[len(rows)/2].IPNet.IP.String(),
					wantCIDR: rows[len(rows)/2].CIDR,
					wantHit:  true,
				},
				{
					name:     "TailHit",
					target:   rows[len(rows)-1].IPNet.IP.String(),
					wantCIDR: rows[len(rows)-1].CIDR,
					wantHit:  true,
				},
				{
					name:    "Miss",
					target:  benchmarkGeoFeedMissTarget(tc.ipv6),
					wantHit: false,
				},
			}

			for _, lookup := range lookupCases {
				b.Run(lookup.name, func(b *testing.B) {
					b.ReportAllocs()
					var (
						row   GeoFeedRow
						found bool
					)
					for b.Loop() {
						row, found = FindGeoFeedRow(lookup.target, rows)
					}
					if found != lookup.wantHit || found && row.CIDR != lookup.wantCIDR {
						b.Fatalf(
							"FindGeoFeedRow(%q) = (%+v, %v), want CIDR %q, found %v",
							lookup.target,
							row,
							found,
							lookup.wantCIDR,
							lookup.wantHit,
						)
					}
					benchmarkGeoFeedRowSink = row
					benchmarkGeoFeedFoundSink = found
				})
			}
		})
	}
}

func benchmarkGeoFeedMissTarget(ipv6 bool) string {
	if ipv6 {
		return "2001:db8::1"
	}
	return "192.0.2.1"
}

func buildBenchmarkGeoFeedCSV(ipv6 bool, entries int) string {
	var content strings.Builder
	content.Grow(entries * 72)
	for i := 0; i < entries; i++ {
		if ipv6 {
			_, _ = fmt.Fprintf(
				&content,
				"fd00:%x::/64,us,US,City-%d,AS%d,Owner-%d\n",
				i,
				i,
				64512+i,
				i,
			)
			continue
		}
		_, _ = fmt.Fprintf(
			&content,
			"10.%d.%d.0/24,us,US,City-%d,AS%d,Owner-%d\n",
			(i/256)%256,
			i%256,
			i,
			64512+i,
			i,
		)
	}
	return content.String()
}

func writeBenchmarkGeoFeed(b *testing.B, content string) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "geofeed.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		b.Fatalf("write benchmark geofeed: %v", err)
	}
	return path
}

func setBenchmarkGeoFeedPath(b *testing.B, path string) {
	b.Helper()
	previous := viper.Get("geoFeedPath")
	viper.Set("geoFeedPath", path)
	b.Cleanup(func() {
		viper.Set("geoFeedPath", previous)
	})
}
