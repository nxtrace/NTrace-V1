package dn42

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const benchmarkGeoFeedEntryCount = 4096

var (
	benchmarkGeoFeedRowsSink   []GeoFeedRow
	benchmarkGeoFeedRowSink    GeoFeedRow
	benchmarkGeoFeedRecordSink GeoFeedRecord
	benchmarkGeoFeedFoundSink  bool
)

func BenchmarkReadGeoFeedCachedLegacyView(b *testing.B) {
	content := buildBenchmarkGeoFeedCSV(false, benchmarkGeoFeedEntryCount/2) +
		buildBenchmarkGeoFeedCSV(true, benchmarkGeoFeedEntryCount/2)
	setBenchmarkGeoFeedPath(b, writeBenchmarkGeoFeed(b, content))
	if _, err := ReadGeoFeed(); err != nil {
		b.Fatalf("ReadGeoFeed() setup error = %v", err)
	}

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
	for _, test := range []struct {
		name string
		ipv6 bool
	}{
		{name: "IPv4"},
		{name: "IPv6", ipv6: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			content := buildBenchmarkGeoFeedCSV(test.ipv6, benchmarkGeoFeedEntryCount)
			setBenchmarkGeoFeedPath(b, writeBenchmarkGeoFeed(b, content))
			rows, err := ReadGeoFeed()
			if err != nil {
				b.Fatalf("ReadGeoFeed() setup error = %v", err)
			}
			if len(rows) != benchmarkGeoFeedEntryCount {
				b.Fatalf("ReadGeoFeed() rows = %d, want %d", len(rows), benchmarkGeoFeedEntryCount)
			}

			lookups := []struct {
				name     string
				target   string
				wantCIDR string
				wantHit  bool
			}{
				{name: "HeadHit", target: rows[0].IPNet.IP.String(), wantCIDR: rows[0].CIDR, wantHit: true},
				{name: "MiddleHit", target: rows[len(rows)/2].IPNet.IP.String(), wantCIDR: rows[len(rows)/2].CIDR, wantHit: true},
				{name: "TailHit", target: rows[len(rows)-1].IPNet.IP.String(), wantCIDR: rows[len(rows)-1].CIDR, wantHit: true},
				{name: "Miss", target: benchmarkGeoFeedMissTarget(test.ipv6)},
			}
			for _, lookup := range lookups {
				b.Run(lookup.name, func(b *testing.B) {
					b.ReportAllocs()
					var row GeoFeedRow
					var found bool
					for b.Loop() {
						row, found = FindGeoFeedRow(lookup.target, rows)
					}
					if found != lookup.wantHit || found && row.CIDR != lookup.wantCIDR {
						b.Fatalf("FindGeoFeedRow(%q) = (%+v, %v), want CIDR %q, found %v", lookup.target, row, found, lookup.wantCIDR, lookup.wantHit)
					}
					benchmarkGeoFeedRowSink = row
					benchmarkGeoFeedFoundSink = found
				})
			}
		})
	}
}

func BenchmarkGeoFeedParseIndex(b *testing.B) {
	content := buildBenchmarkGeoFeedCSV(false, benchmarkGeoFeedEntryCount/2) +
		buildBenchmarkGeoFeedCSV(true, benchmarkGeoFeedEntryCount/2)
	b.ReportAllocs()
	var index *GeoFeedIndex
	for b.Loop() {
		var err error
		index, err = parseGeoFeedIndex(strings.NewReader(content), geoFeedFileIdentity{}, 1)
		if err != nil {
			b.Fatalf("parseGeoFeedIndex() error = %v", err)
		}
	}
	if len(index.records) != benchmarkGeoFeedEntryCount {
		b.Fatalf("parsed records = %d, want %d", len(index.records), benchmarkGeoFeedEntryCount)
	}
	benchmarkGeoFeedRecordSink = index.records[len(index.records)-1]
}

func BenchmarkGeoFeedLookupImplementationsMixed4096(b *testing.B) {
	for _, test := range []struct {
		name string
		ipv6 bool
	}{
		{name: "IPv4"},
		{name: "IPv6", ipv6: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			content := buildMixedBenchmarkGeoFeedCSV(test.ipv6, benchmarkGeoFeedEntryCount)
			path := writeBenchmarkGeoFeed(b, content)
			rows, err := legacyReadGeoFeed(path)
			if err != nil {
				b.Fatalf("legacyReadGeoFeed() error = %v", err)
			}
			index, err := parseGeoFeedIndex(strings.NewReader(content), geoFeedFileIdentity{}, 1)
			if err != nil {
				b.Fatalf("parseGeoFeedIndex() error = %v", err)
			}
			validateMixedBenchmarkGeoFeedShape(b, rows, index, test.ipv6)
			trie := buildBenchmarkGeoFeedTrie(index.records)
			queries := benchmarkGeoFeedQueries(index, test.ipv6)
			validateBenchmarkGeoFeedImplementations(b, rows, index, trie, queries)

			b.Run("LegacyEndToEnd", func(b *testing.B) {
				b.ReportAllocs()
				queryIndex := 0
				var row GeoFeedRow
				var found bool
				for b.Loop() {
					query := queries[queryIndex&3]
					queryIndex++
					loadedRows, loadErr := legacyReadGeoFeed(path)
					if loadErr != nil {
						b.Fatalf("legacyReadGeoFeed() error = %v", loadErr)
					}
					row, found = legacyFindGeoFeedRow(query.text, loadedRows)
				}
				benchmarkGeoFeedRowSink = row
				benchmarkGeoFeedFoundSink = found
			})

			b.Run("LegacyPreparsedSlice", func(b *testing.B) {
				b.ReportAllocs()
				queryIndex := 0
				var row GeoFeedRow
				var found bool
				for b.Loop() {
					query := queries[queryIndex&3]
					queryIndex++
					row, found = legacyFindGeoFeedRowParsed(query.ip, rows)
				}
				benchmarkGeoFeedRowSink = row
				benchmarkGeoFeedFoundSink = found
			})

			b.Run("PrefixMap", func(b *testing.B) {
				b.ReportAllocs()
				queryIndex := 0
				var record GeoFeedRecord
				var found bool
				for b.Loop() {
					query := queries[queryIndex&3]
					queryIndex++
					record, found = index.Lookup(query.addr)
				}
				benchmarkGeoFeedRecordSink = record
				benchmarkGeoFeedFoundSink = found
			})

			b.Run("TestOnlyTrie", func(b *testing.B) {
				b.ReportAllocs()
				queryIndex := 0
				var record GeoFeedRecord
				var found bool
				for b.Loop() {
					query := queries[queryIndex&3]
					queryIndex++
					record, found = trie.lookup(query.addr)
				}
				benchmarkGeoFeedRecordSink = record
				benchmarkGeoFeedFoundSink = found
			})
		})
	}
}

func validateMixedBenchmarkGeoFeedShape(b *testing.B, rows []GeoFeedRow, index *GeoFeedIndex, ipv6 bool) {
	b.Helper()
	if len(rows) != benchmarkGeoFeedEntryCount || len(index.records) != benchmarkGeoFeedEntryCount {
		b.Fatalf("mixed dataset sizes = rows %d index %d, want %d", len(rows), len(index.records), benchmarkGeoFeedEntryCount)
	}
	wantBits := []int{27, 26, 25, 24, 23, 22, 21, 20}
	gotBits := index.v4.prefixBits
	if ipv6 {
		wantBits = []int{128, 112, 96, 80, 72, 64, 56, 48}
		gotBits = index.v6.prefixBits
	}
	if !slices.Equal(gotBits, wantBits) {
		b.Fatalf("mixed prefix bits = %v, want %v", gotBits, wantBits)
	}
}

type benchmarkGeoFeedQuery struct {
	text string
	ip   net.IP
	addr netip.Addr
}

func benchmarkGeoFeedQueries(index *GeoFeedIndex, ipv6 bool) []benchmarkGeoFeedQuery {
	indices := []int{0, len(index.records) / 2, len(index.records) - 1}
	queries := make([]benchmarkGeoFeedQuery, 0, 4)
	for _, recordIndex := range indices {
		queries = append(queries, newBenchmarkGeoFeedQuery(index.records[recordIndex].Prefix.Addr().String()))
	}
	queries = append(queries, newBenchmarkGeoFeedQuery(benchmarkGeoFeedMissTarget(ipv6)))
	return queries
}

func newBenchmarkGeoFeedQuery(target string) benchmarkGeoFeedQuery {
	return benchmarkGeoFeedQuery{
		text: target,
		ip:   net.ParseIP(target),
		addr: netip.MustParseAddr(target),
	}
}

func validateBenchmarkGeoFeedImplementations(
	b *testing.B,
	rows []GeoFeedRow,
	index *GeoFeedIndex,
	trie *benchmarkGeoFeedTrie,
	queries []benchmarkGeoFeedQuery,
) {
	b.Helper()
	for _, query := range queries {
		legacyRow, legacyFound := legacyFindGeoFeedRowParsed(query.ip, rows)
		mapRecord, mapFound := index.Lookup(query.addr)
		trieRecord, trieFound := trie.lookup(query.addr)
		if legacyFound != mapFound || mapFound != trieFound {
			b.Fatalf("lookup %s found mismatch: legacy=%v map=%v trie=%v", query.text, legacyFound, mapFound, trieFound)
		}
		if mapFound && (legacyRow.CIDR != mapRecord.CIDR || mapRecord.CIDR != trieRecord.CIDR) {
			b.Fatalf("lookup %s CIDR mismatch: legacy=%q map=%q trie=%q", query.text, legacyRow.CIDR, mapRecord.CIDR, trieRecord.CIDR)
		}
	}
}

func legacyReadGeoFeed(path string) ([]GeoFeedRow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	input, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, err
	}
	rows := make([]GeoFeedRow, 0, len(input))
	for _, fields := range input {
		if len(fields) == 0 {
			continue
		}
		cidr := fields[0]
		_, ipNet, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil {
			continue
		}
		row := GeoFeedRow{IPNet: ipNet, CIDR: cidr}
		switch {
		case len(fields) == 4:
			row.LtdCode, row.ISO3166, row.City = fields[1], fields[2], fields[3]
		case len(fields) >= 6:
			row.LtdCode, row.ISO3166, row.City = fields[1], fields[2], fields[3]
			row.ASN, row.IPWhois = fields[4], fields[5]
		default:
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].IPNet.Mask.String() > rows[j].IPNet.Mask.String()
	})
	return rows, nil
}

func legacyFindGeoFeedRow(target string, rows []GeoFeedRow) (GeoFeedRow, bool) {
	return legacyFindGeoFeedRowParsed(net.ParseIP(target), rows)
}

func legacyFindGeoFeedRowParsed(target net.IP, rows []GeoFeedRow) (GeoFeedRow, bool) {
	if target == nil {
		return GeoFeedRow{}, false
	}
	for _, row := range rows {
		if row.IPNet.Contains(target) {
			return row, true
		}
	}
	return GeoFeedRow{}, false
}

type benchmarkGeoFeedTrie struct {
	v4 benchmarkGeoFeedTrieNode
	v6 benchmarkGeoFeedTrieNode
}

type benchmarkGeoFeedTrieNode struct {
	children [2]*benchmarkGeoFeedTrieNode
	record   GeoFeedRecord
	hasValue bool
}

func buildBenchmarkGeoFeedTrie(records []GeoFeedRecord) *benchmarkGeoFeedTrie {
	trie := new(benchmarkGeoFeedTrie)
	for _, record := range records {
		root := &trie.v6
		addr := record.Prefix.Addr()
		if addr.Is4() {
			root = &trie.v4
		}
		node := root
		for bitIndex := range record.Prefix.Bits() {
			bit := geoFeedBitAtAddr(addr, bitIndex)
			if node.children[bit] == nil {
				node.children[bit] = new(benchmarkGeoFeedTrieNode)
			}
			node = node.children[bit]
		}
		node.record = record
		node.hasValue = true
	}
	return trie
}

func (trie *benchmarkGeoFeedTrie) lookup(addr netip.Addr) (GeoFeedRecord, bool) {
	if trie == nil || !addr.IsValid() {
		return GeoFeedRecord{}, false
	}
	addr = addr.Unmap()
	root := &trie.v6
	maxBits := 128
	if addr.Is4() {
		root = &trie.v4
		maxBits = 32
	}
	node := root
	best, found := node.record, node.hasValue
	for bitIndex := range maxBits {
		node = node.children[geoFeedBitAtAddr(addr, bitIndex)]
		if node == nil {
			break
		}
		if node.hasValue {
			best, found = node.record, true
		}
	}
	return best, found
}

func geoFeedBitAtAddr(addr netip.Addr, bitIndex int) byte {
	if addr.Is4() {
		value := addr.As4()
		return (value[bitIndex/8] >> (7 - uint(bitIndex%8))) & 1
	}
	value := addr.As16()
	return (value[bitIndex/8] >> (7 - uint(bitIndex%8))) & 1
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
	for i := range entries {
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

func buildMixedBenchmarkGeoFeedCSV(ipv6 bool, entries int) string {
	var content strings.Builder
	content.Grow(entries * 72)
	if ipv6 {
		bits := [...]int{48, 56, 64, 72, 80, 96, 112, 128}
		for i := range entries {
			group := i % len(bits)
			ordinal := i / len(bits)
			_, _ = fmt.Fprintf(
				&content,
				"fd00:%x:%x::/%d,us,US,City-%d,AS%d,Owner-%d\n",
				group,
				ordinal,
				bits[group],
				i,
				64512+i,
				i,
			)
		}
		return content.String()
	}

	bits := [...]int{20, 21, 22, 23, 24, 25, 26, 27}
	for i := range entries {
		group := i % len(bits)
		ordinal := i / len(bits)
		block := group*(benchmarkGeoFeedEntryCount/len(bits)) + ordinal
		_, _ = fmt.Fprintf(
			&content,
			"10.%d.%d.0/%d,us,US,City-%d,AS%d,Owner-%d\n",
			block>>4,
			(block&15)<<4,
			bits[group],
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
