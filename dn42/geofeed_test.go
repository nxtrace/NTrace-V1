package dn42

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestParseGeoFeedIndexSkipsRecordErrors(t *testing.T) {
	index, err := parseGeoFeedIndex(strings.NewReader(strings.Join([]string{
		"10.0.0.0/8,na,US,Four columns",
		"too-short",
		"10.1.0.0/16,na,US,Five columns,AS64512",
		"bad-cidr,na,US,Bad CIDR",
		"10.1.2.0/24,eu,DE,Six columns,AS64513,Example",
		"2001:db8::/32,eu,DE,Extra columns,AS64514,Example,ignored",
	}, "\n")+"\n"), geoFeedFileIdentity{}, 7)
	if err != nil {
		t.Fatalf("parseGeoFeedIndex() error = %v", err)
	}
	if got := index.Generation(); got != 7 {
		t.Fatalf("Generation() = %d, want 7", got)
	}

	tests := []struct {
		addr     string
		wantCIDR string
		wantASN  string
	}{
		{addr: "10.2.3.4", wantCIDR: "10.0.0.0/8"},
		{addr: "10.1.2.3", wantCIDR: "10.1.2.0/24", wantASN: "AS64513"},
		{addr: "2001:db8::1", wantCIDR: "2001:db8::/32", wantASN: "AS64514"},
	}
	for _, test := range tests {
		record, found := index.Lookup(netip.MustParseAddr(test.addr))
		if !found || record.CIDR != test.wantCIDR || record.ASN != test.wantASN {
			t.Errorf("Lookup(%s) = (%+v, %v), want CIDR %q ASN %q", test.addr, record, found, test.wantCIDR, test.wantASN)
		}
	}
	if _, found := index.Lookup(netip.MustParseAddr("192.0.2.1")); found {
		t.Error("Lookup(miss) found a record")
	}
	if got := len(index.records); got != 3 {
		t.Fatalf("record count = %d, want 3", got)
	}
	if !slices.Equal(index.v4.prefixBits, []int{24, 8}) {
		t.Fatalf("IPv4 prefix bits = %v, want [24 8]", index.v4.prefixBits)
	}
	if !slices.Equal(index.v6.prefixBits, []int{32}) {
		t.Fatalf("IPv6 prefix bits = %v, want [32]", index.v6.prefixBits)
	}
}

func TestParseGeoFeedIndexRejectsStructuralAndIOErrors(t *testing.T) {
	t.Run("MalformedCSV", func(t *testing.T) {
		_, err := parseGeoFeedIndex(
			strings.NewReader("10.0.0.0/8,na,US,\"unterminated\n"),
			geoFeedFileIdentity{},
			1,
		)
		if err == nil {
			t.Fatal("parseGeoFeedIndex() error = nil, want CSV parse error")
		}
	})

	t.Run("ReaderFailure", func(t *testing.T) {
		wantErr := errors.New("injected read failure")
		_, err := parseGeoFeedIndex(errorReader{err: wantErr}, geoFeedFileIdentity{}, 1)
		if !errors.Is(err, wantErr) {
			t.Fatalf("parseGeoFeedIndex() error = %v, want %v", err, wantErr)
		}
	})
}

func TestParseGeoFeedIndexCSVFixtures(t *testing.T) {
	index := mustParseGeoFeedIndex(t,
		"10.3.0.0/16,na,US,\"City, With Comma\"\r\n"+
			"10.4.0.0/16,na,US,\"City\r\nWith Newline\",AS64512,Owner\r\n",
	)
	tests := []struct {
		addr     string
		wantCity string
	}{
		{addr: "10.3.1.1", wantCity: "City, With Comma"},
		{addr: "10.4.1.1", wantCity: "City\nWith Newline"},
	}
	for _, test := range tests {
		record, found := index.Lookup(netip.MustParseAddr(test.addr))
		if !found || record.City != test.wantCity {
			t.Errorf("Lookup(%s) = (%+v, %v), want city %q", test.addr, record, found, test.wantCity)
		}
	}
}

func TestGeoFeedIndexLongestPrefixLastWinsAndMappedIPv4(t *testing.T) {
	index := mustParseGeoFeedIndex(t, strings.Join([]string{
		"10.0.0.0/8,na,US,Broad,AS1,Broad Owner",
		"10.1.0.0/16,na,US,Narrow,AS2,Narrow Owner",
		"10.1.2.99/24,na,US,First,AS3,First Owner",
		"10.1.2.0/24,na,US,Last,AS4,Last Owner",
		"10.1.2.0/24,na,US,Invalid Later Row,AS5",
		"::ffff:10.2.0.0/112,na,US,Mapped Prefix,AS5,Mapped Owner",
		"2001:db8::/32,na,US,IPv6 Broad,AS6,IPv6 Broad Owner",
		"2001:db8:1::/48,na,US,IPv6 Narrow,AS7,IPv6 Narrow Owner",
	}, "\n")+"\n")

	tests := []struct {
		addr     string
		wantCity string
	}{
		{addr: "10.1.2.8", wantCity: "Last"},
		{addr: "::ffff:10.1.2.8", wantCity: "Last"},
		{addr: "10.1.9.8", wantCity: "Narrow"},
		{addr: "10.2.9.8", wantCity: "Mapped Prefix"},
		{addr: "2001:db8:1::1", wantCity: "IPv6 Narrow"},
		{addr: "2001:db8:2::1", wantCity: "IPv6 Broad"},
	}
	for _, test := range tests {
		record, found := index.Lookup(netip.MustParseAddr(test.addr))
		if !found || record.City != test.wantCity {
			t.Errorf("Lookup(%s) = (%+v, %v), want city %q", test.addr, record, found, test.wantCity)
		}
	}
	if _, found := index.Lookup(netip.Addr{}); found {
		t.Error("Lookup(invalid) found a record")
	}
}

func TestGeoFeedStoreLazyReloadAndGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geofeed.csv")
	baseTime := time.Unix(1_700_000_000, 0)
	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,First\n", baseTime)

	var store geoFeedStore
	first, err := store.load(path)
	if err != nil {
		t.Fatalf("first load error = %v", err)
	}
	if first.Generation() != 1 {
		t.Fatalf("first generation = %d, want 1", first.Generation())
	}
	unchanged, err := store.load(path)
	if err != nil {
		t.Fatalf("unchanged load error = %v", err)
	}
	if unchanged != first {
		t.Fatal("unchanged file published a new snapshot")
	}

	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,Other\n", baseTime)
	sameMetadata, err := store.load(path)
	if err != nil {
		t.Fatalf("same-metadata load error = %v", err)
	}
	if sameMetadata != first {
		t.Fatal("same path/mtime/size published a new snapshot")
	}
	record, found := sameMetadata.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !found || record.City != "First" {
		t.Fatalf("same-metadata Lookup() = (%+v, %v), want retained First", record, found)
	}

	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,Other\n", baseTime.Add(time.Second))
	second, err := store.load(path)
	if err != nil {
		t.Fatalf("changed load error = %v", err)
	}
	if second == first || second.Generation() != 2 {
		t.Fatalf("changed load = %p generation %d, want new snapshot generation 2", second, second.Generation())
	}
	record, found = second.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !found || record.City != "Other" {
		t.Fatalf("mtime-changed Lookup() = (%+v, %v), want Other", record, found)
	}

	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,Longer\n", baseTime.Add(time.Second))
	third, err := store.load(path)
	if err != nil {
		t.Fatalf("size-changed load error = %v", err)
	}
	if third == second || third.Generation() != 3 {
		t.Fatalf("size-changed load = %p generation %d, want new snapshot generation 3", third, third.Generation())
	}

	otherPath := filepath.Join(dir, "other.csv")
	writeGeoFeedAt(t, otherPath, "10.0.0.0/8,na,US,Longer\n", baseTime.Add(time.Second))
	fourth, err := store.load(otherPath)
	if err != nil {
		t.Fatalf("path-changed load error = %v", err)
	}
	if fourth == third || fourth.Generation() != 4 {
		t.Fatalf("path-changed load = %p generation %d, want new snapshot generation 4", fourth, fourth.Generation())
	}
}

func TestGeoFeedStoreFailedReloadPreservesSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	baseTime := time.Unix(1_700_000_000, 0)
	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,Valid\n", baseTime)

	var store geoFeedStore
	valid, err := store.load(path)
	if err != nil {
		t.Fatalf("valid load error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove geofeed: %v", err)
	}
	stale, err := store.load(path)
	if err == nil || stale != valid {
		t.Fatalf("missing-file reload = (%p, %v), want old %p and error", stale, err, valid)
	}
	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,\"unterminated\n", baseTime.Add(time.Second))

	stale, err = store.load(path)
	if err == nil {
		t.Fatal("malformed reload error = nil")
	}
	if stale != valid || stale.Generation() != 1 {
		t.Fatalf("failed reload returned %p generation %d, want old %p generation 1", stale, stale.Generation(), valid)
	}
	record, found := stale.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !found || record.City != "Valid" {
		t.Fatalf("stale Lookup() = (%+v, %v), want Valid", record, found)
	}

	writeGeoFeedAt(t, path, "", baseTime.Add(2*time.Second))
	empty, err := store.load(path)
	if err != nil {
		t.Fatalf("empty reload error = %v", err)
	}
	if empty == valid || empty.Generation() != 2 {
		t.Fatalf("empty reload = %p generation %d, want new snapshot generation 2", empty, empty.Generation())
	}
	if _, found := empty.Lookup(netip.MustParseAddr("10.1.2.3")); found {
		t.Error("empty snapshot unexpectedly contains old record")
	}
}

func TestLoadGeoFeedFileRejectsSameMetadataReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geofeed.csv")
	replacement := filepath.Join(dir, "replacement.csv")
	modTime := time.Unix(1_700_000_000, 0)
	content := "10.0.0.0/8,na,US,Same metadata\n"
	writeGeoFeedAt(t, path, content, modTime)
	writeGeoFeedAt(t, replacement, content, modTime)

	identity, err := statGeoFeed(path)
	if err != nil {
		t.Fatalf("statGeoFeed() error = %v", err)
	}
	_, err = loadGeoFeedFileWithFinalStat(
		path,
		identity,
		1,
		func(string) (os.FileInfo, error) { return os.Stat(replacement) },
	)
	if err == nil || !strings.Contains(err.Error(), "changed while loading") {
		t.Fatalf("same-metadata replacement error = %v, want changed-while-loading error", err)
	}
}

func TestGeoFeedStoreInitialFailureDoesNotConsumeGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	var store geoFeedStore
	if index, err := store.load(path); err == nil || index != nil {
		t.Fatalf("load(missing) = (%p, %v), want nil and error", index, err)
	}

	writeGeoFeedAt(t, path, "bad,na,US,Invalid\n", time.Unix(1_700_000_000, 0))
	index, err := store.load(path)
	if err != nil {
		t.Fatalf("record-level errors should publish empty snapshot: %v", err)
	}
	if index.Generation() != 1 || len(index.records) != 0 {
		t.Fatalf("invalid-only snapshot = generation %d records %d, want 1 and 0", index.Generation(), len(index.records))
	}
}

func TestGeoFeedIndexBackedLegacyAPIsReturnDetachedIPNet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	modTime := time.Unix(1_700_000_000, 0)
	writeGeoFeedAt(t, path, "10.1.0.0/16,na,US,Legacy,AS64512,Owner\n", modTime)
	setGeoFeedPathForTest(t, path)

	rows, err := ReadGeoFeed()
	if err != nil {
		t.Fatalf("ReadGeoFeed() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ReadGeoFeed() rows = %d, want 1", len(rows))
	}
	rows[0].IPNet.IP[0] = 192
	rows[0].IPNet.Mask[0] = 0

	again, err := ReadGeoFeed()
	if err != nil {
		t.Fatalf("second ReadGeoFeed() error = %v", err)
	}
	if got := again[0].IPNet.String(); got != "10.1.0.0/16" {
		t.Fatalf("second ReadGeoFeed() IPNet = %q, want 10.1.0.0/16", got)
	}
	row, found := GetGeoFeed("10.1.2.3")
	if !found || row.City != "Legacy" {
		t.Fatalf("GetGeoFeed() = (%+v, %v), want Legacy", row, found)
	}
	row.IPNet.IP[0] = 192
	row, found = GetGeoFeed("10.1.2.3")
	if !found || row.IPNet.String() != "10.1.0.0/16" {
		t.Fatalf("second GetGeoFeed() = (%+v, %v), want detached IPNet", row, found)
	}
	writeGeoFeedAt(t, path, "10.1.0.0/16,na,US,\"unterminated\n", modTime.Add(time.Second))
	staleRows, err := ReadGeoFeed()
	if err == nil || len(staleRows) != 1 || staleRows[0].City != "Legacy" {
		t.Fatalf("ReadGeoFeed() after failed reload = (%+v, %v), want stale Legacy row and error", staleRows, err)
	}
	row, found = GetGeoFeed("10.1.2.3")
	if !found || row.City != "Legacy" {
		t.Fatalf("GetGeoFeed() after failed reload = (%+v, %v), want stale Legacy row", row, found)
	}

	input := []GeoFeedRow{{
		IPNet: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		CIDR:  "10.0.0.0/8",
	}}
	foundRow, found := FindGeoFeedRow("10.1.2.3", input)
	if !found {
		t.Fatal("FindGeoFeedRow() did not find input row")
	}
	if foundRow.CIDR != input[0].CIDR {
		t.Fatalf("FindGeoFeedRow() CIDR = %q, want %q", foundRow.CIDR, input[0].CIDR)
	}
	if _, found := FindGeoFeedRow("10.1.2.3", []GeoFeedRow{{IPNet: nil}}); found {
		t.Fatal("FindGeoFeedRow() matched nil IPNet")
	}
}

func TestGeoFeedLegacyRowsPreserveMaskStringOrder(t *testing.T) {
	index := mustParseGeoFeedIndex(t, strings.Join([]string{
		"10.0.0.0/8,na,US,IPv4 Eight",
		"2001:db8::/32,na,US,IPv6 Thirty Two",
		"10.1.2.0/24,na,US,IPv4 Twenty Four",
		"2001:db8:1::/64,na,US,IPv6 Sixty Four",
	}, "\n")+"\n")
	rows := index.legacyRows()
	got := make([]string, len(rows))
	for i, row := range rows {
		got[i] = row.CIDR
	}
	want := []string{
		"2001:db8:1::/64",
		"2001:db8::/32",
		"10.1.2.0/24",
		"10.0.0.0/8",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("legacy row order = %v, want %v", got, want)
	}
}

func TestGeoFeedLegacyRowsPreserveMappedIPv4IPNet(t *testing.T) {
	index := mustParseGeoFeedIndex(t, "::ffff:10.2.0.0/112,na,US,Mapped\n")
	rows := index.legacyRows()
	if len(rows) != 1 {
		t.Fatalf("legacy rows = %d, want 1", len(rows))
	}
	ones, bits := rows[0].IPNet.Mask.Size()
	if ones != 112 || bits != 128 || len(rows[0].IPNet.IP) != net.IPv6len {
		t.Fatalf("mapped legacy IPNet = %v mask (%d, %d) IP len %d", rows[0].IPNet, ones, bits, len(rows[0].IPNet.IP))
	}
	if !rows[0].IPNet.Contains(net.ParseIP("::ffff:10.2.1.1")) {
		t.Fatal("mapped legacy IPNet no longer contains mapped IPv4 address")
	}
}

func TestGeoFeedStoreConcurrentLoadAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	writeGeoFeedAt(t, path, "10.0.0.0/8,na,US,Concurrent\n", time.Unix(1_700_000_000, 0))

	var store geoFeedStore
	const workers = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Go(func() {
			<-start
			for range 100 {
				index, err := store.load(path)
				if err != nil {
					errs <- err
					return
				}
				record, found := index.Lookup(netip.MustParseAddr("10.1.2.3"))
				if !found || record.City != "Concurrent" {
					errs <- errors.New("concurrent lookup returned wrong record")
					return
				}
			}
		})
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if index := store.current.Load(); index == nil || index.Generation() != 1 {
		t.Fatalf("published index = %p generation %d, want non-nil generation 1", index, index.Generation())
	}
}

func TestGeoFeedIndexLookupAllocations(t *testing.T) {
	index := mustParseGeoFeedIndex(t, "10.0.0.0/8,na,US,Allocation\n")
	addr := netip.MustParseAddr("10.1.2.3")
	allocs := testing.AllocsPerRun(1000, func() {
		record, found := index.Lookup(addr)
		if !found || record.City != "Allocation" {
			panic("unexpected lookup result")
		}
	})
	if allocs > 1 {
		t.Fatalf("Lookup() allocations = %.2f, want <= 1", allocs)
	}
}

func TestFindGeoFeedRowInvalidIP(t *testing.T) {
	row, found := FindGeoFeedRow("not-an-ip", nil)
	if found || row != (GeoFeedRow{}) {
		t.Fatalf("FindGeoFeedRow(invalid) = (%+v, %v), want zero and false", row, found)
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func mustParseGeoFeedIndex(t *testing.T, content string) *GeoFeedIndex {
	t.Helper()
	index, err := parseGeoFeedIndex(strings.NewReader(content), geoFeedFileIdentity{}, 1)
	if err != nil {
		t.Fatalf("parseGeoFeedIndex() error = %v", err)
	}
	return index
}

func writeGeoFeedAt(t *testing.T, path, content string, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write geofeed: %v", err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("set geofeed timestamps: %v", err)
	}
}

func setGeoFeedPathForTest(t *testing.T, path string) {
	t.Helper()
	previous := viper.Get("geoFeedPath")
	defaultGeoFeedStore.mu.Lock()
	defaultGeoFeedStore.current.Store(nil)
	defaultGeoFeedStore.nextGeneration = 0
	defaultGeoFeedStore.mu.Unlock()
	viper.Set("geoFeedPath", path)
	t.Cleanup(func() {
		defaultGeoFeedStore.mu.Lock()
		defaultGeoFeedStore.current.Store(nil)
		defaultGeoFeedStore.nextGeneration = 0
		defaultGeoFeedStore.mu.Unlock()
		viper.Set("geoFeedPath", previous)
	})
}
