package dn42

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nxtrace/NTrace-core/config"
)

// GeoFeedRecord is an immutable value stored in a GeoFeedIndex.
type GeoFeedRecord struct {
	Prefix  netip.Prefix
	CIDR    string
	LtdCode string
	ISO3166 string
	City    string
	ASN     string
	IPWhois string
}

// GeoFeedIndex is an immutable longest-prefix-match GeoFeed snapshot.
type GeoFeedIndex struct {
	v4         geoFeedFamilyIndex
	v6         geoFeedFamilyIndex
	records    []GeoFeedRecord
	generation uint64
	identity   geoFeedFileIdentity
}

type geoFeedFamilyIndex struct {
	prefixBits []int
	byBits     map[int]map[netip.Prefix]GeoFeedRecord
}

type geoFeedFileIdentity struct {
	path    string
	modTime time.Time
	size    int64
}

type geoFeedStore struct {
	mu             sync.Mutex
	current        atomic.Pointer[GeoFeedIndex]
	nextGeneration uint64
}

var defaultGeoFeedStore geoFeedStore

// LoadGeoFeedIndex lazily loads or reloads the configured GeoFeed file. A
// failed reload returns the last valid snapshot and leaves it published.
func LoadGeoFeedIndex() (*GeoFeedIndex, error) {
	path := config.GeoFeedPath()
	if path == "" {
		return defaultGeoFeedStore.current.Load(), fmt.Errorf("geoFeedPath not configured")
	}
	return defaultGeoFeedStore.load(path)
}

// Generation identifies the successful publication that produced index.
func (index *GeoFeedIndex) Generation() uint64 {
	if index == nil {
		return 0
	}
	return index.generation
}

// Lookup performs a longest-prefix match without file I/O.
func (index *GeoFeedIndex) Lookup(addr netip.Addr) (GeoFeedRecord, bool) {
	if index == nil || !addr.IsValid() {
		return GeoFeedRecord{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return index.v4.lookup(addr)
	}
	return index.v6.lookup(addr)
}

func (family geoFeedFamilyIndex) lookup(addr netip.Addr) (GeoFeedRecord, bool) {
	for _, bits := range family.prefixBits {
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if record, found := family.byBits[bits][prefix]; found {
			return record, true
		}
	}
	return GeoFeedRecord{}, false
}

func (store *geoFeedStore) load(path string) (*GeoFeedIndex, error) {
	identity, _, err := statGeoFeed(path)
	if err != nil {
		return store.current.Load(), err
	}
	if current := store.current.Load(); current != nil && current.identity.equal(identity) {
		return current, nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	identity, statInfo, err := statGeoFeed(path)
	if err != nil {
		return store.current.Load(), err
	}
	if current := store.current.Load(); current != nil && current.identity.equal(identity) {
		return current, nil
	}

	generation := store.nextGeneration + 1
	index, err := loadGeoFeedFile(path, identity, statInfo, generation)
	if err != nil {
		return store.current.Load(), err
	}
	store.nextGeneration = generation
	store.current.Store(index)
	return index, nil
}

func statGeoFeed(path string) (geoFeedFileIdentity, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return geoFeedFileIdentity{}, nil, err
	}
	if !info.Mode().IsRegular() {
		return geoFeedFileIdentity{}, nil, fmt.Errorf("geofeed %q is not a regular file", path)
	}
	return geoFeedFileIdentity{path: path, modTime: info.ModTime(), size: info.Size()}, info, nil
}

func (identity geoFeedFileIdentity) equal(other geoFeedFileIdentity) bool {
	return identity.path == other.path &&
		identity.size == other.size &&
		identity.modTime.Equal(other.modTime)
}

func loadGeoFeedFile(
	path string,
	wantIdentity geoFeedFileIdentity,
	wantInfo os.FileInfo,
	generation uint64,
) (*GeoFeedIndex, error) {
	return loadGeoFeedFileWithFileOps(path, wantIdentity, wantInfo, generation, os.Open, os.Stat)
}

func loadGeoFeedFileWithFileOps(
	path string,
	wantIdentity geoFeedFileIdentity,
	wantInfo os.FileInfo,
	generation uint64,
	openFile func(string) (*os.File, error),
	finalStat func(string) (os.FileInfo, error),
) (*GeoFeedIndex, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	openedIdentity := geoFeedFileIdentity{
		path:    path,
		modTime: openedInfo.ModTime(),
		size:    openedInfo.Size(),
	}
	if !wantIdentity.equal(openedIdentity) || !os.SameFile(wantInfo, openedInfo) {
		return nil, fmt.Errorf("geofeed %q changed before loading", path)
	}

	index, err := parseGeoFeedIndex(file, openedIdentity, generation)
	if err != nil {
		return nil, err
	}

	loadedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	loadedIdentity := geoFeedFileIdentity{
		path:    path,
		modTime: loadedInfo.ModTime(),
		size:    loadedInfo.Size(),
	}
	currentInfo, err := finalStat(path)
	if err != nil {
		return nil, err
	}
	currentIdentity := geoFeedFileIdentity{
		path:    path,
		modTime: currentInfo.ModTime(),
		size:    currentInfo.Size(),
	}
	if !openedIdentity.equal(loadedIdentity) ||
		!openedIdentity.equal(currentIdentity) ||
		!os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("geofeed %q changed while loading", path)
	}
	return index, nil
}

func parseGeoFeedIndex(
	reader io.Reader,
	identity geoFeedFileIdentity,
	generation uint64,
) (*GeoFeedIndex, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1

	records := make([]GeoFeedRecord, 0)
	for {
		row, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if record, valid := parseGeoFeedRecord(row); valid {
			records = append(records, record)
		}
	}
	return buildGeoFeedIndex(records, identity, generation), nil
}

func parseGeoFeedRecord(row []string) (GeoFeedRecord, bool) {
	if len(row) != 4 && len(row) < 6 {
		return GeoFeedRecord{}, false
	}
	prefix, err := netip.ParsePrefix(row[0])
	if err != nil {
		return GeoFeedRecord{}, false
	}
	prefix, valid := normalizeGeoFeedPrefix(prefix)
	if !valid {
		return GeoFeedRecord{}, false
	}

	record := GeoFeedRecord{
		Prefix:  prefix,
		CIDR:    row[0],
		LtdCode: row[1],
		ISO3166: row[2],
		City:    row[3],
	}
	if len(row) >= 6 {
		record.ASN = row[4]
		record.IPWhois = row[5]
	}
	return record, true
}

func normalizeGeoFeedPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr.Unmap(), bits-96).Masked(), true
	}
	return prefix.Masked(), true
}

func buildGeoFeedIndex(
	records []GeoFeedRecord,
	identity geoFeedFileIdentity,
	generation uint64,
) *GeoFeedIndex {
	index := &GeoFeedIndex{
		v4:         newGeoFeedFamilyIndex(),
		v6:         newGeoFeedFamilyIndex(),
		generation: generation,
		identity:   identity,
	}
	for _, record := range records {
		family := &index.v6
		if record.Prefix.Addr().Is4() {
			family = &index.v4
		}
		bits := record.Prefix.Bits()
		bucket := family.byBits[bits]
		if bucket == nil {
			bucket = make(map[netip.Prefix]GeoFeedRecord)
			family.byBits[bits] = bucket
		}
		bucket[record.Prefix] = record
	}
	index.v4.finalize()
	index.v6.finalize()
	index.records = appendFamilyRecords(index.records, index.v4)
	index.records = appendFamilyRecords(index.records, index.v6)
	return index
}

func newGeoFeedFamilyIndex() geoFeedFamilyIndex {
	return geoFeedFamilyIndex{byBits: make(map[int]map[netip.Prefix]GeoFeedRecord)}
}

func (family *geoFeedFamilyIndex) finalize() {
	family.prefixBits = make([]int, 0, len(family.byBits))
	for bits := range family.byBits {
		family.prefixBits = append(family.prefixBits, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(family.prefixBits)))
}

func appendFamilyRecords(records []GeoFeedRecord, family geoFeedFamilyIndex) []GeoFeedRecord {
	for _, bits := range family.prefixBits {
		prefixes := make([]netip.Prefix, 0, len(family.byBits[bits]))
		for prefix := range family.byBits[bits] {
			prefixes = append(prefixes, prefix)
		}
		sort.Slice(prefixes, func(i, j int) bool {
			return prefixes[i].Addr().Compare(prefixes[j].Addr()) < 0
		})
		for _, prefix := range prefixes {
			records = append(records, family.byBits[bits][prefix])
		}
	}
	return records
}
