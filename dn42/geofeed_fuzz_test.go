package dn42

import (
	"bytes"
	"encoding/csv"
	"testing"
)

const fuzzGeoFeedRowMaxBytes = 64 << 10

func FuzzParseGeoFeedRecord(f *testing.F) {
	f.Add([]byte("10.0.0.0/8,na,US,Test City\n"))
	f.Add([]byte("2001:db8::/32,eu,DE,Berlin,AS4242420000,example\n"))
	f.Add([]byte("bad-cidr,na,US,Invalid\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzGeoFeedRowMaxBytes {
			data = data[:fuzzGeoFeedRowMaxBytes]
		}
		reader := csv.NewReader(bytes.NewReader(data))
		reader.FieldsPerRecord = -1
		row, err := reader.Read()
		if err != nil {
			return
		}
		record, ok := parseGeoFeedRecord(row)
		if !ok {
			return
		}
		if !record.Prefix.IsValid() || record.Prefix != record.Prefix.Masked() {
			t.Fatalf("record prefix = %v, want valid masked prefix", record.Prefix)
		}
		if len(row) != 4 && len(row) < 6 {
			t.Fatalf("accepted unsupported row width %d", len(row))
		}
		if record.CIDR != row[0] {
			t.Fatalf("record CIDR = %q, want original %q", record.CIDR, row[0])
		}
		index := buildGeoFeedIndex([]GeoFeedRecord{record}, geoFeedFileIdentity{}, 1)
		if found, exists := index.Lookup(record.Prefix.Addr()); !exists || found != record {
			t.Fatalf("indexed record = (%+v, %v), want %+v", found, exists, record)
		}

		var encoded bytes.Buffer
		writer := csv.NewWriter(&encoded)
		if err := writer.Write(row); err != nil {
			t.Fatalf("encode CSV row: %v", err)
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			t.Fatalf("flush CSV row: %v", err)
		}
		roundTripReader := csv.NewReader(&encoded)
		roundTripReader.FieldsPerRecord = -1
		roundTripRow, err := roundTripReader.Read()
		if err != nil {
			t.Fatalf("decode encoded CSV row: %v", err)
		}
		roundTrip, valid := parseGeoFeedRecord(roundTripRow)
		if !valid || roundTrip != record {
			t.Fatalf("GeoFeed round-trip = (%+v, %v), want %+v", roundTrip, valid, record)
		}
	})
}
