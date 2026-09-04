package dn42

import (
	"net"
	"net/netip"
	"sort"
)

// GeoFeedRow is the legacy GeoFeed representation kept for API compatibility.
type GeoFeedRow struct {
	IPNet   *net.IPNet
	CIDR    string
	LtdCode string
	ISO3166 string
	City    string
	ASN     string
	IPWhois string
}

// GetGeoFeed returns the longest-prefix GeoFeed match for ip.
func GetGeoFeed(ip string) (GeoFeedRow, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return GeoFeedRow{}, false
	}

	index, _ := LoadGeoFeedIndex()
	if index == nil {
		return GeoFeedRow{}, false
	}
	record, found := index.Lookup(addr)
	if !found {
		return GeoFeedRow{}, false
	}
	return geoFeedRecordToRow(record), true
}

// ReadGeoFeed returns a detached legacy view of the current GeoFeed snapshot.
// When a reload fails, it returns the last valid snapshot together with the
// reload error.
func ReadGeoFeed() ([]GeoFeedRow, error) {
	index, err := LoadGeoFeedIndex()
	if index == nil {
		return nil, err
	}
	return index.legacyRows(), err
}

// FindGeoFeedRow preserves the legacy first-match lookup contract.
func FindGeoFeedRow(ipStr string, rows []GeoFeedRow) (GeoFeedRow, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoFeedRow{}, false
	}

	for _, row := range rows {
		if row.IPNet.Contains(ip) {
			return row, true
		}
	}
	return GeoFeedRow{}, false
}

func (index *GeoFeedIndex) legacyRows() []GeoFeedRow {
	if index == nil || len(index.records) == 0 {
		return nil
	}
	rows := make([]GeoFeedRow, len(index.records))
	for i, record := range index.records {
		rows[i] = geoFeedRecordToRow(record)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].IPNet.Mask.String() > rows[j].IPNet.Mask.String()
	})
	return rows
}

func geoFeedRecordToRow(record GeoFeedRecord) GeoFeedRow {
	ipNet := prefixToIPNet(record.Prefix)
	if _, legacyIPNet, err := net.ParseCIDR(record.CIDR); err == nil {
		ipNet = legacyIPNet
	}
	return GeoFeedRow{
		IPNet:   ipNet,
		CIDR:    record.CIDR,
		LtdCode: record.LtdCode,
		ISO3166: record.ISO3166,
		City:    record.City,
		ASN:     record.ASN,
		IPWhois: record.IPWhois,
	}
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		ip := addr.As4()
		return &net.IPNet{
			IP:   net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4(),
			Mask: net.CIDRMask(bits, 32),
		}
	}
	ip := addr.As16()
	return &net.IPNet{
		IP:   append(net.IP(nil), ip[:]...),
		Mask: net.CIDRMask(bits, 128),
	}
}
