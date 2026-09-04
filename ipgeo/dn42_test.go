package ipgeo

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dn42GeoFeedA = "192.0.2.0/24,hk,HK,Hong Kong,AS65000,Owner A\n"
	dn42GeoFeedB = "192.0.2.0/24,tw,TW,Taipei,AS650001,Owner version B\n"
)

func TestLtdCodeToCountryOrAreaNameUsesExactCodes(t *testing.T) {
	tests := map[string]string{
		"US":        "United States",
		"bd":        "Bangladesh",
		"ca":        "Canada",
		"dk":        "Denmark",
		"do":        "Dominica",
		"gb":        "United Kingdom",
		"hk":        "Hong Kong",
		"kw":        "Kuwait",
		"mh":        "Marshall Islands",
		"mo":        "Macao",
		"se":        "Sweden",
		"tf":        "French Southern Territories",
		"tw":        "Taiwan",
		"unknown":   "unknown",
		"prefix-us": "prefix-us",
		" us ":      " us ",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, LtdCodeToCountryOrAreaName(input))
		})
	}
	assert.Len(t, countryOrAreaNameByLtdCode, 244)
}

func TestDN42SourceSessionPinsAndRefreshesIndex(t *testing.T) {
	geofeedPath := configureDN42GeoFeed(t, dn42GeoFeedA)

	session := GetSourceSession("DN42")
	require.NotNil(t, session.Source)
	require.NotNil(t, session.Refresh)
	assertDN42GeoResult(t, session.Source, "China", "Hong Kong", "Hong Kong", "AS65000", "Owner A")

	writeDN42GeoFeed(t, geofeedPath, dn42GeoFeedB)
	assertDN42GeoResult(t, session.Source, "China", "Hong Kong", "Hong Kong", "AS65000", "Owner A")

	session.Refresh()
	assertDN42GeoResult(t, session.Source, "China", "Taiwan", "Taipei", "AS650001", "Owner version B")

	legacySource := GetSource("DN42")
	writeDN42GeoFeed(t, geofeedPath, dn42GeoFeedA)
	assertDN42GeoResult(t, legacySource, "China", "Taiwan", "Taipei", "AS650001", "Owner version B")
	assertDN42GeoResult(t, GetSource("DN42"), "China", "Hong Kong", "Hong Kong", "AS65000", "Owner A")
}

func TestDN42CountryAreaContracts(t *testing.T) {
	configureDN42GeoFeed(t, "192.0.2.1/32,hk,HK,Hong Kong\n"+
		"192.0.2.2/32,tw,TW,Taipei\n"+
		"192.0.2.3/32,mo,MO,Macao\n")
	source := GetSource("DN42")
	tests := []struct {
		ip      string
		country string
		prov    string
	}{
		{ip: "192.0.2.1", country: "China", prov: "Hong Kong"},
		{ip: "192.0.2.2", country: "China", prov: "Taiwan"},
		{ip: "192.0.2.3", country: "China", prov: "Macao"},
		{ip: "192.0.2.4", country: "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			got, err := source(tc.ip, time.Second, "", false)
			require.NoError(t, err)
			assert.Equal(t, tc.country, got.Country)
			assert.Equal(t, tc.prov, got.Prov)
		})
	}
}

func TestDN42SourceSessionFailedRefreshKeepsSnapshot(t *testing.T) {
	geofeedPath := configureDN42GeoFeed(t, dn42GeoFeedA)
	session := GetSourceSessionWithGeoDNS("DN42", "")

	writeDN42GeoFeed(t, geofeedPath, `"unterminated`)
	session.Refresh()
	assertDN42GeoResult(t, session.Source, "China", "Hong Kong", "Hong Kong", "AS65000", "Owner A")

	writeDN42GeoFeed(t, geofeedPath, dn42GeoFeedB)
	session.Refresh()
	assertDN42GeoResult(t, session.Source, "China", "Taiwan", "Taipei", "AS650001", "Owner version B")
}

func TestDN42SourceSessionConcurrentRefresh(t *testing.T) {
	geofeedPath := configureDN42GeoFeed(t, dn42GeoFeedA)
	session := GetSourceSession("DN42")

	const workers = 16
	stop := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := session.Source("192.0.2.8", time.Second, "", false)
				if err != nil {
					errs <- err
					return
				}
				if !isDN42GeoFeedA(got) && !isDN42GeoFeedB(got) {
					errs <- fmt.Errorf("lookup combined different generations: %+v", got)
					return
				}
			}
		}()
	}

	for i := range 40 {
		content := dn42GeoFeedA
		if i%2 == 0 {
			content = dn42GeoFeedB
		}
		writeDN42GeoFeed(t, geofeedPath, content)
		session.Refresh()
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func configureDN42GeoFeed(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	geofeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")
	writeDN42GeoFeed(t, geofeedPath, content)
	require.NoError(t, os.WriteFile(ptrPath, nil, 0o644))
	viper.Set("geoFeedPath", geofeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(viper.Reset)
	return geofeedPath
}

func writeDN42GeoFeed(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func assertDN42GeoResult(
	t *testing.T,
	source Source,
	country string,
	prov string,
	city string,
	asn string,
	owner string,
) {
	t.Helper()
	got, err := source("192.0.2.8", time.Second, "", false)
	require.NoError(t, err)
	assert.Equal(t, country, got.Country)
	assert.Equal(t, prov, got.Prov)
	assert.Equal(t, city, got.City)
	assert.Equal(t, asn, got.Asnumber)
	assert.Equal(t, owner, got.Owner)
}

func isDN42GeoFeedA(got *IPGeoData) bool {
	return got.Country == "China" &&
		got.Prov == "Hong Kong" &&
		got.City == "Hong Kong" &&
		got.Asnumber == "AS65000" &&
		got.Owner == "Owner A"
}

func isDN42GeoFeedB(got *IPGeoData) bool {
	return got.Country == "China" &&
		got.Prov == "Taiwan" &&
		got.City == "Taipei" &&
		got.Asnumber == "AS650001" &&
		got.Owner == "Owner version B"
}

func TestDN42GeoFeedAndPtrIntegration(t *testing.T) {
	dir := t.TempDir()
	geofeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")

	geofeedContent := "192.0.2.0/24,hk,HK,Hong Kong,AS65000,Example Owner\n"
	ptrContent := "HKG,hk,Hong Kong,Hong Kong\n"

	require.NoError(t, os.WriteFile(geofeedPath, []byte(geofeedContent), 0o644))
	require.NoError(t, os.WriteFile(ptrPath, []byte(ptrContent), 0o644))

	viper.Set("geoFeedPath", geofeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(viper.Reset)

	res, err := DN42("192.0.2.8,core.hongkong-1.example", time.Second, "", false)
	require.NoError(t, err)

	assert.Equal(t, "China", res.Country)
	assert.Equal(t, "Hong Kong", res.Prov)
	assert.Equal(t, "Hong Kong", res.City)
	assert.Equal(t, "AS65000", res.Asnumber)
	assert.Equal(t, "Example Owner", res.Owner)
}

func TestDN42PtrFallback(t *testing.T) {
	dir := t.TempDir()
	geofeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")

	// geofeed does not cover the IP, forcing the PTR fallback path
	require.NoError(t, os.WriteFile(geofeedPath, []byte("198.18.0.0/15,us,US,Test,AS65010,Owner\n"), 0o644))
	require.NoError(t, os.WriteFile(ptrPath, []byte("AMS,nl,Noord-Holland,Amsterdam\n"), 0o644))

	viper.Set("geoFeedPath", geofeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(viper.Reset)

	res, err := DN42("198.51.100.25,edge.ams01.provider", time.Second, "", false)
	require.NoError(t, err)

	assert.Equal(t, "Netherlands", res.Country)
	assert.Equal(t, "Noord-Holland", res.Prov)
	assert.Equal(t, "Amsterdam", res.City)
}

func TestDN42UnknownDefaults(t *testing.T) {
	dir := t.TempDir()
	geofeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")

	require.NoError(t, os.WriteFile(geofeedPath, []byte(""), 0o644))
	require.NoError(t, os.WriteFile(ptrPath, []byte(""), 0o644))

	viper.Set("geoFeedPath", geofeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(viper.Reset)

	res, err := DN42("10.0.0.1", time.Second, "", false)
	require.NoError(t, err)

	assert.Equal(t, "Unknown", res.Country)
	assert.Empty(t, res.Prov)
	assert.Empty(t, res.City)
}
