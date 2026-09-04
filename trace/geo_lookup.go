package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

var (
	ErrEmptyGeoQuery = errors.New("empty geo lookup target")
	ErrNilGeoSource  = errors.New("nil geo source")
	ErrNotIPGeoQuery = errors.New("geo lookup target is not an IP address")
)

// LookupIPGeo reuses traceroute's shared GeoIP cache/retry path for direct IP metadata lookups.
func LookupIPGeo(ctx context.Context, source ipgeo.Source, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeo(ctx, ipgeo.SourceSession{Source: source}, lang, maptrace, numMeasurements, query)
}

// LookupIPGeoWithSession reuses a source session for direct IP metadata lookups.
// Sessions with a refresh hook bypass process-wide filtering, caching, and singleflight.
func LookupIPGeoWithSession(ctx context.Context, session ipgeo.SourceSession, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeo(ctx, session, lang, maptrace, numMeasurements, query)
}

func lookupIPGeo(ctx context.Context, session ipgeo.SourceSession, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, ErrEmptyGeoQuery
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if session.Source == nil {
		return nil, ErrNilGeoSource
	}
	if ip := net.ParseIP(query); ip == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotIPGeoQuery, query)
	}
	uncached := session.Refresh != nil
	if !uncached {
		if geo, ok := ipgeo.Filter(query); ok {
			geoCache.Store(query, geo)
			return geo, nil
		}
	}
	return lookupGeoWithRetry(Config{
		Context:            ctx,
		IPGeoSource:        session.Source,
		RefreshIPGeoSource: session.Refresh,
		Lang:               lang,
		Maptrace:           maptrace,
		NumMeasurements:    numMeasurements,
	}, query, query, uncached)
}
