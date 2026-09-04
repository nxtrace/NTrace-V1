package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

var (
	ErrEmptyGeoQuery = errors.New("empty geo lookup target")
	ErrNilGeoSource  = errors.New("nil geo source")
	ErrNotIPGeoQuery = errors.New("geo lookup target is not an IP address")
)

// LookupIPGeo performs a direct IP metadata lookup. A bare Source has no safe
// cross-call identity and therefore bypasses process-wide cache and singleflight.
func LookupIPGeo(ctx context.Context, source ipgeo.Source, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeo(ctx, ipgeo.SourceSession{Source: source}, lang, maptrace, numMeasurements, query)
}

// LookupIPGeoWithDescriptor performs a direct lookup with descriptor-scoped
// caching and request coalescing.
func LookupIPGeoWithDescriptor(ctx context.Context, descriptor ipgeo.SourceDescriptor, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeoSource(
		ctx,
		descriptor.Source,
		func() ipgeo.SourceDescriptor { return descriptor },
		lang,
		maptrace,
		numMeasurements,
		query,
		descriptor.Namespace == ipgeo.SourceNamespaceDN42,
	)
}

// CachedGeoSource adds process-wide caching only when descriptor has a
// canonical namespace. Sources without a namespace retain direct-call
// semantics and never join another source's in-flight lookup.
func CachedGeoSource(descriptor ipgeo.SourceDescriptor) ipgeo.Source {
	if descriptor.Source == nil {
		return nil
	}
	if descriptor.Namespace == "" {
		return descriptor.Source
	}
	return func(query string, timeout time.Duration, language string, maptrace bool) (*ipgeo.IPGeoData, error) {
		return geoCache.lookup(descriptor, query, timeout, language, maptrace)
	}
}

// CachedGeoSourceSession adapts a descriptor session to the legacy session
// surface while reading the current descriptor for every lookup.
func CachedGeoSourceSession(session ipgeo.SourceDescriptorSession) ipgeo.SourceSession {
	if session.Current == nil {
		return ipgeo.SourceSession{Refresh: session.Refresh}
	}
	return ipgeo.SourceSession{
		Source: func(query string, timeout time.Duration, language string, maptrace bool) (*ipgeo.IPGeoData, error) {
			return geoCache.lookup(session.Current(), query, timeout, language, maptrace)
		},
		Refresh: session.Refresh,
	}
}

// LookupIPGeoWithSession reuses a source session for direct IP metadata lookups.
// Legacy sessions do not provide a cache namespace, so their sources bypass
// process-wide caching and singleflight. A refresh hook continues to mark a
// session whose reserved-address filtering must be handled by its source.
func LookupIPGeoWithSession(ctx context.Context, session ipgeo.SourceSession, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeo(ctx, session, lang, maptrace, numMeasurements, query)
}

func lookupIPGeo(ctx context.Context, session ipgeo.SourceSession, lang string, maptrace bool, numMeasurements int, query string) (*ipgeo.IPGeoData, error) {
	return lookupIPGeoSource(ctx, session.Source, nil, lang, maptrace, numMeasurements, query, session.Refresh != nil)
}

func lookupIPGeoSource(
	ctx context.Context,
	source ipgeo.Source,
	descriptor func() ipgeo.SourceDescriptor,
	lang string,
	maptrace bool,
	numMeasurements int,
	query string,
	bypassFilter bool,
) (*ipgeo.IPGeoData, error) {
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
	if source == nil {
		return nil, ErrNilGeoSource
	}
	if ip := net.ParseIP(query); ip == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotIPGeoQuery, query)
	}
	if !bypassFilter {
		if geo, ok := ipgeo.Filter(query); ok {
			return geo, nil
		}
	}
	return lookupGeoWithRetry(Config{
		Context:         ctx,
		IPGeoSource:     source,
		IPGeoDescriptor: descriptor,
		Lang:            lang,
		Maptrace:        maptrace,
		NumMeasurements: numMeasurements,
	}, query, query, bypassFilter)
}
