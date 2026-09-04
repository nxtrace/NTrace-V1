package trace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

func TestClearCachesRemovesAllEntries(t *testing.T) {
	geoCache.Store("198.51.100.1", &ipgeo.IPGeoData{IP: "198.51.100.1"})
	geoCache.Store("2001:db8::1", &ipgeo.IPGeoData{IP: "2001:db8::1"})

	ClearCaches()

	if _, ok := geoCache.Load("198.51.100.1"); ok {
		t.Fatal("IPv4 cache entry remained after ClearCaches")
	}
	if _, ok := geoCache.Load("2001:db8::1"); ok {
		t.Fatal("IPv6 cache entry remained after ClearCaches")
	}
}

func TestLookupIPGeoCachesResults(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	var calls atomic.Int32
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{
			IP:        ip,
			Asnumber:  "13335",
			CountryEn: "Canada",
			ProvEn:    "Ontario",
			CityEn:    "Toronto",
			Owner:     "Cloudflare, Inc.",
		}, nil
	}

	for i := 0; i < 2; i++ {
		geo, err := LookupIPGeo(context.Background(), source, "en", false, 3, "1.1.1.1")
		if err != nil {
			t.Fatalf("LookupIPGeo() error = %v", err)
		}
		if geo == nil || geo.Asnumber != "13335" {
			t.Fatalf("LookupIPGeo() geo = %+v, want ASN 13335", geo)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("geo source calls = %d, want 1 due to shared cache", got)
	}
}

func TestLookupIPGeoRejectsNonIPTargets(t *testing.T) {
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		t.Fatal("geo source should not be called for non-IP target")
		return nil, nil
	}

	if _, err := LookupIPGeo(context.Background(), source, "en", false, 3, "example.com"); err == nil {
		t.Fatal("LookupIPGeo(non-ip) error = nil, want error")
	} else if !errors.Is(err, ErrNotIPGeoQuery) {
		t.Fatalf("LookupIPGeo(non-ip) error = %v, want ErrNotIPGeoQuery", err)
	}
}

func TestLookupIPGeoHonorsContextCancellationDuringRetry(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	ctx, cancel := context.WithCancel(context.Background())
	sourceEntered := make(chan struct{}, 1)
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		select {
		case sourceEntered <- struct{}{}:
		default:
		}
		time.Sleep(200 * time.Millisecond)
		return nil, context.DeadlineExceeded
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := LookupIPGeo(ctx, source, "en", false, 3, "8.8.8.8")
		done <- err
	}()

	select {
	case <-sourceEntered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for geo lookup attempt to start")
	}
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("LookupIPGeo() error = nil, want cancellation")
		}
		if time.Since(start) >= 150*time.Millisecond {
			t.Fatalf("LookupIPGeo() returned too slowly after cancellation: %v", time.Since(start))
		}
	case <-time.After(time.Second):
		t.Fatal("LookupIPGeo() did not return after cancellation")
	}
}

func TestLookupGeoWithRetryExpiredDeadlineReturnsDeadlineExceeded(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		t.Fatal("geo source should not be called after deadline")
		return nil, nil
	}

	_, err := lookupGeoWithRetry(Config{
		Context:     ctx,
		IPGeoSource: source,
	}, "8.8.8.8", "8.8.8.8", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookupGeoWithRetry() error = %v, want DeadlineExceeded", err)
	}
}

func TestLookupGeoWithRetryClampsLargeOffset(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	var gotTimeout time.Duration
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		gotTimeout = timeout
		return &ipgeo.IPGeoData{IP: ip, Asnumber: "64515"}, nil
	}

	geo, err := lookupGeoWithRetry(Config{
		IPGeoSource:     source,
		GeoLookupOffset: int(^uint(0) >> 1),
		NumMeasurements: 1,
	}, "203.0.113.10", "203.0.113.10", false)
	if err != nil {
		t.Fatalf("lookupGeoWithRetry() error = %v", err)
	}
	if geo == nil || geo.Asnumber != "64515" {
		t.Fatalf("lookupGeoWithRetry() geo = %+v, want ASN 64515", geo)
	}
	if gotTimeout != 6*time.Second {
		t.Fatalf("geo timeout = %s, want 6s", gotTimeout)
	}
}

func TestLookupGeoWithRetryDN42BypassesCache(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	const key = "172.20.0.1,dn42.example"
	stale := &ipgeo.IPGeoData{Asnumber: "STALE"}
	geoCache.Store(key, stale)

	var calls atomic.Int32
	fresh := &ipgeo.IPGeoData{Asnumber: "FRESH"}
	geo, err := lookupGeoWithRetry(Config{
		IPGeoSource: func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
			calls.Add(1)
			return fresh, nil
		},
		NumMeasurements: 1,
	}, key, key, true)
	if err != nil {
		t.Fatalf("lookupGeoWithRetry() error = %v", err)
	}
	if geo != fresh {
		t.Fatalf("lookupGeoWithRetry() geo = %+v, want fresh result", geo)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("DN42 source calls = %d, want 1", got)
	}
	if cached, ok := geoCache.Load(key); !ok || cached != stale {
		t.Fatalf("DN42 lookup changed shared cache: got %#v, want original stale entry", cached)
	}
}

func TestLookupGeoWithRetryDN42BypassesSingleflight(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	var calls atomic.Int32
	cfg := Config{
		IPGeoSource: func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
			calls.Add(1)
			started <- struct{}{}
			<-release
			return &ipgeo.IPGeoData{Asnumber: "DN42"}, nil
		},
		NumMeasurements: 1,
	}

	errCh := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := lookupGeoWithRetry(cfg, "172.20.0.2", "172.20.0.2", true)
			errCh <- err
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("DN42 source call %d did not start independently", i+1)
		}
	}
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("lookupGeoWithRetry() error = %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("concurrent DN42 source calls = %d, want 2", got)
	}
}

func TestLookupGeoWithRetryDN42HonorsContextCancellation(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	done := make(chan error, 1)
	go func() {
		_, err := lookupGeoWithRetry(Config{
			Context: ctx,
			IPGeoSource: func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
				close(started)
				<-release
				return &ipgeo.IPGeoData{Asnumber: "DN42"}, nil
			},
			NumMeasurements: 1,
		}, "172.20.0.3", "172.20.0.3", true)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DN42 source lookup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookupGeoWithRetry() error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("DN42 lookup did not return after context cancellation")
	}
}

func TestLookupIPGeoWithSessionBypassesFilterAndCacheWithoutRefreshing(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	const query = "10.23.0.1"
	geoCache.Store(query, &ipgeo.IPGeoData{Asnumber: "STALE"})

	var state atomic.Int32
	state.Store(1)
	var sourceCalls atomic.Int32
	var refreshCalls atomic.Int32
	session := ipgeo.SourceSession{
		Source: func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
			sourceCalls.Add(1)
			if state.Load() == 1 {
				return &ipgeo.IPGeoData{IP: ip, Asnumber: "OLD"}, nil
			}
			return &ipgeo.IPGeoData{IP: ip, Asnumber: "NEW"}, nil
		},
		Refresh: func() { refreshCalls.Add(1) },
	}

	first, err := LookupIPGeoWithSession(context.Background(), session, "en", false, 1, query)
	if err != nil {
		t.Fatalf("first LookupIPGeoWithSession() error = %v", err)
	}
	state.Store(2)
	second, err := LookupIPGeoWithSession(context.Background(), session, "en", false, 1, query)
	if err != nil {
		t.Fatalf("second LookupIPGeoWithSession() error = %v", err)
	}

	if first.Asnumber != "OLD" || second.Asnumber != "NEW" {
		t.Fatalf("session results = %q then %q, want OLD then NEW", first.Asnumber, second.Asnumber)
	}
	if got := sourceCalls.Load(); got != 2 {
		t.Fatalf("session source calls = %d, want 2", got)
	}
	if got := refreshCalls.Load(); got != 0 {
		t.Fatalf("LookupIPGeoWithSession invoked Refresh %d times, want 0", got)
	}
	if cached, ok := geoCache.Load(query); !ok || cached.(*ipgeo.IPGeoData).Asnumber != "STALE" {
		t.Fatalf("session lookup changed shared cache: %#v", cached)
	}
}
