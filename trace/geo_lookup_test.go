package trace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

func TestClearCachesRemovesAllEntries(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(ip string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: ip}, nil
	})
	if _, err := LookupIPGeoWithDescriptor(context.Background(), descriptor, "en", false, 1, "8.8.8.8"); err != nil {
		t.Fatalf("initial LookupIPGeoWithDescriptor() error = %v", err)
	}

	ClearCaches()

	if _, err := LookupIPGeoWithDescriptor(context.Background(), descriptor, "en", false, 1, "8.8.8.8"); err != nil {
		t.Fatalf("post-clear LookupIPGeoWithDescriptor() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want 2 after ClearCaches", got)
	}
}

func TestLookupIPGeoBareSourceBypassesProcessCache(t *testing.T) {
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

	if got := calls.Load(); got != 2 {
		t.Fatalf("geo source calls = %d, want 2 for unnamespaced source", got)
	}
}

func TestLookupIPGeoWithDescriptorCachesResults(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(ip string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: ip, Asnumber: "13335"}, nil
	})
	for range 2 {
		geo, err := LookupIPGeoWithDescriptor(context.Background(), descriptor, "en", false, 1, "1.1.1.1")
		if err != nil {
			t.Fatalf("LookupIPGeoWithDescriptor() error = %v", err)
		}
		if geo == nil || geo.Asnumber != "13335" {
			t.Fatalf("LookupIPGeoWithDescriptor() geo = %+v, want ASN 13335", geo)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("geo source calls = %d, want 1 due to descriptor cache", got)
	}
}

func TestLookupIPGeoWithDescriptorDN42BypassesFilterAndCaches(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	var calls atomic.Int32
	descriptor := ipgeo.SourceDescriptor{
		Source: func(ip string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
			calls.Add(1)
			return &ipgeo.IPGeoData{IP: ip, Asnumber: "4242420001"}, nil
		},
		Namespace:     ipgeo.SourceNamespaceDN42,
		Backend:       ipgeo.SourceBackendDN42GeoFeed,
		Generation:    1,
		HasGeneration: true,
	}
	for range 2 {
		geo, err := LookupIPGeoWithDescriptor(context.Background(), descriptor, "en", false, 1, "10.23.0.1")
		if err != nil {
			t.Fatalf("LookupIPGeoWithDescriptor() error = %v", err)
		}
		if geo == nil || geo.Asnumber != "4242420001" {
			t.Fatalf("LookupIPGeoWithDescriptor() geo = %+v, want DN42 result", geo)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("DN42 source calls = %d, want 1", got)
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

func TestLookupIPGeoHonorsContextCancellationDuringSourceCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		release := make(chan struct{})
		sourceDone := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := LookupIPGeo(ctx, func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
				close(started)
				<-release
				close(sourceDone)
				return &ipgeo.IPGeoData{}, nil
			}, "en", false, 1, "8.8.8.8")
			done <- err
		}()

		<-started
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("LookupIPGeo() error = %v, want context.Canceled", err)
		}
		select {
		case <-sourceDone:
			t.Fatal("blocked source finished before release")
		default:
		}
		close(release)
		synctest.Wait()
		<-sourceDone
	})
}

func TestLookupIPGeoWithDescriptorHonorsContextCancellation(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		release := make(chan struct{})
		sourceDone := make(chan struct{})
		done := make(chan error, 1)
		descriptor := geoCacheTestDescriptor(func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
			close(started)
			<-release
			close(sourceDone)
			return &ipgeo.IPGeoData{}, nil
		})
		go func() {
			_, err := LookupIPGeoWithDescriptor(ctx, descriptor, "en", false, 1, "8.8.8.8")
			done <- err
		}()

		<-started
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("LookupIPGeoWithDescriptor() error = %v, want context.Canceled", err)
		}
		select {
		case <-sourceDone:
			t.Fatal("blocked descriptor source finished before release")
		default:
		}
		close(release)
		synctest.Wait()
		<-sourceDone
	})
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
	var calls atomic.Int32
	fresh := &ipgeo.IPGeoData{Asnumber: "FRESH"}
	source := func(ip string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return fresh, nil
	}
	config := Config{
		IPGeoSource:     source,
		NumMeasurements: 1,
	}
	for range 2 {
		geo, err := lookupGeoWithRetry(config, key, key, true)
		if err != nil {
			t.Fatalf("lookupGeoWithRetry() error = %v", err)
		}
		if geo != fresh {
			t.Fatalf("lookupGeoWithRetry() geo = %+v, want fresh result", geo)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("DN42 source calls = %d, want 2 for bare source", got)
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

func TestLookupGeoWithRetryDN42ReturnsCancellationAfterSourceFinishes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ClearCaches()
		t.Cleanup(ClearCaches)

		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

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

		<-started
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("lookupGeoWithRetry() returned %v before the source finished", err)
		default:
		}

		releaseOnce.Do(func() { close(release) })
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("lookupGeoWithRetry() error = %v, want context.Canceled", err)
		}
	})
}

func TestLookupGeoSourceDirectWithContextDoesNotAllocate(t *testing.T) {
	ctx := context.Background()
	want := &ipgeo.IPGeoData{Asnumber: "DN42"}
	allocs := testing.AllocsPerRun(1000, func() {
		got, err := lookupGeoSourceDirectWithContext(ctx, func() (any, error) {
			return want, nil
		})
		if err != nil || got != want {
			panic("unexpected direct geo lookup result")
		}
	})
	if allocs != 0 {
		t.Fatalf("lookupGeoSourceDirectWithContext() allocations = %v, want 0", allocs)
	}
}

func TestLookupIPGeoWithSessionBypassesFilterAndCacheWithoutRefreshing(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	const query = "10.23.0.1"

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
}
