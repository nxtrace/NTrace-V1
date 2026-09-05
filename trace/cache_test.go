package trace

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/util"
)

type fakeGeoCacheClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeGeoCacheClock) current() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeGeoCacheClock) advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

func TestGeoCacheDefaults(t *testing.T) {
	if geoCacheCapacity != 4096 {
		t.Fatalf("geo cache capacity = %d, want 4096", geoCacheCapacity)
	}
	if geoCacheTTL != 15*time.Minute {
		t.Fatalf("geo cache TTL = %s, want 15m", geoCacheTTL)
	}
}

func TestGeoCacheRuntimeDefaultCapacityEvictsFirstEntry(t *testing.T) {
	cache := newGeoCacheRuntime(geoCacheCapacity, time.Hour, time.Now)
	descriptor := geoCacheTestDescriptor(nil)
	data := &ipgeo.IPGeoData{Asnumber: "64512"}
	firstKey := benchmarkGeoCacheKey(0)
	for i := range geoCacheCapacity + 1 {
		key := benchmarkGeoCacheKey(uint32(i))
		if !cache.storeAtEpoch(key, data, 0) {
			t.Fatalf("store %d failed", i)
		}
	}
	if cache.size != geoCacheCapacity {
		t.Fatalf("cache size = %d, want %d", cache.size, geoCacheCapacity)
	}
	if _, _, ok := cache.load(firstKey); ok {
		t.Fatal("first entry remained after default-capacity FIFO eviction")
	}
	lastKey := mustGeoCacheKey(t, descriptor, "0.0.16.0")
	if _, _, ok := cache.load(lastKey); !ok {
		t.Fatal("newest entry missing after default-capacity FIFO eviction")
	}
}

func TestGeoCacheKeyIncludesAllResultDimensions(t *testing.T) {
	descriptor := ipgeo.SourceDescriptor{
		Namespace:     ipgeo.SourceNamespaceIPSB,
		Backend:       ipgeo.SourceNamespaceIPSB,
		Generation:    7,
		HasGeneration: true,
	}
	base, ok := newGeoCacheKey(descriptor, "192.0.2.1", " EN ", false)
	if !ok {
		t.Fatal("newGeoCacheKey() rejected valid descriptor")
	}
	mapped, ok := newGeoCacheKey(descriptor, "::ffff:192.0.2.1", "en", false)
	if !ok || mapped != base {
		t.Fatalf("mapped IPv4 key = (%+v, %v), want %+v", mapped, ok, base)
	}
	ipv6Expanded, ok := newGeoCacheKey(descriptor, "2001:0db8:0000:0000:0000:0000:0000:0001", "en", false)
	if !ok {
		t.Fatal("newGeoCacheKey() rejected expanded IPv6")
	}
	ipv6Compressed, ok := newGeoCacheKey(descriptor, "2001:db8::1", "en", false)
	if !ok || ipv6Compressed != ipv6Expanded {
		t.Fatalf("equivalent IPv6 keys = (%+v, %+v, %v), want equal", ipv6Expanded, ipv6Compressed, ok)
	}

	tests := []struct {
		name       string
		descriptor ipgeo.SourceDescriptor
		language   string
		maptrace   bool
	}{
		{name: "namespace", descriptor: withGeoCacheDescriptorNamespace(descriptor, ipgeo.SourceNamespaceIPInfo), language: "en"},
		{name: "backend", descriptor: withGeoCacheDescriptorBackend(descriptor, "other"), language: "en"},
		{name: "language", descriptor: descriptor, language: "cn"},
		{name: "maptrace", descriptor: descriptor, language: "en", maptrace: true},
		{name: "generation", descriptor: withGeoCacheDescriptorGeneration(descriptor, 8, true), language: "en"},
		{name: "generation-presence", descriptor: withGeoCacheDescriptorGeneration(descriptor, 7, false), language: "en"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := newGeoCacheKey(test.descriptor, "192.0.2.1", test.language, test.maptrace)
			if !valid || got == base {
				t.Fatalf("newGeoCacheKey() = (%+v, %v), want key distinct from %+v", got, valid, base)
			}
		})
	}

	dn42Descriptor := ipgeo.SourceDescriptor{
		Namespace:     ipgeo.SourceNamespaceDN42,
		Backend:       ipgeo.SourceBackendDN42GeoFeed,
		Generation:    7,
		HasGeneration: true,
	}
	dn42A, ok := newGeoCacheKey(dn42Descriptor, "172.20.0.1,router-a.dn42", "en", false)
	if !ok {
		t.Fatal("newGeoCacheKey() rejected DN42 query")
	}
	dn42Equivalent, ok := newGeoCacheKey(dn42Descriptor, "172.20.0.1, ROUTER-A.DN42. ", "en", false)
	if !ok || dn42Equivalent != dn42A {
		t.Fatalf("equivalent DN42 hostname key = (%+v, %v), want %+v", dn42Equivalent, ok, dn42A)
	}
	dn42B, ok := newGeoCacheKey(dn42Descriptor, "172.20.0.1,router-b.dn42", "en", false)
	if !ok || dn42A == dn42B {
		t.Fatalf("DN42 hostname keys = (%+v, %+v, %v), want distinct", dn42A, dn42B, ok)
	}
}

func TestGeoCacheKeyUsesCanonicalProviderAliasAndBackend(t *testing.T) {
	cache := newGeoCacheRuntime(4, time.Hour, time.Now)
	var aliasCalls atomic.Int32
	aliasSource := func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		aliasCalls.Add(1)
		return &ipgeo.IPGeoData{IP: query}, nil
	}
	ipAPICom := ipgeo.GetSourceDescriptor("IPAPI.COM")
	ipDashAPICom := ipgeo.GetSourceDescriptor("ip-api.com")
	ipAPICom.Source = aliasSource
	ipDashAPICom.Source = aliasSource
	aliasKey, ok := newGeoCacheKey(ipAPICom, "1.1.1.1", "en", false)
	if !ok {
		t.Fatal("newGeoCacheKey() rejected IPAPI.COM descriptor")
	}
	canonicalKey, ok := newGeoCacheKey(ipDashAPICom, "1.1.1.1", "en", false)
	if !ok || canonicalKey != aliasKey {
		t.Fatalf("provider alias keys = (%+v, %+v, %v), want equal", aliasKey, canonicalKey, ok)
	}
	mustGeoCacheLookup(t, cache, ipAPICom, "1.1.1.1")
	mustGeoCacheLookup(t, cache, ipDashAPICom, "1.1.1.1")
	if got := aliasCalls.Load(); got != 1 {
		t.Fatalf("provider alias source calls = %d, want 1", got)
	}

	var backendCalls atomic.Int32
	backendSource := func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		return &ipgeo.IPGeoData{IP: query, Asnumber: strconv.Itoa(int(backendCalls.Add(1)))}, nil
	}
	v3 := ipgeo.SourceDescriptor{
		Source:    backendSource,
		Namespace: ipgeo.SourceNamespaceNextTraceAPI,
		Backend:   ipgeo.SourceBackendNextTraceAPIV3,
	}
	v4 := v3
	v4.Backend = ipgeo.SourceBackendNextTraceAPIV4
	v3Key, ok := newGeoCacheKey(v3, "1.1.1.1", "en", false)
	if !ok {
		t.Fatal("newGeoCacheKey() rejected NextTrace v3 descriptor")
	}
	v4Key, ok := newGeoCacheKey(v4, "1.1.1.1", "en", false)
	if !ok || v4Key == v3Key {
		t.Fatalf("NextTrace backend keys = (%+v, %+v, %v), want distinct", v3Key, v4Key, ok)
	}
	v3Geo := mustGeoCacheLookup(t, cache, v3, "1.1.1.1")
	v4Geo := mustGeoCacheLookup(t, cache, v4, "1.1.1.1")
	if backendCalls.Load() != 2 || v3Geo.Asnumber == v4Geo.Asnumber {
		t.Fatalf("backend results = (%+v, %+v), calls %d; want distinct lookups", v3Geo, v4Geo, backendCalls.Load())
	}
}

func TestGeoCacheRuntimeCanonicalizesDN42SourceInputs(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	var gotQuery string
	var gotLanguage string
	var calls atomic.Int32
	descriptor := ipgeo.SourceDescriptor{
		Source: func(query string, _ time.Duration, language string, _ bool) (*ipgeo.IPGeoData, error) {
			calls.Add(1)
			gotQuery = query
			gotLanguage = language
			return &ipgeo.IPGeoData{IP: query}, nil
		},
		Namespace:     ipgeo.SourceNamespaceDN42,
		Backend:       ipgeo.SourceBackendDN42GeoFeed,
		Generation:    1,
		HasGeneration: true,
	}
	first, err := cache.lookup(descriptor, "::ffff:172.20.0.1, ROUTER.DN42. ", time.Second, " CN ", false)
	if err != nil {
		t.Fatalf("cache lookup error = %v", err)
	}
	if gotQuery != "172.20.0.1,router.dn42" || gotLanguage != "cn" {
		t.Fatalf("source inputs = (%q, %q), want canonical DN42 query and language", gotQuery, gotLanguage)
	}
	second, err := cache.lookup(descriptor, "172.20.0.1,router.dn42", time.Second, "cn", false)
	if err != nil {
		t.Fatalf("equivalent cache lookup error = %v", err)
	}
	if first.IP != "172.20.0.1,router.dn42" || second.IP != first.IP {
		t.Fatalf("lookup IPs = (%q, %q), want identical canonical query", first.IP, second.IP)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want equivalent inputs to share one key", got)
	}
}

func TestGeoCacheRuntimeCanonicalizesSourceAddress(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: query}, nil
	})

	first := mustGeoCacheLookup(t, cache, descriptor, "::ffff:192.0.2.1")
	second := mustGeoCacheLookup(t, cache, descriptor, "192.0.2.1")
	if first.IP != "192.0.2.1" || second.IP != first.IP {
		t.Fatalf("lookup IPs = (%q, %q), want identical canonical address", first.IP, second.IP)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want mapped and canonical addresses to share one lookup", got)
	}
}

func TestGeoCacheRuntimeAbsoluteTTL(t *testing.T) {
	clock := &fakeGeoCacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newGeoCacheRuntime(2, 15*time.Minute, clock.current)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: query}, nil
	})

	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	clock.advance(14 * time.Minute)
	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	clock.advance(time.Minute)
	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want 2 after absolute TTL expiry", got)
	}
}

func TestGeoCacheRuntimeFIFOHitDoesNotPromote(t *testing.T) {
	clock := &fakeGeoCacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newGeoCacheRuntime(2, time.Hour, clock.current)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: query}, nil
	})

	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	mustGeoCacheLookup(t, cache, descriptor, "8.8.8.8")
	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	mustGeoCacheLookup(t, cache, descriptor, "9.9.9.9")
	mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	if got := calls.Load(); got != 4 {
		t.Fatalf("source calls = %d, want 4 when hit does not promote FIFO entry", got)
	}
}

func TestGeoCacheRuntimeDuplicateStoreDoesNotRefreshTTLOrFIFO(t *testing.T) {
	clock := &fakeGeoCacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newGeoCacheRuntime(2, 15*time.Minute, clock.current)
	descriptor := geoCacheTestDescriptor(nil)
	keyA := mustGeoCacheKey(t, descriptor, "1.1.1.1")
	keyB := mustGeoCacheKey(t, descriptor, "8.8.8.8")
	keyC := mustGeoCacheKey(t, descriptor, "9.9.9.9")
	old := &ipgeo.IPGeoData{Asnumber: "OLD"}
	newValue := &ipgeo.IPGeoData{Asnumber: "NEW"}
	if !cache.storeAtEpoch(keyA, old, 0) || !cache.storeAtEpoch(keyB, old, 0) {
		t.Fatal("initial cache store failed")
	}
	clock.advance(14 * time.Minute)
	if cache.storeAtEpoch(keyA, newValue, 0) {
		t.Fatal("duplicate store replaced a live entry")
	}
	if !cache.storeAtEpoch(keyC, old, 0) {
		t.Fatal("third cache store failed")
	}
	if _, _, ok := cache.load(keyA); ok {
		t.Fatal("duplicate store promoted the oldest FIFO entry")
	}
}

func TestGeoCacheRuntimeDuplicateStoreDoesNotRenewAbsoluteTTL(t *testing.T) {
	clock := &fakeGeoCacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newGeoCacheRuntime(1, 15*time.Minute, clock.current)
	key := mustGeoCacheKey(t, geoCacheTestDescriptor(nil), "1.1.1.1")
	if !cache.storeAtEpoch(key, &ipgeo.IPGeoData{Asnumber: "OLD"}, 0) {
		t.Fatal("initial cache store failed")
	}
	clock.advance(14 * time.Minute)
	if cache.storeAtEpoch(key, &ipgeo.IPGeoData{Asnumber: "NEW"}, 0) {
		t.Fatal("duplicate store replaced a live entry")
	}
	clock.advance(time.Minute)
	if _, _, ok := cache.load(key); ok {
		t.Fatal("duplicate store renewed absolute TTL")
	}
}

func TestGeoCacheRuntimeDoesNotCacheErrorOrNil(t *testing.T) {
	wantErr := errors.New("lookup failed")
	for _, test := range []struct {
		name  string
		first func() (*ipgeo.IPGeoData, error)
	}{
		{name: "error", first: func() (*ipgeo.IPGeoData, error) { return nil, wantErr }},
		{name: "nil", first: func() (*ipgeo.IPGeoData, error) { return nil, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := newGeoCacheRuntime(2, time.Hour, time.Now)
			var calls atomic.Int32
			descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
				if calls.Add(1) == 1 {
					return test.first()
				}
				return &ipgeo.IPGeoData{IP: query}, nil
			})

			_, _ = cache.lookup(descriptor, "1.1.1.1", time.Second, "en", false)
			mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
			if got := calls.Load(); got != 2 {
				t.Fatalf("source calls = %d, want 2", got)
			}
		})
	}
}

func TestGeoCacheRuntimeReturnsIndependentCopies(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{
			IP:       query,
			Asnumber: "64512",
			Router:   map[string][]string{"64512": {"64513", "64514"}},
		}, nil
	})

	first := mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	first.Asnumber = "MUTATED"
	first.Router["64512"][0] = "MUTATED"
	first.Router["other"] = []string{"MUTATED"}

	second := mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	if first == second {
		t.Fatal("cache hit returned the first caller's pointer")
	}
	if second.Asnumber != "64512" {
		t.Fatalf("cached scalar = %q, want 64512", second.Asnumber)
	}
	if got := second.Router["64512"]; len(got) != 2 || got[0] != "64513" || got[1] != "64514" {
		t.Fatalf("cached router = %#v, want independent original route", second.Router)
	}
	if _, ok := second.Router["other"]; ok {
		t.Fatalf("cached router inherited caller mutation: %#v", second.Router)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}
}

func TestGeoCacheRuntimeEmptyNamespaceBypassesCacheAndSingleflight(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	descriptor := ipgeo.SourceDescriptor{Source: func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return &ipgeo.IPGeoData{IP: query}, nil
	}}

	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := cache.lookup(descriptor, "1.1.1.1", time.Second, "en", false)
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("unnamespaced source calls joined singleflight")
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("lookup error = %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want 2", got)
	}
}

func TestGeoCacheRuntimeCoalesces32ConcurrentLookups(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return &ipgeo.IPGeoData{
			IP:     query,
			Router: map[string][]string{"64512": {"64513"}},
		}, nil
	})

	const concurrency = 32
	ready := make(chan struct{}, concurrency)
	begin := make(chan struct{})
	type lookupResult struct {
		geo *ipgeo.IPGeoData
		err error
	}
	done := make(chan lookupResult, concurrency)
	for range concurrency {
		go func() {
			ready <- struct{}{}
			<-begin
			geo, err := cache.lookup(descriptor, "1.1.1.1", time.Second, "en", false)
			done <- lookupResult{geo: geo, err: err}
		}()
	}
	for range concurrency {
		<-ready
	}
	close(begin)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("source lookup did not start")
	}
	close(release)
	results := make([]*ipgeo.IPGeoData, 0, concurrency)
	seen := make(map[*ipgeo.IPGeoData]struct{}, concurrency)
	for range concurrency {
		result := <-done
		if result.err != nil {
			t.Fatalf("concurrent lookup error = %v", result.err)
		}
		if result.geo == nil {
			t.Fatal("concurrent lookup result = nil")
		}
		if _, ok := seen[result.geo]; ok {
			t.Fatal("concurrent singleflight waiters shared an IPGeoData pointer")
		}
		seen[result.geo] = struct{}{}
		results = append(results, result.geo)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1 for 32 concurrent lookups", got)
	}
	results[0].Router["64512"][0] = "MUTATED"
	results[0].Router["other"] = []string{"MUTATED"}
	for i, geo := range results[1:] {
		if got := geo.Router["64512"]; len(got) != 1 || got[0] != "64513" {
			t.Fatalf("waiter %d router = %#v, want independent route", i+1, geo.Router)
		}
		if _, ok := geo.Router["other"]; ok {
			t.Fatalf("waiter %d router inherited map mutation: %#v", i+1, geo.Router)
		}
	}
}

func TestGeoCacheRuntimeClearIsEpochBarrier(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	started := make(chan int32, 2)
	releaseOld := make(chan struct{})
	releaseNew := make(chan struct{})
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		call := calls.Add(1)
		started <- call
		if call == 1 {
			<-releaseOld
		} else {
			<-releaseNew
		}
		return &ipgeo.IPGeoData{IP: query, Asnumber: strconv.Itoa(int(call))}, nil
	})

	oldDone := make(chan *ipgeo.IPGeoData, 1)
	go func() {
		geo, _ := cache.lookup(descriptor, "1.1.1.1", time.Second, "en", false)
		oldDone <- geo
	}()
	if call := <-started; call != 1 {
		t.Fatalf("first source call = %d, want 1", call)
	}

	cache.clear()
	newDone := make(chan *ipgeo.IPGeoData, 1)
	go func() {
		geo, _ := cache.lookup(descriptor, "1.1.1.1", time.Second, "en", false)
		newDone <- geo
	}()
	select {
	case call := <-started:
		if call != 2 {
			t.Fatalf("post-clear source call = %d, want 2", call)
		}
	case <-time.After(time.Second):
		t.Fatal("post-clear lookup joined pre-clear flight")
	}

	close(releaseNew)
	if geo := <-newDone; geo == nil || geo.Asnumber != "2" {
		t.Fatalf("post-clear result = %+v, want call 2", geo)
	}
	close(releaseOld)
	if geo := <-oldDone; geo == nil || geo.Asnumber != "1" {
		t.Fatalf("pre-clear result = %+v, want call 1", geo)
	}
	geo := mustGeoCacheLookup(t, cache, descriptor, "1.1.1.1")
	if geo.Asnumber != "2" {
		t.Fatalf("cached result after old flight completed = %+v, want call 2", geo)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want 2", got)
	}
}

func TestGeoCacheRuntimeFollowerUsesOwnDeadline(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	descriptor := ipgeo.GetSourceDescriptorWithGeoDNS("disable-geoip", " GOOGLE ")
	descriptor.Source = func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return &ipgeo.IPGeoData{IP: query}, nil
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.lookupContext(context.Background(), descriptor, "1.1.1.1", time.Hour, "en", false)
		firstDone <- err
	}()
	<-started

	followerCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := cache.lookupContext(followerCtx, descriptor, "1.1.1.1", time.Hour, "en", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follower error = %v, want context.DeadlineExceeded", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want follower to join one flight", got)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first lookup error = %v", err)
	}
}

func TestGeoCacheRuntimeFollowerUsesOwnProviderTimeout(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	started := make(chan struct{})
	release := make(chan struct{})
	const shortTimeout = 20 * time.Millisecond
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(query string, timeout time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		if timeout == shortTimeout {
			close(started)
			<-release
			return nil, context.DeadlineExceeded
		}
		return &ipgeo.IPGeoData{IP: query}, nil
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.lookup(descriptor, "1.1.1.1", shortTimeout, "en", false)
		firstDone <- err
	}()
	<-started

	geo, err := cache.lookup(descriptor, "1.1.1.1", 100*time.Millisecond, "en", false)
	close(release)
	if firstErr := <-firstDone; !errors.Is(firstErr, context.DeadlineExceeded) {
		t.Fatalf("short lookup error = %v, want context.DeadlineExceeded", firstErr)
	}
	if err != nil || geo == nil || geo.IP != "1.1.1.1" {
		t.Fatalf("long lookup = (%+v, %v), want its independent provider timeout", geo, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls = %d, want separate flights for different provider timeouts", got)
	}
	if _, err := cache.lookup(descriptor, "1.1.1.1", shortTimeout, "en", false); err != nil || calls.Load() != 2 {
		t.Fatalf("completed value was not shared across timeouts: error %v, calls %d", err, calls.Load())
	}
}

func TestGeoCacheRuntimeDoesNotJoinBlockedDNSResolverScope(t *testing.T) {
	tests := []struct {
		name      string
		outer     string
		other     string
		unwrapped bool
	}{
		{name: "different-resolvers", outer: "google", other: "cloudflare"},
		{name: "explicit-system-resolver", outer: "google", other: ""},
		{name: "system-resolver-outer-scope", outer: "", other: "cloudflare"},
		{name: "unwrapped-source", outer: "google", other: "", unwrapped: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache := newGeoCacheRuntime(2, time.Hour, time.Now)
			first := ipgeo.GetSourceDescriptorWithGeoDNS("disable-geoip", tc.outer)
			if tc.unwrapped {
				first = ipgeo.GetSourceDescriptor("disable-geoip")
			}
			second := ipgeo.GetSourceDescriptorWithGeoDNS("disable-geoip", tc.other)
			entered := make(chan struct{})
			finished := make(chan struct{})
			secondSource := second.Source
			second.Source = func(query string, timeout time.Duration, lang string, maptrace bool) (*ipgeo.IPGeoData, error) {
				defer close(finished)
				close(entered)
				return secondSource(query, timeout, lang, maptrace)
			}
			secondDone := make(chan error, 1)
			const timeout = 100 * time.Millisecond
			_, firstErr := util.WithGeoDNSResolver(tc.outer, func() (*ipgeo.IPGeoData, error) {
				go func() {
					_, err := cache.lookup(second, "1.1.1.1", timeout, "en", false)
					secondDone <- err
				}()
				<-entered
				return cache.lookup(first, "1.1.1.1", timeout, "en", false)
			})
			secondErr := <-secondDone
			<-finished
			if firstErr != nil {
				t.Fatalf("lookup holding its DNS scope joined a blocked flight: %v", firstErr)
			}
			if secondErr != nil {
				t.Fatalf("lookup did not resume after the other DNS scope exited: %v", secondErr)
			}
			second.Source = func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
				t.Error("completed value was not shared across DNS scopes")
				return nil, errors.New("unexpected source call")
			}
			if _, err := cache.lookup(second, "1.1.1.1", timeout, "en", false); err != nil {
				t.Fatalf("shared completed value lookup failed: %v", err)
			}
		})
	}
}

func TestGeoCacheRuntimeHitDoesNotStartSource(t *testing.T) {
	cache := newGeoCacheRuntime(2, time.Hour, time.Now)
	var calls atomic.Int32
	descriptor := geoCacheTestDescriptor(func(string, time.Duration, string, bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return nil, errors.New("source must not run")
	})
	key := mustGeoCacheKey(t, descriptor, "1.1.1.1")
	if !cache.storeAtEpoch(key, &ipgeo.IPGeoData{IP: "1.1.1.1"}, 0) {
		t.Fatal("cache seed failed")
	}
	geo, err := cache.lookupContext(t.Context(), descriptor, "1.1.1.1", time.Second, "en", false)
	if err != nil || geo == nil || geo.IP != "1.1.1.1" {
		t.Fatalf("cache hit = (%+v, %v), want seeded value", geo, err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("source calls = %d, want 0 on cache hit", got)
	}
}

func TestCachedGeoSourceSessionReadsCurrentDescriptor(t *testing.T) {
	ClearCaches()
	t.Cleanup(ClearCaches)

	var generation atomic.Uint64
	generation.Store(1)
	var calls atomic.Int32
	source := func(query string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
		calls.Add(1)
		return &ipgeo.IPGeoData{IP: query, Asnumber: strconv.FormatUint(generation.Load(), 10)}, nil
	}
	session := CachedGeoSourceSession(ipgeo.SourceDescriptorSession{
		Current: func() ipgeo.SourceDescriptor {
			return ipgeo.SourceDescriptor{
				Source:        source,
				Namespace:     ipgeo.SourceNamespaceDN42,
				Backend:       ipgeo.SourceBackendDN42GeoFeed,
				Generation:    generation.Load(),
				HasGeneration: true,
			}
		},
		Refresh: func() { generation.Add(1) },
	})

	first, err := session.Source("172.20.0.1,router.dn42", time.Second, "en", false)
	if err != nil {
		t.Fatalf("first lookup error = %v", err)
	}
	session.Refresh()
	second, err := session.Source("172.20.0.1,router.dn42", time.Second, "en", false)
	if err != nil {
		t.Fatalf("second lookup error = %v", err)
	}
	if first.Asnumber != "1" || second.Asnumber != "2" || calls.Load() != 2 {
		t.Fatalf("session results = (%+v, %+v), calls %d; want generations 1 and 2", first, second, calls.Load())
	}
}

func geoCacheTestDescriptor(source ipgeo.Source) ipgeo.SourceDescriptor {
	return ipgeo.SourceDescriptor{
		Source:    source,
		Namespace: ipgeo.SourceNamespaceIPSB,
		Backend:   ipgeo.SourceNamespaceIPSB,
	}
}

func withGeoCacheDescriptorNamespace(descriptor ipgeo.SourceDescriptor, namespace string) ipgeo.SourceDescriptor {
	descriptor.Namespace = namespace
	return descriptor
}

func withGeoCacheDescriptorBackend(descriptor ipgeo.SourceDescriptor, backend string) ipgeo.SourceDescriptor {
	descriptor.Backend = backend
	return descriptor
}

func withGeoCacheDescriptorGeneration(descriptor ipgeo.SourceDescriptor, generation uint64, present bool) ipgeo.SourceDescriptor {
	descriptor.Generation = generation
	descriptor.HasGeneration = present
	return descriptor
}

func mustGeoCacheLookup(t *testing.T, cache *geoCacheRuntime, descriptor ipgeo.SourceDescriptor, query string) *ipgeo.IPGeoData {
	t.Helper()
	geo, err := cache.lookup(descriptor, query, time.Second, "en", false)
	if err != nil {
		t.Fatalf("cache lookup error = %v", err)
	}
	if geo == nil {
		t.Fatal("cache lookup result = nil")
	}
	return geo
}

func mustGeoCacheKey(t testing.TB, descriptor ipgeo.SourceDescriptor, query string) geoCacheKey {
	t.Helper()
	key, ok := newGeoCacheKey(descriptor, query, "en", false)
	if !ok {
		t.Fatalf("newGeoCacheKey(%q) rejected valid query", query)
	}
	return key
}
