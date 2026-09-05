package trace

import (
	"container/list"
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

const (
	geoCacheCapacity = 4096
	geoCacheTTL      = 15 * time.Minute
)

type geoCacheKey struct {
	namespace     string
	backend       string
	addr          netip.Addr
	language      string
	maptrace      bool
	dn42Hostname  string
	generation    uint64
	hasGeneration bool
}

type geoCacheEntry struct {
	key       geoCacheKey
	value     *ipgeo.IPGeoData
	expiresAt time.Time
	epoch     uint64
	element   *list.Element
}

type geoCacheRuntime struct {
	mu       sync.Mutex
	entries  sync.Map
	fifo     list.List
	size     int
	epoch    atomic.Uint64
	capacity int
	ttl      time.Duration
	now      func() time.Time
	flights  singleflight.Group
}

var geoCache = newGeoCacheRuntime(geoCacheCapacity, geoCacheTTL, time.Now)

func newGeoCacheRuntime(capacity int, ttl time.Duration, now func() time.Time) *geoCacheRuntime {
	if now == nil {
		now = time.Now
	}
	return &geoCacheRuntime{
		capacity: capacity,
		ttl:      ttl,
		now:      now,
	}
}

// ClearCaches invalidates all process-wide trace caches. In-flight Geo
// lookups from the previous epoch cannot refill the cleared cache.
func ClearCaches() {
	geoCache.clear()
}

func (cache *geoCacheRuntime) clear() {
	cache.mu.Lock()
	cache.epoch.Add(1)
	cache.entries.Clear()
	cache.fifo.Init()
	cache.size = 0
	cache.mu.Unlock()
}

func (cache *geoCacheRuntime) lookup(
	descriptor ipgeo.SourceDescriptor,
	query string,
	timeout time.Duration,
	language string,
	maptrace bool,
) (*ipgeo.IPGeoData, error) {
	return cache.lookupContext(context.Background(), descriptor, query, timeout, language, maptrace)
}

func (cache *geoCacheRuntime) lookupContext(
	ctx context.Context,
	descriptor ipgeo.SourceDescriptor,
	query string,
	timeout time.Duration,
	language string,
	maptrace bool,
) (*ipgeo.IPGeoData, error) {
	if descriptor.Source == nil {
		return nil, ErrNilGeoSource
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	key, cacheable := newGeoCacheKey(descriptor, query, language, maptrace)
	if !cacheable {
		return callGeoSourceWithContext(ctx, timeout, func() (*ipgeo.IPGeoData, error) {
			return descriptor.Source(query, timeout, language, maptrace)
		})
	}
	value, epoch, ok := cache.load(key)
	if ok {
		return value, nil
	}
	flightKey := encodeGeoFlightKey(epoch, key, descriptor, timeout)
	resultCh := cache.flights.DoChan(flightKey, func() (any, error) {
		if cached, ok := cache.loadAtEpoch(key, epoch); ok {
			return cached, nil
		}
		geo, lookupErr := descriptor.Source(key.sourceQuery(), timeout, key.language, maptrace)
		if lookupErr == nil && geo != nil {
			cache.storeAtEpoch(key, geo, epoch)
		}
		return geo, lookupErr
	})
	waitCtx, cancel := geoCacheWaitContext(ctx, timeout)
	defer cancel()
	select {
	case <-waitCtx.Done():
		return nil, waitCtx.Err()
	case result := <-resultCh:
		if result.Err != nil {
			return nil, result.Err
		}
		geo, _ := result.Val.(*ipgeo.IPGeoData)
		return cloneGeoCacheValue(geo), nil
	}
}

func (key geoCacheKey) sourceQuery() string {
	query := key.addr.String()
	if key.namespace == ipgeo.SourceNamespaceDN42 && key.dn42Hostname != "" {
		query += "," + key.dn42Hostname
	}
	return query
}

func geoCacheWaitContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return ctx, func() {}
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func callGeoSourceWithContext(
	ctx context.Context,
	timeout time.Duration,
	lookup func() (*ipgeo.IPGeoData, error),
) (*ipgeo.IPGeoData, error) {
	waitCtx, cancel := geoCacheWaitContext(ctx, timeout)
	defer cancel()
	if waitCtx.Done() == nil {
		return lookup()
	}
	type result struct {
		geo *ipgeo.IPGeoData
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		geo, err := lookup()
		resultCh <- result{geo: geo, err: err}
	}()
	select {
	case <-waitCtx.Done():
		return nil, waitCtx.Err()
	case result := <-resultCh:
		return result.geo, result.err
	}
}

func (cache *geoCacheRuntime) load(key geoCacheKey) (*ipgeo.IPGeoData, uint64, bool) {
	epoch := cache.epoch.Load()
	entryValue, ok := cache.entries.Load(key)
	if !ok {
		return nil, epoch, false
	}
	entry := entryValue.(*geoCacheEntry)
	currentEpoch := cache.epoch.Load()
	if entry.epoch != epoch || currentEpoch != epoch {
		return nil, currentEpoch, false
	}
	if cache.now().Before(entry.expiresAt) {
		if cache.epoch.Load() == epoch {
			return cloneGeoCacheValue(entry.value), epoch, true
		}
		return nil, cache.epoch.Load(), false
	}
	value, ok := cache.expireAndReload(key, epoch)
	return value, epoch, ok
}

func (cache *geoCacheRuntime) loadAtEpoch(key geoCacheKey, epoch uint64) (*ipgeo.IPGeoData, bool) {
	if cache.epoch.Load() != epoch {
		return nil, false
	}
	entryValue, ok := cache.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := entryValue.(*geoCacheEntry)
	if entry.epoch != epoch || cache.epoch.Load() != epoch {
		return nil, false
	}
	if cache.now().Before(entry.expiresAt) {
		return cloneGeoCacheValue(entry.value), cache.epoch.Load() == epoch
	}
	return cache.expireAndReload(key, epoch)
}

func (cache *geoCacheRuntime) expireAndReload(key geoCacheKey, epoch uint64) (*ipgeo.IPGeoData, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.epoch.Load() != epoch {
		return nil, false
	}
	entryValue, ok := cache.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := entryValue.(*geoCacheEntry)
	if entry.epoch != epoch {
		return nil, false
	}
	if !cache.now().Before(entry.expiresAt) {
		cache.deleteLocked(entry)
		return nil, false
	}
	return cloneGeoCacheValue(entry.value), true
}

func (cache *geoCacheRuntime) storeAtEpoch(key geoCacheKey, value *ipgeo.IPGeoData, epoch uint64) bool {
	if value == nil || cache.capacity <= 0 || cache.ttl <= 0 {
		return false
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.epoch.Load() != epoch {
		return false
	}
	if previousValue, ok := cache.entries.Load(key); ok {
		previous := previousValue.(*geoCacheEntry)
		if cache.now().Before(previous.expiresAt) {
			return false
		}
		cache.deleteLocked(previous)
	}
	for cache.size >= cache.capacity {
		oldest := cache.fifo.Front()
		if oldest == nil {
			break
		}
		cache.deleteLocked(oldest.Value.(*geoCacheEntry))
	}
	entry := &geoCacheEntry{
		key:       key,
		value:     cloneGeoCacheValue(value),
		expiresAt: cache.now().Add(cache.ttl),
		epoch:     epoch,
	}
	entry.element = cache.fifo.PushBack(entry)
	cache.entries.Store(key, entry)
	cache.size++
	return true
}

func cloneGeoCacheValue(value *ipgeo.IPGeoData) *ipgeo.IPGeoData {
	if value == nil {
		return nil
	}
	cloned := *value
	if value.Router == nil {
		return &cloned
	}
	cloned.Router = make(map[string][]string, len(value.Router))
	for asn, route := range value.Router {
		if route == nil {
			cloned.Router[asn] = nil
			continue
		}
		clonedRoute := make([]string, len(route))
		copy(clonedRoute, route)
		cloned.Router[asn] = clonedRoute
	}
	return &cloned
}

func (cache *geoCacheRuntime) deleteLocked(entry *geoCacheEntry) {
	if entry == nil {
		return
	}
	current, ok := cache.entries.Load(entry.key)
	if !ok || current != entry {
		return
	}
	cache.entries.Delete(entry.key)
	cache.fifo.Remove(entry.element)
	cache.size--
}

func newGeoCacheKey(
	descriptor ipgeo.SourceDescriptor,
	query string,
	language string,
	maptrace bool,
) (geoCacheKey, bool) {
	if descriptor.Namespace == "" {
		return geoCacheKey{}, false
	}

	ipText := query
	hostname := ""
	if descriptor.Namespace == ipgeo.SourceNamespaceDN42 {
		ipText, hostname, _ = strings.Cut(query, ",")
		hostname = normalizeDN42CacheHostname(hostname)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil {
		return geoCacheKey{}, false
	}
	return geoCacheKey{
		namespace:     descriptor.Namespace,
		backend:       descriptor.Backend,
		addr:          addr.Unmap(),
		language:      normalizeGeoCacheLanguage(language),
		maptrace:      maptrace,
		dn42Hostname:  hostname,
		generation:    descriptor.Generation,
		hasGeneration: descriptor.HasGeneration,
	}, true
}

func normalizeGeoCacheLanguage(language string) string {
	return strings.ToLower(strings.TrimSpace(language))
}

func normalizeDN42CacheHostname(hostname string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
}

func encodeGeoFlightKey(epoch uint64, key geoCacheKey, descriptor ipgeo.SourceDescriptor, timeout time.Duration) string {
	var encoded strings.Builder
	encoded.WriteString(strconv.FormatUint(epoch, 10))
	encoded.WriteByte('|')
	appendGeoFlightKeyPart(&encoded, key.namespace)
	appendGeoFlightKeyPart(&encoded, key.backend)
	appendGeoFlightKeyPart(&encoded, key.addr.String())
	appendGeoFlightKeyPart(&encoded, key.language)
	if key.maptrace {
		encoded.WriteByte('1')
	} else {
		encoded.WriteByte('0')
	}
	appendGeoFlightKeyPart(&encoded, key.dn42Hostname)
	encoded.WriteString(strconv.FormatUint(key.generation, 10))
	encoded.WriteByte('|')
	if key.hasGeneration {
		encoded.WriteByte('1')
	} else {
		encoded.WriteByte('0')
	}
	// Resolver scopes can wait on each other, and a provider's timeout belongs
	// to the leader. Share completed values without joining incompatible work.
	encoded.WriteByte('|')
	appendGeoFlightKeyPart(&encoded, strconv.FormatInt(int64(timeout), 10))
	if descriptor.HasGeoDNSResolver {
		encoded.WriteByte('1')
		appendGeoFlightKeyPart(&encoded, descriptor.GeoDNSResolver)
	} else {
		encoded.WriteByte('0')
	}
	return encoded.String()
}

func appendGeoFlightKeyPart(encoded *strings.Builder, value string) {
	encoded.WriteString(strconv.Itoa(len(value)))
	encoded.WriteByte(':')
	encoded.WriteString(value)
	encoded.WriteByte('|')
}
