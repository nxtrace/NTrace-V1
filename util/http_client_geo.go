package util

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const geoHTTPTransportPoolMaxSize = 32

var (
	defaultGeoHTTPPolicy    = NewGeoDNSPolicy("", true)
	defaultGeoHTTPTransport = sync.OnceValue(func() *http.Transport {
		return newGeoHTTPTransport(defaultGeoHTTPPolicy)
	})
	sharedGeoHTTPTransports = newGeoHTTPTransportPool(geoHTTPTransportPoolMaxSize)
)

type geoHTTPTransportPool struct {
	mu         sync.Mutex
	maxSize    int
	transports map[GeoDNSPolicy]*http.Transport
	order      []GeoDNSPolicy
}

type geoHostLookupFunc func(context.Context, string, GeoDNSPolicy) ([]net.IP, error)
type geoDialContextFunc func(context.Context, string, string) (net.Conn, error)

func newGeoHTTPTransportPool(maxSize int) *geoHTTPTransportPool {
	if maxSize < 1 {
		maxSize = 1
	}
	return &geoHTTPTransportPool{
		maxSize:    maxSize,
		transports: make(map[GeoDNSPolicy]*http.Transport),
	}
}

func (p *geoHTTPTransportPool) transportFor(policy GeoDNSPolicy) *http.Transport {
	policy = NewGeoDNSPolicy(policy.Resolver(), policy.Fallback())
	p.mu.Lock()
	if transport := p.transports[policy]; transport != nil {
		p.mu.Unlock()
		return transport
	}

	transport := newGeoHTTPTransport(policy)
	p.transports[policy] = transport
	p.order = append(p.order, policy)
	var evicted *http.Transport
	if len(p.order) > p.maxSize {
		oldest := p.order[0]
		copy(p.order, p.order[1:])
		p.order[len(p.order)-1] = GeoDNSPolicy{}
		p.order = p.order[:len(p.order)-1]
		evicted = p.transports[oldest]
		delete(p.transports, oldest)
	}
	p.mu.Unlock()

	if evicted != nil {
		evicted.CloseIdleConnections()
	}
	return transport
}

// NewGeoHTTPClient returns an independently configurable client whose Transport
// captures the current Geo DNS policy.
func NewGeoHTTPClient(timeout time.Duration) *http.Client {
	return NewGeoHTTPClientWithPolicy(timeout, CurrentGeoDNSPolicy())
}

// NewGeoHTTPClientWithPolicy returns an independently configurable client for policy.
func NewGeoHTTPClientWithPolicy(timeout time.Duration, policy GeoDNSPolicy) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: newGeoHTTPTransport(policy),
	}
}

// NewSharedGeoHTTPClient returns a client backed by the shared immutable
// Transport for the current Geo DNS policy.
func NewSharedGeoHTTPClient(timeout time.Duration) *http.Client {
	return NewSharedGeoHTTPClientWithPolicy(timeout, CurrentGeoDNSPolicy())
}

// NewSharedGeoHTTPClientWithPolicy returns a client backed by the shared
// immutable Transport for policy. Callers must not mutate Client.Transport.
func NewSharedGeoHTTPClientWithPolicy(timeout time.Duration, policy GeoDNSPolicy) *http.Client {
	policy = NewGeoDNSPolicy(policy.Resolver(), policy.Fallback())
	var transport *http.Transport
	if policy == defaultGeoHTTPPolicy {
		transport = defaultGeoHTTPTransport()
	} else {
		transport = sharedGeoHTTPTransports.transportFor(policy)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func newGeoHTTPTransport(policy GeoDNSPolicy) *http.Transport {
	return newGeoHTTPTransportWithLookup(policy, LookupHostForGeoWithPolicy)
}

func newGeoHTTPTransportWithLookup(policy GeoDNSPolicy, lookup geoHostLookupFunc) *http.Transport {
	transport := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		transport = base.Clone()
	}

	policy = NewGeoDNSPolicy(policy.Resolver(), policy.Fallback())
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		ips, err := lookup(ctx, host, policy)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("geo DNS returned no IPs for host %q", host)
		}
		return dialGeoAddresses(ctx, network, port, ips, dialer.DialContext)
	}
	return transport
}

func dialGeoAddresses(ctx context.Context, network, port string, ips []net.IP, dial geoDialContextFunc) (net.Conn, error) {
	var lastErr error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, lastErr
}
