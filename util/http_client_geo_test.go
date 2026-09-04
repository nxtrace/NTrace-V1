package util

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewGeoHTTPClient_ReturnsValidClient(t *testing.T) {
	c := NewGeoHTTPClient(3 * time.Second)
	if c == nil {
		t.Fatal("NewGeoHTTPClient returned nil")
	}
	if c.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", c.Timeout)
	}
}

func TestNewGeoHTTPClient_HasCustomTransport(t *testing.T) {
	c := NewGeoHTTPClient(2 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatal("Transport is not *http.Transport or is nil")
	}
	if tr.DialContext == nil {
		t.Error("Transport.DialContext is nil, expected custom function")
	}
}

func TestNewGeoHTTPClient_DifferentTimeouts(t *testing.T) {
	for _, d := range []time.Duration{
		500 * time.Millisecond,
		2 * time.Second,
		10 * time.Second,
	} {
		c := NewGeoHTTPClient(d)
		if c.Timeout != d {
			t.Errorf("NewGeoHTTPClient(%v).Timeout = %v", d, c.Timeout)
		}
	}
}

func TestNewGeoHTTPClientTransportRemainsIsolated(t *testing.T) {
	first := NewGeoHTTPClient(time.Second)
	second := NewGeoHTTPClient(time.Second)
	if first.Transport == second.Transport {
		t.Fatal("NewGeoHTTPClient unexpectedly exposes a shared mutable Transport")
	}
	firstTransport := first.Transport.(*http.Transport)
	secondTransport := second.Transport.(*http.Transport)
	firstTransport.MaxIdleConns = 1
	if secondTransport.MaxIdleConns == 1 {
		t.Fatal("mutating one legacy client Transport affected another client")
	}
}

func TestNewGeoHTTPClientUsesPolicyAtDialTime(t *testing.T) {
	previousPolicy := CurrentGeoDNSPolicy()
	previousOverride := getGeoResolverOverride()
	t.Cleanup(func() {
		setGeoDNSPolicy(previousPolicy)
		setGeoResolverOverride(previousOverride)
	})

	lookupErr := errors.New("blocked test resolver")
	setGeoResolverOverride(&net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, lookupErr
		},
	})
	setGeoDNSPolicy(NewGeoDNSPolicy("cloudflare", false))
	client := NewGeoHTTPClient(time.Second)
	t.Cleanup(client.CloseIdleConnections)

	setGeoDNSPolicy(NewGeoDNSPolicy("", true))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	resp, err := client.Get("http://" + net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("request with policy changed after client creation: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || string(body) != "ok" {
		t.Fatalf("response body = %q, read error = %v, close error = %v, want ok", body, readErr, closeErr)
	}
}

func TestNewSharedGeoHTTPClientSharesTransportByPolicy(t *testing.T) {
	defaultPolicy := NewGeoDNSPolicy("", true)
	first := NewSharedGeoHTTPClientWithPolicy(500*time.Millisecond, defaultPolicy)
	second := NewSharedGeoHTTPClientWithPolicy(10*time.Second, defaultPolicy)
	if first.Transport != second.Transport {
		t.Fatal("default Geo HTTP clients do not share their Transport")
	}
	if first.Timeout != 500*time.Millisecond || second.Timeout != 10*time.Second {
		t.Fatalf("client timeouts = (%s, %s), want per-client values", first.Timeout, second.Timeout)
	}

	google := NewGeoDNSPolicy(" Google ", true)
	googleAgain := NewGeoDNSPolicy("google", true)
	withoutFallback := NewGeoDNSPolicy("google", false)
	googleClient := NewSharedGeoHTTPClientWithPolicy(time.Second, google)
	googleClientAgain := NewSharedGeoHTTPClientWithPolicy(2*time.Second, googleAgain)
	withoutFallbackClient := NewSharedGeoHTTPClientWithPolicy(time.Second, withoutFallback)
	if googleClient.Transport != googleClientAgain.Transport {
		t.Fatal("equivalent normalized policies do not share their Transport")
	}
	if googleClient.Transport == withoutFallbackClient.Transport {
		t.Fatal("policies with different fallback behavior share a Transport")
	}
	if googleClient.Transport == first.Transport {
		t.Fatal("default and non-default policies share a Transport")
	}
}

func TestNewGeoHTTPTransportClonesDefaultTransportSettings(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()

	proxyErr := errors.New("proxy marker")
	base := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, proxyErr
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        73,
		MaxIdleConnsPerHost: 17,
		IdleConnTimeout:     41 * time.Second,
	}
	http.DefaultTransport = base

	transport := newGeoHTTPTransportWithLookup(
		NewGeoDNSPolicy("cloudflare", true),
		func(context.Context, string, GeoDNSPolicy) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	)
	if transport == base {
		t.Fatal("Geo Transport reused the mutable default Transport instead of cloning it")
	}
	if transport.Proxy == nil {
		t.Fatal("Geo Transport dropped the default proxy function")
	}
	if _, err := transport.Proxy(&http.Request{}); !errors.Is(err, proxyErr) {
		t.Fatalf("Geo Transport proxy error = %v, want %v", err, proxyErr)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("Geo Transport TLS config = %#v, want cloned TLS 1.3 config", transport.TLSClientConfig)
	}
	if transport.TLSClientConfig == base.TLSClientConfig {
		t.Fatal("Geo Transport shares the default Transport TLS config pointer")
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("Geo Transport dropped ForceAttemptHTTP2")
	}
	if transport.MaxIdleConns != 73 || transport.MaxIdleConnsPerHost != 17 || transport.IdleConnTimeout != 41*time.Second {
		t.Fatalf(
			"Geo Transport pool settings = (%d, %d, %s), want (73, 17, 41s)",
			transport.MaxIdleConns,
			transport.MaxIdleConnsPerHost,
			transport.IdleConnTimeout,
		)
	}
}

func TestNewGeoHTTPTransportExpandsImplicitIdlePoolForSharedUse(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = &http.Transport{MaxIdleConnsPerHost: 0}

	transport := newGeoHTTPTransport(NewGeoDNSPolicy("", true))
	if transport.MaxIdleConnsPerHost != geoHTTPDefaultMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, geoHTTPDefaultMaxIdleConnsPerHost)
	}
}

func TestGeoHTTPTransportUsesProxyEnvironmentInFreshProcess(t *testing.T) {
	const helperEnv = "NEXTTRACE_GEO_PROXY_HELPER"
	if os.Getenv(helperEnv) == "1" {
		client := NewSharedGeoHTTPClientWithPolicy(time.Second, NewGeoDNSPolicy("", true))
		resp, err := client.Get("http://geo-target.invalid/probe")
		if err != nil {
			t.Fatalf("proxy helper request: %v", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("proxy helper response read=%v close=%v", readErr, closeErr)
		}
		if string(body) != "proxied" {
			t.Fatalf("proxy helper body = %q, want proxied", body)
		}
		return
	}

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "geo-target.invalid" || r.URL.Path != "/probe" {
			t.Errorf("proxy request URL = %s, want http://geo-target.invalid/probe", r.URL.String())
		}
		_, _ = io.WriteString(w, "proxied")
	}))
	defer proxy.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable: %v", err)
	}
	cmd := exec.Command(executable, "-test.run=^TestGeoHTTPTransportUsesProxyEnvironmentInFreshProcess$")
	helperBase := append(os.Environ(), "REQUEST_METHOD=GET")
	cmd.Env = geoProxyHelperEnvironment(helperBase, helperEnv, proxy.URL)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy helper failed: %v\n%s", err, output)
	}
}

func geoProxyHelperEnvironment(base []string, helperEnv, proxyURL string) []string {
	overridden := map[string]string{
		helperEnv:        "1",
		"HTTP_PROXY":     proxyURL,
		"HTTPS_PROXY":    "",
		"ALL_PROXY":      "",
		"NO_PROXY":       "",
		"http_proxy":     "",
		"https_proxy":    "",
		"all_proxy":      "",
		"no_proxy":       "",
		"REQUEST_METHOD": "",
	}
	env := make([]string, 0, len(base)+len(overridden))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, replace := overridden[key]; replace {
				continue
			}
		}
		env = append(env, entry)
	}
	for key, value := range overridden {
		env = append(env, key+"="+value)
	}
	return env
}

func TestNewSharedGeoHTTPClientReusesConnectionsAcrossClientWrappers(t *testing.T) {
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "geo")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	policy := NewGeoDNSPolicy("", true)
	for i := 0; i < 100; i++ {
		client := NewSharedGeoHTTPClientWithPolicy(2*time.Second, policy)
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("read response %d: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response %d: %v", i, err)
		}
	}

	if got := newConnections.Load(); got > 3 {
		t.Fatalf("new connections = %d, want at most 3 for 100 sequential requests", got)
	}
}

func TestNewSharedGeoHTTPClientReusesConnectionsAcrossConcurrentWrappers(t *testing.T) {
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "geo")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	policy := NewGeoDNSPolicy("concurrent-reuse", true)
	clients := make([]*http.Client, 4)
	for i := range clients {
		clients[i] = NewSharedGeoHTTPClientWithPolicy(2*time.Second, policy)
	}
	defer clients[0].CloseIdleConnections()

	for round := 0; round < 100; round++ {
		var wg sync.WaitGroup
		errCh := make(chan error, len(clients))
		for _, client := range clients {
			wg.Go(func() {
				resp, err := client.Get(server.URL)
				if err != nil {
					errCh <- err
					return
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				closeErr := resp.Body.Close()
				if readErr != nil {
					errCh <- readErr
				} else if closeErr != nil {
					errCh <- closeErr
				}
			})
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("round %d: %v", round, err)
		}
	}

	if got := newConnections.Load(); got > 8 {
		t.Fatalf("new connections = %d, want at most 8 for 400 concurrent requests", got)
	}
}

func TestGeoHTTPTransportPoolEvictsOldestAndClosesIdleConnections(t *testing.T) {
	idle := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "geo")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateIdle:
			select {
			case idle <- struct{}{}:
			default:
			}
		case http.StateClosed:
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()

	pool := newGeoHTTPTransportPool(2)
	firstPolicy := NewGeoDNSPolicy("resolver-1", true)
	firstTransport := pool.transportFor(firstPolicy)
	client := &http.Client{Timeout: time.Second, Transport: firstTransport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("warm first Transport: %v", err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("warm first Transport read=%v close=%v", readErr, closeErr)
	}
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("first Transport connection did not become idle")
	}

	_ = pool.transportFor(NewGeoDNSPolicy("resolver-2", true))
	_ = pool.transportFor(NewGeoDNSPolicy("resolver-3", true))

	pool.mu.Lock()
	_, firstStillCached := pool.transports[firstPolicy]
	gotOrder := append([]GeoDNSPolicy(nil), pool.order...)
	pool.mu.Unlock()
	if firstStillCached {
		t.Fatal("oldest Transport remains cached after FIFO eviction")
	}
	wantOrder := []GeoDNSPolicy{
		NewGeoDNSPolicy("resolver-2", true),
		NewGeoDNSPolicy("resolver-3", true),
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("pool order = %#v, want %#v", gotOrder, wantOrder)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("evicted Transport did not close its idle connection")
	}
}

func TestGeoHTTPTransportPoolCoalescesConcurrentMiss(t *testing.T) {
	pool := newGeoHTTPTransportPool(geoHTTPTransportPoolMaxSize)
	policy := NewGeoDNSPolicy("concurrent", true)
	transports := make([]*http.Transport, 32)
	var wg sync.WaitGroup
	for i := range transports {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			transports[index] = pool.transportFor(policy)
		}(i)
	}
	wg.Wait()
	for i := 1; i < len(transports); i++ {
		if transports[i] != transports[0] {
			t.Fatalf("transport %d differs for one concurrent policy", i)
		}
	}
	pool.mu.Lock()
	gotSize := len(pool.transports)
	pool.mu.Unlock()
	if gotSize != 1 {
		t.Fatalf("pool size = %d, want 1", gotSize)
	}
}

func TestDialGeoAddressesPreservesDNSOrder(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("192.0.2.1"),
		net.ParseIP("198.51.100.2"),
	}
	var attempts []string
	clientConn, serverConn := net.Pipe()
	defer func() {
		if err := serverConn.Close(); err != nil {
			t.Errorf("close server connection: %v", err)
		}
	}()
	dial := func(_ context.Context, _ string, addr string) (net.Conn, error) {
		attempts = append(attempts, addr)
		if len(attempts) == len(ips) {
			return clientConn, nil
		}
		return nil, errors.New("unreachable")
	}

	conn, err := dialGeoAddresses(context.Background(), "tcp", "443", ips, dial)
	if err != nil {
		t.Fatalf("dialGeoAddresses() error = %v", err)
	}
	_ = conn.Close()
	want := []string{
		net.JoinHostPort("2001:db8::1", "443"),
		net.JoinHostPort("192.0.2.1", "443"),
		net.JoinHostPort("198.51.100.2", "443"),
	}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("dial attempts = %#v, want DNS order %#v", attempts, want)
	}
}

func TestDialGeoAddressesStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	var attempts atomic.Int32
	go func() {
		_, err := dialGeoAddresses(ctx, "tcp", "443", []net.IP{
			net.ParseIP("192.0.2.1"),
			net.ParseIP("198.51.100.2"),
		}, func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			attempts.Add(1)
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dialGeoAddresses() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial did not stop after context cancellation")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("dial attempts after cancellation = %d, want 1", got)
	}
}

func TestGeoHTTPTransportKeepsURLHostForTLSAndHTTP(t *testing.T) {
	lookedUpHost := make(chan string, 1)
	gotSNI := make(chan string, 1)
	gotHost := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSNI <- r.TLS.ServerName
		gotHost <- r.Host
		_, _ = io.WriteString(w, "geo")
	}))
	server.StartTLS()
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	transport := newGeoHTTPTransportWithLookup(
		NewGeoDNSPolicy("test", false),
		func(_ context.Context, host string, _ GeoDNSPolicy) ([]net.IP, error) {
			lookedUpHost <- host
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	)
	transport.Proxy = nil
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	client := &http.Client{Timeout: time.Second, Transport: transport}
	resp, err := client.Get("https://" + net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatalf("TLS request: %v", err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("TLS response read=%v close=%v", readErr, closeErr)
	}
	if host := <-lookedUpHost; host != "example.com" {
		t.Fatalf("lookup host = %q, want example.com", host)
	}
	if sni := <-gotSNI; sni != "example.com" {
		t.Fatalf("TLS SNI = %q, want example.com", sni)
	}
	if host := <-gotHost; host != net.JoinHostPort("example.com", port) {
		t.Fatalf("HTTP Host = %q, want %q", host, net.JoinHostPort("example.com", port))
	}
}

func TestGeoHTTPClientRequestContextCancelsBodyRead(t *testing.T) {
	requestCanceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
		requestCanceled <- struct{}{}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	client := NewGeoHTTPClientWithPolicy(2*time.Second, NewGeoDNSPolicy("", true))
	resp, err := client.Do(req)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request/body error = %v, want context deadline exceeded", err)
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("server request context was not canceled")
	}
}
