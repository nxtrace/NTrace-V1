//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	qlog "github.com/charmbracelet/log"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	qtransport "github.com/natesales/q/transport"
	"github.com/stretchr/testify/require"
)

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()

	opts := cli.Flags{
		TLSInsecureSkipVerify: true,
		TLSServerName:         "resolver.example",
		TLSMinVersion:         "1.2",
		TLSMaxVersion:         "1.3",
		TLSNextProtos:         []string{"dot"},
		TLSCipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		TLSCurvePreferences:   []string{"X25519", "P256"},
	}
	config, cleanup, err := BuildTLSConfig(opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup()) })
	require.True(t, config.InsecureSkipVerify)
	require.Equal(t, "resolver.example", config.ServerName)
	require.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
	require.Equal(t, []string{"dot"}, config.NextProtos)
	require.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, config.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519, tls.CurveP256}, config.CurvePreferences)
}

func TestBuildTLSConfigRejectsFatalQInputs(t *testing.T) {
	t.Parallel()

	for _, opts := range []cli.Flags{
		{TLSCipherSuites: []string{"NOT_A_CIPHER"}},
		{TLSCurvePreferences: []string{"NOT_A_CURVE"}},
	} {
		_, cleanup, err := BuildTLSConfig(opts)
		require.Error(t, err)
		require.NoError(t, cleanup())
	}
}

func TestBuildTLSConfigKeyLogCleanup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tls.keys")
	config, cleanup, err := BuildTLSConfig(cli.Flags{TLSKeyLogFile: path})
	require.NoError(t, err)
	require.NotNil(t, config.KeyLogWriter)
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		require.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	}
	require.NoError(t, cleanup())
	_, err = config.KeyLogWriter.Write([]byte("closed"))
	require.Error(t, err)
}

func TestNewTransportMapsQFlags(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	base := cli.Flags{
		ReuseConn:        true,
		TCP:              true,
		EDNS:             true,
		UDPBuffer:        1400,
		Timeout:          3 * time.Second,
		HTTPMethod:       http.MethodPost,
		HTTPUserAgent:    "nexttrace-test",
		HTTP2:            true,
		HTTP3:            true,
		PMTUD:            true,
		HTTPHeaders:      []string{"X-Test: one", "X-Test: two", "invalid"},
		QUICALPNTokens:   []string{"doq"},
		QUICLengthPrefix: true,
	}

	plainServer := mustParseServer(t, "1.1.1.1")
	plainTransport, err := NewTransport(plainServer, base, tlsConfig)
	require.NoError(t, err)
	plain := plainTransport.(*qtransport.Plain)
	require.Equal(t, plainServer.Address, plain.Server)
	require.True(t, plain.ReuseConn)
	require.True(t, plain.PreferTCP)
	require.True(t, plain.EDNS)
	require.Equal(t, uint16(1400), plain.UDPBuffer)
	require.Equal(t, 3*time.Second, plain.Timeout)

	tcpServer := mustParseServer(t, "tcp://1.1.1.1")
	tcpTransport, err := NewTransport(tcpServer, cli.Flags{}, tlsConfig)
	require.NoError(t, err)
	require.True(t, tcpTransport.(*qtransport.Plain).PreferTCP)

	tlsServer := mustParseServer(t, "tls://dns.example")
	tlsTransport, err := NewTransport(tlsServer, base, tlsConfig)
	require.NoError(t, err)
	require.Same(t, tlsConfig, tlsTransport.(*qtransport.TLS).TLSConfig)

	httpServer := mustParseServer(t, "https://dns.example/custom")
	httpTransport, err := NewTransport(httpServer, base, tlsConfig)
	require.NoError(t, err)
	httpAdapter := httpTransport.(*scopedHTTPTransport)
	require.Equal(t, http.MethodPost, httpAdapter.inner.Method)
	require.Equal(t, "nexttrace-test", httpAdapter.inner.UserAgent)
	require.True(t, httpAdapter.inner.HTTP2)
	require.True(t, httpAdapter.inner.HTTP3)
	require.False(t, httpAdapter.inner.NoPMTUd)
	require.Equal(t, []string{"one", "two"}, httpAdapter.inner.Headers["X-Test"])

	quicServer := mustParseServer(t, "quic://dns.example")
	quicTransport, err := NewTransport(quicServer, base, tlsConfig)
	require.NoError(t, err)
	quic := quicTransport.(*qtransport.QUIC)
	require.NotSame(t, tlsConfig, quic.TLSConfig)
	require.Equal(t, []string{"doq"}, quic.TLSConfig.NextProtos)
	require.True(t, quic.PMTUD)
	require.True(t, quic.AddLengthPrefix)
}

func TestNewTransportQUICPreservesTLSALPNWithoutOverride(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"custom-doq"},
	}
	quicServer := mustParseServer(t, "quic://dns.example")
	txp, err := NewTransport(quicServer, cli.Flags{}, tlsConfig)
	require.NoError(t, err)
	quic := txp.(*qtransport.QUIC)
	require.NotSame(t, tlsConfig, quic.TLSConfig)
	require.Equal(t, []string{"custom-doq"}, quic.TLSConfig.NextProtos)
}

func TestParseHTTPHeadersValidatesNamesAndValues(t *testing.T) {
	t.Parallel()

	headers, err := parseHTTPHeaders([]string{"X-Test: one", "invalid", "X-Test: two"})
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"X-Test": {"one", "two"}}, headers)

	for _, test := range []struct {
		name    string
		header  string
		wantErr string
	}{
		{name: "empty name", header: ": value", wantErr: `net/http: invalid header field name ""`},
		{name: "space in name", header: "Bad Name: value", wantErr: `net/http: invalid header field name "Bad Name"`},
		{name: "non ASCII name", header: "X-Ü: value", wantErr: `net/http: invalid header field name "X-Ü"`},
		{name: "newline in value", header: "X-Test: one\r\nInjected: value", wantErr: `net/http: invalid header field value for "X-Test"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseHTTPHeaders([]string{test.header})
			require.EqualError(t, err, test.wantErr)
		})
	}
}

func TestParseHTTPHeadersRedactsSensitiveValues(t *testing.T) {
	original := qlog.Default()
	var output bytes.Buffer
	logger := qlog.New(&output)
	logger.SetLevel(qlog.DebugLevel)
	qlog.SetDefault(logger)
	t.Cleanup(func() { qlog.SetDefault(original) })

	_, err := parseHTTPHeaders([]string{
		"Authorization: auth-secret",
		"Proxy-Authorization: proxy-secret",
		"Cookie: cookie-secret",
		"Set-Cookie: set-cookie-secret",
		"API-Key: api-key-secret",
		"X-Goog-API-Key: google-secret",
		"X-Auth-Token: auth-token-secret",
		"X-Access-Token: access-token-secret",
		"X-Test: visible-value",
	})
	require.NoError(t, err)
	logs := output.String()
	for _, secret := range []string{
		"auth-secret",
		"proxy-secret",
		"cookie-secret",
		"set-cookie-secret",
		"api-key-secret",
		"google-secret",
		"auth-token-secret",
		"access-token-secret",
	} {
		require.NotContains(t, logs, secret)
	}
	require.Contains(t, logs, "Added header Authorization")
	require.Contains(t, logs, "Added header X-Test: visible-value")
}

func TestNewTransportODoHAndSafeClose(t *testing.T) {
	t.Parallel()

	server := mustParseServer(t, "https://odoh.example/dns-query")
	txp, err := NewTransport(server, cli.Flags{
		ODoHProxy: "https://proxy.example/proxy",
		ReuseConn: true,
	}, &tls.Config{MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	odoh := txp.(*safeODoHTransport)
	require.Equal(t, "https://proxy.example/proxy", odoh.inner.Proxy)
	require.True(t, odoh.inner.ReuseConn)
	require.NoError(t, txp.Close())
}

func TestSafeODoHTransportClosesAfterPostInitializationError(t *testing.T) {
	t.Parallel()

	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("invalid ODoH configs"))
	}))
	defer target.Close()

	tlsConfig := target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	txp, err := NewTransport(mustParseServer(t, target.URL+"/dns-query"), cli.Flags{
		ODoHProxy: "https://proxy.example/proxy",
		ReuseConn: true,
	}, tlsConfig)
	require.NoError(t, err)

	odoh := txp.(*safeODoHTransport)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	_, err = odoh.Exchange(query)
	require.Error(t, err)
	require.True(t, odoh.exchanged)
	require.NoError(t, odoh.Close())
}

func TestNewTransportDNSCrypt(t *testing.T) {
	t.Parallel()

	const rawStamp = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	stampServer := mustParseServer(t, rawStamp)
	txp, err := NewTransport(stampServer, cli.Flags{
		DNSCryptTCP:     true,
		DNSCryptUDPSize: 1232,
		ReuseConn:       true,
	}, nil)
	require.NoError(t, err)
	dnscryptTransport := txp.(*qtransport.DNSCrypt)
	require.Equal(t, rawStamp, dnscryptTransport.ServerStamp)
	require.True(t, dnscryptTransport.TCP)
	require.Equal(t, 1232, dnscryptTransport.UDPSize)
	require.True(t, dnscryptTransport.ReuseConn)

	parsedStamp, err := dnsstamps.NewServerStampFromString(rawStamp)
	require.NoError(t, err)
	manualServer := mustParseServer(t, "dnscrypt://94.140.14.14:5443")
	txp, err = NewTransport(manualServer, cli.Flags{
		DNSCryptPublicKey: hex.EncodeToString(parsedStamp.ServerPk),
		DNSCryptProvider:  parsedStamp.ProviderName,
	}, nil)
	require.NoError(t, err)
	manual := txp.(*qtransport.DNSCrypt)
	require.NotEmpty(t, manual.ServerStamp)
	createdStamp, err := dnsstamps.NewServerStampFromString(manual.ServerStamp)
	require.NoError(t, err)
	require.Equal(t, dnsstamps.StampProtoTypeDNSCrypt, createdStamp.Proto)
}

func TestNewTransportPrevalidatesFatalPaths(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	tests := []struct {
		name   string
		server ParsedServer
		opts   cli.Flags
		tls    *tls.Config
	}{
		{name: "invalid QUIC address", server: ParsedServer{Address: "missing-port", TransportType: qtransport.TypeQUIC}, tls: tlsConfig},
		{name: "manual DNSCrypt missing key", server: mustParseServer(t, "dnscrypt://1.1.1.1:443"), opts: cli.Flags{}},
		{name: "negative DNSCrypt size", server: mustParseServer(t, "dnscrypt://1.1.1.1:443"), opts: cli.Flags{DNSCryptUDPSize: -1}},
		{name: "non-HTTPS ODoH target", server: mustParseServer(t, "http://dns.example"), opts: cli.Flags{ODoHProxy: "https://proxy.example"}, tls: tlsConfig},
		{name: "invalid ODoH proxy", server: mustParseServer(t, "https://dns.example"), opts: cli.Flags{ODoHProxy: "http://proxy.example"}, tls: tlsConfig},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewTransport(test.server, test.opts, test.tls)
			require.Error(t, err)
		})
	}
}

func TestScopedHTTPTransportRestoresDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	base := original.(*http.Transport)
	originalTLS := base.TLSClientConfig
	sentinelTLS := &tls.Config{ServerName: "original.example"}
	base.TLSClientConfig = sentinelTLS
	t.Cleanup(func() {
		http.DefaultTransport = original
		base.TLSClientConfig = originalTLS
	})

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(writer, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		query := new(dns.Msg)
		wire, err := query.Pack()
		if err != nil {
			t.Errorf("pack DNS response: %v", err)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		if _, err = writer.Write(wire); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	}))
	defer server.Close()

	parsed := mustParseServer(t, server.URL)
	txp, err := NewTransport(parsed, cli.Flags{HTTPMethod: http.MethodGet, ReuseConn: true}, &tls.Config{ServerName: "dns.example"})
	require.NoError(t, err)
	httpAdapter := txp.(*scopedHTTPTransport)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	_, err = txp.Exchange(query)
	require.Error(t, err)
	require.False(t, httpAdapter.initialized)
	require.Same(t, original, http.DefaultTransport)
	require.Same(t, sentinelTLS, base.TLSClientConfig)
	for range 2 {
		_, err = txp.Exchange(query)
		require.NoError(t, err)
		require.True(t, httpAdapter.initialized)
		require.Same(t, original, http.DefaultTransport)
		require.Same(t, sentinelTLS, base.TLSClientConfig)
	}
	require.NoError(t, txp.Close())
}

func mustParseServer(t *testing.T, input string) ParsedServer {
	t.Helper()
	server, err := ParseServer(input)
	require.NoError(t, err)
	return server
}
