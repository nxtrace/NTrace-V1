//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	qlog "github.com/charmbracelet/log"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	qtransport "github.com/natesales/q/transport"
	qtls "github.com/natesales/q/util/tls"
	"golang.org/x/net/http/httpguts"
)

var (
	// q v0.19.12's TLS helpers terminate the process for unknown names. Keep
	// this allowlist in sync with util/tls before upgrading q so invalid CLI
	// input can be returned as an ordinary error instead.
	qCipherSuites = map[string]struct{}{
		"TLS_RSA_WITH_RC4_128_SHA":                      {},
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 {},
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  {},
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  {},
		"TLS_RSA_WITH_AES_128_CBC_SHA256":               {},
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               {},
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               {},
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              {},
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          {},
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          {},
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                {},
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           {},
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            {},
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            {},
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       {},
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         {},
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         {},
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       {},
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         {},
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       {},
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   {},
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": {},
		"TLS_AES_128_GCM_SHA256":                        {},
		"TLS_AES_256_GCM_SHA384":                        {},
		"TLS_CHACHA20_POLY1305_SHA256":                  {},
	}
	qCurves = map[string]struct{}{
		"P256": {}, "P384": {}, "P521": {}, "X25519": {},
	}

	httpDefaultTransportMu sync.Mutex
)

// BuildTLSConfig creates the TLS configuration expected by q transports. The
// returned cleanup closes the optional TLS key-log file and is always non-nil.
func BuildTLSConfig(opts cli.Flags) (*tls.Config, func() error, error) {
	cleanup := func() error { return nil }
	if err := validateTLSNames(opts.TLSCipherSuites, opts.TLSCurvePreferences); err != nil {
		return nil, cleanup, err
	}

	config := &tls.Config{
		InsecureSkipVerify: opts.TLSInsecureSkipVerify, //nolint:gosec // Explicit q-compatible CLI option.
		ServerName:         opts.TLSServerName,
		MinVersion:         qtls.Version(opts.TLSMinVersion, tls.VersionTLS10),
		MaxVersion:         qtls.Version(opts.TLSMaxVersion, tls.VersionTLS13),
		NextProtos:         append([]string(nil), opts.TLSNextProtos...),
		CipherSuites:       qtls.ParseCipherSuites(opts.TLSCipherSuites),
		CurvePreferences:   qtls.ParseCurves(opts.TLSCurvePreferences),
	}

	if opts.TLSClientCertificate != "" {
		certificate, err := tls.LoadX509KeyPair(opts.TLSClientCertificate, opts.TLSClientKey)
		if err != nil {
			return nil, cleanup, fmt.Errorf("load TLS client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}

	if opts.TLSKeyLogFile != "" {
		qlog.Warnf("TLS secret logging enabled")
		keyLog, err := os.OpenFile(opts.TLSKeyLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return nil, cleanup, fmt.Errorf("open TLS key log: %w", err)
		}
		config.KeyLogWriter = keyLog
		cleanup = keyLog.Close
	}

	return config, cleanup, nil
}

func validateTLSNames(cipherSuites, curves []string) error {
	for _, name := range cipherSuites {
		if _, ok := qCipherSuites[name]; !ok {
			return fmt.Errorf("unknown TLS cipher suite %q", name)
		}
	}
	for _, name := range curves {
		if _, ok := qCurves[name]; !ok {
			return fmt.Errorf("unknown TLS curve %q", name)
		}
	}
	return nil
}

// NewTransport creates a q public transport from a normalized server and q
// flags. Inputs known to trigger log.Fatal inside q are rejected where they
// can be validated without performing the query itself.
func NewTransport(server ParsedServer, opts cli.Flags, tlsConfig *tls.Config) (qtransport.Transport, error) {
	if err := validateTransportServer(server); err != nil {
		return nil, err
	}

	common := qtransport.Common{Server: server.Address, ReuseConn: opts.ReuseConn}
	switch server.TransportType {
	case qtransport.TypePlain:
		qlog.Debugf("Using UDP with TCP fallback: %s", server.Address)
		return &qtransport.Plain{
			Common:    common,
			PreferTCP: opts.TCP,
			EDNS:      opts.EDNS,
			UDPBuffer: opts.UDPBuffer,
			Timeout:   opts.Timeout,
		}, nil
	case qtransport.TypeTCP:
		qlog.Debugf("Using TCP transport: %s", server.Address)
		return &qtransport.Plain{
			Common:    common,
			PreferTCP: true,
			EDNS:      opts.EDNS,
			UDPBuffer: opts.UDPBuffer,
			Timeout:   opts.Timeout,
		}, nil
	case qtransport.TypeTLS:
		if tlsConfig == nil {
			return nil, fmt.Errorf("TLS transport requires a TLS configuration")
		}
		qlog.Debugf("Using TLS transport: %s", server.Address)
		return &qtransport.TLS{Common: common, TLSConfig: tlsConfig}, nil
	case qtransport.TypeHTTP:
		if tlsConfig == nil {
			return nil, fmt.Errorf("HTTP transport requires a TLS configuration")
		}
		if opts.ODoHProxy != "" {
			if server.Scheme != "https" {
				return nil, fmt.Errorf("ODoH target must use HTTPS")
			}
			if err := validateHTTPSURL(opts.ODoHProxy, "ODoH proxy"); err != nil {
				return nil, err
			}
			qlog.Debugf("Using ODoH transport with target %s proxy %s", server.Address, opts.ODoHProxy)
			return &safeODoHTransport{inner: &qtransport.ODoH{
				Common:    common,
				Proxy:     opts.ODoHProxy,
				TLSConfig: tlsConfig,
			}}, nil
		}
		qlog.Debugf("Using HTTP(s) transport: %s", server.Address)
		headers, err := parseHTTPHeaders(opts.HTTPHeaders)
		if err != nil {
			return nil, err
		}
		return &scopedHTTPTransport{inner: &qtransport.HTTP{
			Common:    common,
			TLSConfig: tlsConfig,
			UserAgent: opts.HTTPUserAgent,
			Method:    opts.HTTPMethod,
			HTTP2:     opts.HTTP2,
			HTTP3:     opts.HTTP3,
			NoPMTUd:   !opts.PMTUD,
			Headers:   headers,
		}}, nil
	case qtransport.TypeQUIC:
		if tlsConfig == nil {
			return nil, fmt.Errorf("QUIC transport requires a TLS configuration")
		}
		quicTLS := tlsConfig.Clone()
		quicTLS.NextProtos = append([]string(nil), opts.QUICALPNTokens...)
		qlog.Debugf("Using QUIC transport: %s", server.Address)
		return &qtransport.QUIC{
			Common:          common,
			TLSConfig:       quicTLS,
			PMTUD:           opts.PMTUD,
			AddLengthPrefix: opts.QUICLengthPrefix,
		}, nil
	case qtransport.TypeDNSCrypt:
		qlog.Debugf("Using DNSCrypt transport: %s", server.Address)
		if server.FromStamp {
			qlog.Debug("Using provided DNS stamp for DNSCrypt")
		} else {
			qlog.Debug("Using manual DNSCrypt configuration")
		}
		return newDNSCryptTransport(common, server, opts)
	default:
		return nil, fmt.Errorf("unknown DNS transport %q", server.TransportType)
	}
}

func validateTransportServer(server ParsedServer) error {
	if server.Address == "" {
		return fmt.Errorf("DNS transport server is empty")
	}
	if server.TransportType == qtransport.TypeDNSCrypt {
		if strings.HasPrefix(server.Address, "sdns://") {
			stamp, err := dnsstamps.NewServerStampFromString(server.Address)
			if err != nil {
				return fmt.Errorf("parse DNSCrypt stamp: %w", err)
			}
			if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
				return fmt.Errorf("DNSCrypt transport requires a DNSCrypt stamp")
			}
		}
		return nil
	}
	if server.TransportType == qtransport.TypeHTTP {
		u, err := url.Parse(server.Address)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Port() == "" {
			return fmt.Errorf("invalid HTTP DNS server %q", server.Address)
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(server.Address); err != nil {
		return fmt.Errorf("invalid %s DNS server %q: %w", server.TransportType, server.Address, err)
	}
	return nil
}

func validateHTTPSURL(rawURL, label string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse %s: %w", label, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("%s must be an HTTPS URL with a host", label)
	}
	return nil
}

func parseHTTPHeaders(values []string) (map[string][]string, error) {
	headers := make(map[string][]string)
	for _, value := range values {
		name, fieldValue, found := strings.Cut(value, ":")
		if !found {
			qlog.Warnf("Invalid header format: %s (expected 'Name: Value')", value)
			continue
		}
		name = strings.TrimSpace(name)
		fieldValue = strings.TrimSpace(fieldValue)
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("net/http: invalid header field name %q", name)
		}
		if !httpguts.ValidHeaderFieldValue(fieldValue) {
			return nil, fmt.Errorf("net/http: invalid header field value for %q", name)
		}
		headers[name] = append(headers[name], fieldValue)
		qlog.Debugf("Added header %s: %s", name, fieldValue)
	}
	return headers, nil
}

func newDNSCryptTransport(common qtransport.Common, server ParsedServer, opts cli.Flags) (qtransport.Transport, error) {
	if opts.DNSCryptUDPSize < 0 {
		return nil, fmt.Errorf("DNSCrypt UDP size must not be negative")
	}
	stamp := server.Address
	if !strings.HasPrefix(stamp, "sdns://") {
		if opts.DNSCryptPublicKey == "" || opts.DNSCryptProvider == "" {
			return nil, fmt.Errorf("manual DNSCrypt configuration requires a public key and provider name")
		}
		parsedStamp, err := dnsstamps.NewDNSCryptServerStampFromLegacy(
			server.Address,
			opts.DNSCryptPublicKey,
			opts.DNSCryptProvider,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("create DNSCrypt stamp: %w", err)
		}
		stamp = parsedStamp.String()
		qlog.Debugf("Created DNS stamp from manual DNSCrypt configuration: %s", stamp)
	}
	return &qtransport.DNSCrypt{
		Common:      common,
		ServerStamp: stamp,
		TCP:         opts.DNSCryptTCP,
		UDPSize:     opts.DNSCryptUDPSize,
	}, nil
}

// q's HTTP transport mutates http.DefaultTransport while constructing its
// client. DNS mode is exclusive, but the adapter still restores that global
// after each construction so later NextTrace modes do not inherit the change.
type scopedHTTPTransport struct {
	mu          sync.Mutex
	inner       *qtransport.HTTP
	initialized bool
}

func (t *scopedHTTPTransport) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.inner.ReuseConn && t.initialized {
		return t.inner.Exchange(msg)
	}

	httpDefaultTransportMu.Lock()
	defer httpDefaultTransportMu.Unlock()

	original := http.DefaultTransport
	base, ok := original.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("q HTTP transport requires http.DefaultTransport to be *http.Transport")
	}
	http.DefaultTransport = base.Clone()
	defer func() { http.DefaultTransport = original }()

	reply, err := t.inner.Exchange(msg)
	if err == nil {
		t.initialized = true
	}
	return reply, err
}

func (t *scopedHTTPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inner.Close()
}

// q's ODoH Close assumes Exchange initialized its client. NewTransport
// prevalidates the target and proxy URLs, after which q initializes the client
// before every recoverable Exchange error. Delegate Close after Exchange
// returns so failed requests do not leak idle connections.
type safeODoHTransport struct {
	mu        sync.Mutex
	inner     *qtransport.ODoH
	exchanged bool
}

func (t *safeODoHTransport) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reply, err := t.inner.Exchange(msg)
	t.exchanged = true
	return reply, err
}

func (t *safeODoHTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.exchanged {
		return nil
	}
	return t.inner.Close()
}

var (
	_ qtransport.Transport = (*scopedHTTPTransport)(nil)
	_ qtransport.Transport = (*safeODoHTransport)(nil)
)
