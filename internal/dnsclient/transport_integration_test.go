//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	dnscryptlib "github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	"github.com/quic-go/quic-go"
	"github.com/sthorne/odoh-go"
	"github.com/stretchr/testify/require"
)

const dnsCryptSmokeHelperEnv = "NEXTTRACE_DNSCRYPT_SMOKE_HELPER"

func TestQPublicTransportAgainstLocalDoT(t *testing.T) {
	certificate := testTLSCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go serveOneDoT(listener)

	server := mustParseServer(t, "tls://"+listener.Addr().String())
	txp, err := NewTransport(server, cli.Flags{}, insecureTestTLSConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = txp.Close() })
	reply, err := txp.Exchange(testDNSQuery())
	assertTestDNSReply(t, reply, err)
}

func TestQPublicTransportAgainstLocalDoH(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		wire, err := base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		reply := testDNSReply(query)
		response, err := reply.Pack()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	}))
	t.Cleanup(server.Close)

	parsed := mustParseServer(t, server.URL+"/dns-query")
	txp, err := NewTransport(parsed, cli.Flags{HTTPMethod: http.MethodGet, ReuseConn: true}, insecureTestTLSConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = txp.Close() })
	reply, err := txp.Exchange(testDNSQuery())
	assertTestDNSReply(t, reply, err)
}

func TestQPublicTransportAgainstLocalDoQ(t *testing.T) {
	certificate := testTLSCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go serveOneDoQ(listener)

	server := mustParseServer(t, "quic://"+listener.Addr().String())
	txp, err := NewTransport(server, cli.Flags{
		QUICALPNTokens:   []string{"doq"},
		QUICLengthPrefix: true,
	}, insecureTestTLSConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = txp.Close() })
	reply, err := txp.Exchange(testDNSQuery())
	assertTestDNSReply(t, reply, err)
}

func TestQPublicTransportAgainstLocalODoH(t *testing.T) {
	keyPair, err := odoh.CreateDefaultKeyPair()
	require.NoError(t, err)
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{keyPair.Config}).Marshal()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/odohconfigs":
			_, _ = writer.Write(configs)
		case "/proxy":
			serveODoHProxyResponse(writer, request, keyPair)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	parsed := mustParseServer(t, server.URL+"/dns-query")
	txp, err := NewTransport(parsed, cli.Flags{
		ODoHProxy: server.URL + "/proxy",
		ReuseConn: true,
	}, insecureTestTLSConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = txp.Close() })
	reply, err := txp.Exchange(testDNSQuery())
	assertTestDNSReply(t, reply, err)
}

func TestRunODoHTimeoutDoesNotCloseDuringExchange(t *testing.T) {
	isolateRunEnvironment(t)
	keyPair, err := odoh.CreateDefaultKeyPair()
	require.NoError(t, err)
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{keyPair.Config}).Marshal()
	proxyStarted := make(chan struct{}, 1)
	releaseProxy := make(chan struct{})

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/odohconfigs":
			_, _ = writer.Write(configs)
		case "/proxy":
			select {
			case proxyStarted <- struct{}{}:
			default:
			}
			<-releaseProxy
			serveODoHProxyResponse(writer, request, keyPair)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	type runResult struct {
		code   int
		stderr string
	}
	result := make(chan runResult, 1)
	start := time.Now()
	go func() {
		var stderr bytes.Buffer
		code := Run(context.Background(), []string{
			"--server=" + server.URL + "/dns-query",
			"--odoh-proxy=" + server.URL + "/proxy",
			"--tls-insecure-skip-verify",
			"--qname=example.com",
			"--type=A",
			"--timeout=1s",
		}, io.Discard, &stderr)
		result <- runResult{code: code, stderr: stderr.String()}
	}()

	select {
	case <-proxyStarted:
	case <-time.After(2 * time.Second):
		close(releaseProxy)
		t.Fatal("ODoH exchange did not reach the proxy")
	}
	select {
	case got := <-result:
		if got.code != 1 || !strings.Contains(got.stderr, "timeout after 1s") {
			close(releaseProxy)
			t.Fatalf("code/stderr = %d/%q", got.code, got.stderr)
		}
	case <-time.After(2 * time.Second):
		close(releaseProxy)
		t.Fatal("Run did not honor the overall timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		close(releaseProxy)
		t.Fatalf("timeout returned after %s", elapsed)
	}

	close(releaseProxy)
	// Run has returned, but the exclusive DNS scope remains held until the
	// in-flight q transport finishes and closes in sequence.
	dnsClientGlobalMu.Lock()
	dnsClientGlobalMu.Unlock()
}

func TestQPublicTransportAgainstLocalDNSCrypt(t *testing.T) {
	if os.Getenv(dnsCryptSmokeHelperEnv) == "1" {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{
			"@" + os.Getenv("NEXTTRACE_DNSCRYPT_SMOKE_STAMP"),
			"example.com",
			"A",
			"--format=raw",
		}, &stdout, &stderr)
		if code != 0 || !strings.Contains(stdout.String(), "192.0.2.10") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		return
	}

	stamp := startTestDNSCryptServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQPublicTransportAgainstLocalDNSCrypt$")
	command.Env = append(os.Environ(),
		dnsCryptSmokeHelperEnv+"=1",
		"NEXTTRACE_DNSCRYPT_SMOKE_STAMP="+stamp,
		"HOME="+t.TempDir(),
		"NO_COLOR=1",
		"SSLKEYLOGFILE=",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("DNSCrypt helper timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("DNSCrypt helper failed: %v, output=%q", err, output)
	}
}

func serveODoHProxyResponse(writer http.ResponseWriter, request *http.Request, keyPair odoh.ObliviousDoHKeyPair) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	encryptedQuery, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	queryBody, responseContext, err := keyPair.DecryptQuery(encryptedQuery)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	query := new(dns.Msg)
	if err := query.Unpack(queryBody.DnsMessage); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	replyWire, err := testDNSReply(query).Pack()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	encryptedResponse, err := responseContext.EncryptResponse(odoh.CreateObliviousDNSResponse(replyWire, 0))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/oblivious-dns-message")
	_, _ = writer.Write(encryptedResponse.Marshal())
}

type testDNSCryptHandler struct{}

func (testDNSCryptHandler) ServeDNS(writer dnscryptlib.ResponseWriter, request *dns.Msg) error {
	return writer.WriteMsg(testDNSReply(request))
}

func startTestDNSCryptServer(t *testing.T) string {
	t.Helper()
	resolverConfig, err := dnscryptlib.GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	resolverCertificate, err := resolverConfig.CreateCert()
	require.NoError(t, err)
	server := &dnscryptlib.Server{
		ProviderName: resolverConfig.ProviderName,
		ResolverCert: resolverCertificate,
		Handler:      testDNSCryptHandler{},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	go func() { _ = server.ServeUDP(connection) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = connection.Close()
	})
	stamp, err := resolverConfig.CreateStamp(connection.LocalAddr().String())
	require.NoError(t, err)
	return stamp.String()
}

func serveOneDoT(listener net.Listener) {
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	dnsConnection := &dns.Conn{Conn: connection}
	query, err := dnsConnection.ReadMsg()
	if err != nil {
		return
	}
	_ = dnsConnection.WriteMsg(testDNSReply(query))
}

func serveOneDoQ(listener *quic.Listener) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := listener.Accept(ctx)
	if err != nil {
		return
	}
	stream, err := connection.AcceptStream(ctx)
	if err != nil {
		return
	}
	wire, err := io.ReadAll(stream)
	if err != nil || len(wire) < 2 || int(binary.BigEndian.Uint16(wire[:2])) != len(wire)-2 {
		stream.CancelRead(1)
		return
	}
	query := new(dns.Msg)
	if err := query.Unpack(wire[2:]); err != nil {
		stream.CancelRead(1)
		return
	}
	replyWire, err := testDNSReply(query).Pack()
	if err != nil {
		return
	}
	response := make([]byte, len(replyWire)+2)
	binary.BigEndian.PutUint16(response[:2], uint16(len(replyWire)))
	copy(response[2:], replyWire)
	_, _ = stream.Write(response)
	_ = stream.Close()
}

func testDNSQuery() *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	return query
}

func testDNSReply(query *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.10"),
	}}
	return reply
}

func assertTestDNSReply(t *testing.T, reply *dns.Msg, err error) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, reply)
	require.Len(t, reply.Answer, 1)
	require.Equal(t, "192.0.2.10", reply.Answer[0].(*dns.A).A.String())
}

func insecureTestTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // Local test server.
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	require.NoError(t, err)
	return certificate
}
