//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/sthorne/odoh-go"
)

const testCommandTimeout = 5 * time.Second

var (
	jsonTimePattern    = regexp.MustCompile(`"time":[0-9]+`)
	yamlTimePattern    = regexp.MustCompile(`(?m)^(\s*)time:.*$`)
	fatalPrefixPattern = regexp.MustCompile(
		`(?m)^(?:(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} )?FATA |dns mode error: )`,
	)
	usageCommandPattern  = regexp.MustCompile(`(?m)^  .* \[OPTIONS\] \[@server\] \[type\.\.\.\] \[name\]$`)
	prettyTimePattern    = regexp.MustCompile(`(?m)^;; Time .*$`)
	prettyFromPattern    = regexp.MustCompile(`(?m)^(;; From .* in ).*$`)
	serverWarningPattern = regexp.MustCompile(
		`(?m)^(?:WARN Server |dns mode warning: skipping server ).*$`,
	)
	quicReceiveBufferWarningPattern = regexp.MustCompile(
		`(?m)^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} )?failed to sufficiently increase receive buffer size \(was: \d+ kiB, wanted: \d+ kiB, got: \d+ kiB\)\. See https://github\.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details\.[ \t]*\r?$`,
	)
	qScopedIPv6LogPattern = regexp.MustCompile(
		`(?m)^(DEBU Removed IPv6 scope ID )%s from server %s (%[A-Za-z0-9]+)=(\S+)$`,
	)
	recAXFRPathPattern = regexp.MustCompile(`example\.com_[^\s]+_recaxfr`)
)

func TestPinnedQOutputParity(t *testing.T) {
	reference := os.Getenv("NEXTTRACE_Q_REFERENCE_BINARY")
	if reference == "" {
		t.Skip("set NEXTTRACE_Q_REFERENCE_BINARY to a q v0.19.12 binary")
	}
	udpServer := startTestDNSServer(t, "udp")
	tcpServer := startTestDNSServer(t, "tcp")
	for _, format := range []string{"pretty", "column", "raw", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			isolateRunEnvironment(t)
			args := []string{
				"--server=plain://" + udpServer,
				"--qname=example.com",
				"--type=A",
				"--qid=1234",
				"--format=" + format,
				"--timeout=1s",
				"+nocolor",
			}
			assertPinnedQParity(t, reference, args)
		})
	}

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "positionals", args: []string{"example.com", "A", "@" + udpServer, "--format=raw", "--qid=1234"}},
		{name: "IDNA", args: []string{"例子.测试", "A", "@" + udpServer, "--format=raw", "--qid=1234"}},
		{name: "reverse", args: []string{"--reverse", "192.0.2.10", "PTR", "@" + udpServer, "--format=raw", "--qid=1234"}},
		{name: "DNSSEC EDNS", args: []string{"example.com", "A", "@" + udpServer, "+dnssec", "--format=json", "--qid=1234"}},
		{name: "TCP", args: []string{"example.com", "TXT", "@tcp://" + tcpServer, "--format=raw", "--qid=1234"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateRunEnvironment(t)
			assertPinnedQParity(t, reference, test.args)
		})
	}
}

func assertPinnedQParity(t *testing.T, reference string, args []string) {
	t.Helper()
	var adapterOut, adapterErr bytes.Buffer
	adapterCode := Run(context.Background(), args, &adapterOut, &adapterErr)
	referenceOut, referenceErr, referenceCode := runReferenceQ(t, reference, args)
	if adapterCode != referenceCode {
		t.Fatalf("exit code adapter/reference = %d/%d\nadapter stderr: %s\nreference stderr: %s", adapterCode, referenceCode, adapterErr.String(), referenceErr)
	}
	if normalizeParityOutput(adapterErr.String()) != normalizeParityOutput(referenceErr) {
		t.Fatalf("stderr differs\nadapter: %q\nreference: %q", adapterErr.String(), referenceErr)
	}
	if normalizeParityOutput(adapterOut.String()) != normalizeParityOutput(referenceOut) {
		t.Fatalf("stdout differs\nadapter:\n%s\nreference:\n%s", adapterOut.String(), referenceOut)
	}
}

func TestPinnedQHelpAndErrorParity(t *testing.T) {
	reference := os.Getenv("NEXTTRACE_Q_REFERENCE_BINARY")
	if reference == "" {
		t.Skip("set NEXTTRACE_Q_REFERENCE_BINARY to a q v0.19.12 binary")
	}

	t.Run("help", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQHelpParity(t, reference)
	})

	t.Run("help with SSLKEYLOGFILE", func(t *testing.T) {
		isolateRunEnvironment(t)
		t.Setenv("SSLKEYLOGFILE", filepath.Join(t.TempDir(), "secret.keys"))
		assertPinnedQHelpParity(t, reference)
	})

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "invalid type", args: []string{"--type=INVALID"}},
		{name: "invalid reverse", args: []string{"--reverse", "not-an-ip"}},
		{name: "invalid ODoH proxy", args: []string{"--odoh-proxy=http://proxy", "@https://target"}},
		{name: "unknown option", args: []string{"--does-not-exist"}},
		{name: "missing option value", args: []string{"--server"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateRunEnvironment(t)
			var adapterOut, adapterErr bytes.Buffer
			adapterCode := Run(context.Background(), test.args, &adapterOut, &adapterErr)
			referenceOut, referenceErr, referenceCode := runReferenceQ(t, reference, test.args)
			if adapterCode != referenceCode {
				t.Fatalf("exit code adapter/reference = %d/%d", adapterCode, referenceCode)
			}
			if normalizeParityOutput(adapterOut.String()) != normalizeParityOutput(referenceOut) {
				t.Fatalf("stdout adapter/reference = %q/%q", adapterOut.String(), referenceOut)
			}
			if normalizeParityOutput(adapterErr.String()) != normalizeParityOutput(referenceErr) {
				t.Fatalf("stderr adapter/reference = %q/%q", adapterErr.String(), referenceErr)
			}
		})
	}
}

func assertPinnedQHelpParity(t *testing.T, reference string) {
	t.Helper()
	var adapterOut, adapterErr bytes.Buffer
	adapterCode := Run(context.Background(), []string{"--help"}, &adapterOut, &adapterErr)
	referenceOut, referenceErr, referenceCode := runReferenceQ(t, reference, []string{"--help"})
	if adapterCode != referenceCode || adapterErr.String() != referenceErr {
		t.Fatalf("help code/stderr adapter=%d/%q reference=%d/%q", adapterCode, adapterErr.String(), referenceCode, referenceErr)
	}
	adapterUsage := usageCommandPattern.ReplaceAllString(adapterOut.String(), "  COMMAND [OPTIONS] [@server] [type...] [name]")
	referenceUsage := usageCommandPattern.ReplaceAllString(referenceOut, "  COMMAND [OPTIONS] [@server] [type...] [name]")
	if normalizeParityOutput(adapterUsage) != normalizeParityOutput(referenceUsage) {
		t.Fatalf("help stdout differs\nadapter:\n%s\nreference:\n%s", adapterOut.String(), referenceOut)
	}
}

func TestPinnedQCompletionParity(t *testing.T) {
	reference := os.Getenv("NEXTTRACE_Q_REFERENCE_BINARY")
	if reference == "" {
		t.Skip("set NEXTTRACE_Q_REFERENCE_BINARY to a q v0.19.12 binary")
	}
	for _, value := range []string{"1", "verbose"} {
		t.Run(value, func(t *testing.T) {
			isolateRunEnvironment(t)
			t.Setenv("GO_FLAGS_COMPLETION", value)
			assertPinnedQParity(t, reference, []string{"--fo"})
		})
	}
}

func TestPinnedQExtendedCorpusParity(t *testing.T) {
	reference := os.Getenv("NEXTTRACE_Q_REFERENCE_BINARY")
	if reference == "" {
		t.Skip("set NEXTTRACE_Q_REFERENCE_BINARY to a q v0.19.12 binary")
	}
	udpServer := startTestDNSServer(t, "udp")

	t.Run("qrc", func(t *testing.T) {
		isolateRunEnvironment(t)
		qrc := strings.Join([]string{
			"--server=plain://" + udpServer,
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		}, "\n")
		if err := os.WriteFile(filepath.Join(os.Getenv("HOME"), ".qrc"), []byte(qrc), 0o600); err != nil {
			t.Fatal(err)
		}
		assertPinnedQParity(t, reference, []string{"example.com"})
	})

	t.Run("default server env", func(t *testing.T) {
		isolateRunEnvironment(t)
		t.Setenv(defaultServerEnv, "plain://"+udpServer)
		assertPinnedQParity(t, reference, []string{
			"example.com", "A", "--format=raw", "--qid=1234", "--timeout=1s",
		})
	})

	t.Run("multiple servers", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQParity(t, reference, []string{
			"--server=127.0.0.1:1",
			"--server=" + udpServer,
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=100ms",
		})
	})

	t.Run("scoped IPv6 logging", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQParity(t, reference, []string{
			"--verbose",
			"--server=plain://[fe80::1%lo0]:1",
			"--server=" + udpServer,
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=20ms",
		})
	})

	t.Run("resolve PTR", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQParity(t, reference, []string{
			"--server=" + udpServer,
			"--qname=example.com",
			"--type=A",
			"--resolve-ips",
			"--format=pretty",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("NSID and EDE", func(t *testing.T) {
		isolateRunEnvironment(t)
		metadataServer := startParityMetadataServer(t)
		assertPinnedQParity(t, reference, []string{
			"--server=" + metadataServer,
			"--qname=example.com",
			"--type=A",
			"--nsid",
			"--ede",
			"--format=pretty",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("UDP TCP fallback", func(t *testing.T) {
		isolateRunEnvironment(t)
		fallbackServer := startParityFallbackServer(t)
		assertPinnedQParity(t, reference, []string{
			"--server=" + fallbackServer,
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("DNS Stamp", func(t *testing.T) {
		isolateRunEnvironment(t)
		stamp, _, closeServer := startParityDoHStampServer(t)
		defer closeServer()
		assertPinnedQParity(t, reference, []string{
			"--server=" + stamp,
			"--qname=example.com",
			"--type=A",
			"--tls-insecure-skip-verify",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("DoT", func(t *testing.T) {
		isolateRunEnvironment(t)
		server := startParityDoTServer(t)
		assertPinnedQParity(t, reference, []string{
			"--server=tls://" + server,
			"--qname=example.com",
			"--type=A",
			"--tls-insecure-skip-verify",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("DoQ", func(t *testing.T) {
		isolateRunEnvironment(t)
		server := startParityDoQServer(t)
		assertPinnedQParity(t, reference, []string{
			"--server=quic://" + server,
			"--qname=example.com",
			"--type=A",
			"--tls-insecure-skip-verify",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("DNSCrypt", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQParity(t, reference, []string{
			"--server=" + startTestDNSCryptServer(t),
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("manual DNSCrypt", func(t *testing.T) {
		isolateRunEnvironment(t)
		stamp, err := dnsstamps.NewServerStampFromString(startTestDNSCryptServer(t))
		if err != nil {
			t.Fatal(err)
		}
		assertPinnedQParity(t, reference, []string{
			"--verbose",
			"--server=dnscrypt://" + stamp.ServerAddrStr,
			"--dnscrypt-key=" + hex.EncodeToString(stamp.ServerPk),
			"--dnscrypt-provider=" + stamp.ProviderName,
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	t.Run("ODoH", func(t *testing.T) {
		isolateRunEnvironment(t)
		target, proxy, closeServer := startParityODoHServer(t)
		defer closeServer()
		assertPinnedQParity(t, reference, []string{
			"--server=" + target,
			"--odoh-proxy=" + strings.Replace(proxy, "https://", "https://user:pass@", 1),
			"--qname=example.com",
			"--type=A",
			"--tls-insecure-skip-verify",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
		})
	})

	for _, mode := range []string{"--verbose", "--trace"} {
		t.Run(strings.TrimPrefix(mode, "--"), func(t *testing.T) {
			isolateRunEnvironment(t)
			assertPinnedQParity(t, reference, []string{
				mode,
				"--server=" + udpServer,
				"--qname=example.com",
				"--type=A",
				"--format=raw",
				"--qid=1234",
				"--timeout=1s",
			})
		})
	}

	for _, rrType := range []string{"TYPE65", "65"} {
		t.Run("numeric RR "+rrType, func(t *testing.T) {
			isolateRunEnvironment(t)
			assertPinnedQParity(t, reference, []string{
				"--verbose",
				"--server=" + udpServer,
				"--qname=example.com",
				"--type=" + rrType,
				"--format=raw",
				"--qid=1234",
				"--timeout=1s",
			})
		})
	}

	t.Run("TLS key log warning", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQParity(t, reference, []string{
			"--server=" + udpServer,
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
			"--tls-key-log-file=" + filepath.Join(t.TempDir(), "keys.log"),
		})
	})

	t.Run("HTTP header logging", func(t *testing.T) {
		isolateRunEnvironment(t)
		_, serverURL, closeServer := startParityDoHStampServer(t)
		defer closeServer()
		for _, header := range []string{"invalid", "X-Parity: enabled"} {
			assertPinnedQParity(t, reference, []string{
				"--verbose",
				"--server=" + serverURL,
				"--qname=example.com",
				"--type=A",
				"--format=raw",
				"--qid=1234",
				"--timeout=1s",
				"--tls-insecure-skip-verify",
				"--http-header=" + header,
			})
		}
		assertPinnedQParity(t, reference, []string{
			"--server=" + strings.Replace(serverURL, "https://", "https://user:pass@", 1),
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
			"--tls-insecure-skip-verify",
		})
		assertPinnedQParity(t, reference, []string{
			"--server=" + serverURL,
			"--qname=example.com",
			"--type=A",
			"--http-method=PATCH",
			"--format=raw",
			"--qid=1234",
			"--timeout=1s",
			"--tls-insecure-skip-verify",
		})
	})

	t.Run("recursive AXFR", func(t *testing.T) {
		isolateRunEnvironment(t)
		assertPinnedQAXFRParity(t, reference, startParityAXFRServer(t))
	})
}

func runReferenceQ(t *testing.T, binary string, args []string) (string, string, int) {
	return runReferenceQInDir(t, binary, args, "")
}

func runReferenceQInDir(t *testing.T, binary string, args []string, dir string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = append(os.Environ(), "NO_COLOR=1")
	command.Dir = dir
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("reference q timed out: %v", ctx.Err())
	}
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run reference q: %v", err)
	}
	return stdout.String(), stderr.String(), exitError.ExitCode()
}

func normalizeParityOutput(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = jsonTimePattern.ReplaceAllString(value, `"time":0`)
	value = yamlTimePattern.ReplaceAllString(value, "${1}time: 0s")
	value = fatalPrefixPattern.ReplaceAllString(value, "")
	value = prettyTimePattern.ReplaceAllString(value, ";; Time TIME")
	value = prettyFromPattern.ReplaceAllString(value, "${1}DURATION")
	value = serverWarningPattern.ReplaceAllString(value, "SERVER_WARNING")
	value = quicReceiveBufferWarningPattern.ReplaceAllString(value, "")
	value = qScopedIPv6LogPattern.ReplaceAllString(value, "${1}${2} from server ${3}")
	value = recAXFRPathPattern.ReplaceAllString(value, "AXFR_DIR")
	return strings.TrimSpace(value)
}

func TestNormalizeParityOutputCorrectsPinnedQScopedIPv6Log(t *testing.T) {
	malformed := "DEBU Removed IPv6 scope ID %s from server %s %lo0=plain://[fe80::1]:1"
	want := "DEBU Removed IPv6 scope ID %lo0 from server plain://[fe80::1]:1"
	if got := normalizeParityOutput(malformed); got != want {
		t.Fatalf("normalizeParityOutput() = %q, want %q", got, want)
	}
}

func TestNormalizeParityOutputIgnoresQUICReceiveBufferWarning(t *testing.T) {
	warning := "2026/07/27 12:34:56 failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB). See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details."
	got := normalizeParityOutput(warning + "\nquery failed: timeout")
	if got != "query failed: timeout" {
		t.Fatalf("normalizeParityOutput() = %q", got)
	}
}

func startParityMetadataServer(t *testing.T) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := testParityAReply(request)
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1232)
		opt.Option = []dns.EDNS0{
			&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e6f6465"},
			&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: "policy"},
		}
		reply.Extra = append(reply.Extra, opt)
		_ = writer.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return packetConn.LocalAddr().String()
}

func startParityFallbackServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := testParityAReply(request)
		if _, ok := writer.RemoteAddr().(*net.UDPAddr); ok {
			reply.Truncated = true
			reply.Answer = nil
		}
		_ = writer.WriteMsg(reply)
	})
	tcpServer := &dns.Server{Listener: listener, Handler: handler}
	udpServer := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return listener.Addr().String()
}

func startParityDoHStampServer(t *testing.T) (string, string, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var wire []byte
		var err error
		switch request.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
		case http.MethodPost:
			wire, err = io.ReadAll(request.Body)
		default:
			http.Error(writer, "unsupported method", http.StatusMethodNotAllowed)
			return
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response, err := testParityAReply(query).Pack()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	}))
	provider := strings.TrimPrefix(server.URL, "https://")
	stamp := (&dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeDoH,
		ServerAddrStr: server.Listener.Addr().String(),
		ProviderName:  provider,
		Path:          "/dns-query",
	}).String()
	return stamp, server.URL + "/dns-query", server.Close
}

func startParityDoTServer(t *testing.T) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testTLSCertificate(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for range 2 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			dnsConnection := &dns.Conn{Conn: connection}
			query, err := dnsConnection.ReadMsg()
			if err == nil {
				_ = dnsConnection.WriteMsg(testParityAReply(query))
			}
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func startParityDoQServer(t *testing.T) string {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testTLSCertificate(t)},
		NextProtos:   []string{"doq", "doq-i11"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testCommandTimeout)
		defer cancel()
		for range 2 {
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
			response, err := testParityAReply(query).Pack()
			if err != nil {
				return
			}
			framed := make([]byte, len(response)+2)
			binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
			copy(framed[2:], response)
			_, _ = stream.Write(framed)
			_ = stream.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func startParityODoHServer(t *testing.T) (string, string, func()) {
	t.Helper()
	keyPair, err := odoh.CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
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
	return server.URL + "/dns-query", server.URL + "/proxy", server.Close
}

func assertPinnedQAXFRParity(t *testing.T, reference, server string) {
	t.Helper()
	args := []string{"--recaxfr", "example.com", "@tcp://" + server, "--timeout=1s"}
	adapterDir := t.TempDir()
	referenceDir := t.TempDir()
	t.Chdir(adapterDir)
	var adapterOut, adapterErr bytes.Buffer
	adapterCode := Run(context.Background(), args, &adapterOut, &adapterErr)
	referenceOut, referenceErr, referenceCode := runReferenceQInDir(t, reference, args, referenceDir)
	if adapterCode != referenceCode || normalizeParityOutput(adapterOut.String()) != normalizeParityOutput(referenceOut) || normalizeParityOutput(adapterErr.String()) != normalizeParityOutput(referenceErr) {
		t.Fatalf("AXFR differs\nadapter code/stdout/stderr: %d/%q/%q\nreference code/stdout/stderr: %d/%q/%q", adapterCode, adapterOut.String(), adapterErr.String(), referenceCode, referenceOut, referenceErr)
	}
	adapterZones, err := filepath.Glob(filepath.Join(adapterDir, "*_recaxfr", "*.zone"))
	if err != nil {
		t.Fatal(err)
	}
	referenceZones, err := filepath.Glob(filepath.Join(referenceDir, "*_recaxfr", "*.zone"))
	if err != nil {
		t.Fatal(err)
	}
	if len(adapterZones) != 1 || len(referenceZones) != 1 {
		t.Fatalf("zone files adapter/reference = %v/%v", adapterZones, referenceZones)
	}
	adapterZone, err := os.ReadFile(adapterZones[0])
	if err != nil {
		t.Fatal(err)
	}
	referenceZone, err := os.ReadFile(referenceZones[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(adapterZone, referenceZone) {
		t.Fatalf("zone files differ\nadapter:\n%s\nreference:\n%s", adapterZone, referenceZone)
	}
}

func startParityAXFRServer(t *testing.T) string {
	t.Helper()
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  1,
		Refresh: 60,
		Retry:   60,
		Expire:  60,
		Minttl:  60,
	}
	address := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.10"),
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		if len(request.Question) != 1 || request.Question[0].Qtype != dns.TypeAXFR {
			_ = writer.WriteMsg(new(dns.Msg).SetRcode(request, dns.RcodeRefused))
			return
		}
		envelopes := make(chan *dns.Envelope, 1)
		envelopes <- &dns.Envelope{RR: []dns.RR{soa, address, soa}}
		close(envelopes)
		_ = new(dns.Transfer).Out(writer, request, envelopes)
		writer.Hijack()
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return listener.Addr().String()
}

func testParityAReply(request *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(request)
	if len(request.Question) > 0 {
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 125},
			A:   net.ParseIP("192.0.2.10"),
		}}
	}
	return reply
}
