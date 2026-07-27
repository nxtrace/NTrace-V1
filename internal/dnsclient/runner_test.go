//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	qlog "github.com/charmbracelet/log"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
	qutil "github.com/natesales/q/util"
)

func TestRunQueriesLocalUDPAndOutputFormats(t *testing.T) {
	server := startTestDNSServer(t, "udp")
	for _, format := range []string{"pretty", "column", "raw", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			isolateRunEnvironment(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{
				"--server=plain://" + server,
				"--qname=example.com",
				"--type=A",
				"--qid=1234",
				"--format=" + format,
				"--timeout=1s",
			}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run() code = %d, stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "192.0.2.10") {
				t.Fatalf("%s output missing address: %q", format, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestRunQueriesLocalTCP(t *testing.T) {
	isolateRunEnvironment(t)
	server := startTestDNSServer(t, "tcp")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"@tcp://" + server,
		"example.com",
		"TXT",
		"--txtconcat",
		"--format=raw",
		"--timeout=1s",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "part-onepart-two") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunSkipsFailedServerWhenAnotherSucceeds(t *testing.T) {
	isolateRunEnvironment(t)
	server := startTestDNSServer(t, "udp")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"--server=127.0.0.1:1",
		"--server=" + server,
		"--qname=example.com",
		"--type=A",
		"--format=raw",
		"--timeout=30ms",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "skipping server") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "192.0.2.10") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunZeroTimeoutExpiresImmediately(t *testing.T) {
	isolateRunEnvironment(t)
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"--server=127.0.0.1:1",
		"--qname=example.com",
		"--type=A",
		"--timeout=0s",
	}, io.Discard, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "timeout after 0s") {
		t.Fatalf("code/stderr = %d/%q", code, stderr.String())
	}
}

func TestAggregateDNSWorkTimeout(t *testing.T) {
	opts := &cli.Flags{Timeout: time.Second, Server: []string{"one", "two"}}
	queries := make([]dns.Msg, 3)
	if got := aggregateDNSWorkTimeout(opts, queries); got != 6*time.Second {
		t.Fatalf("aggregateDNSWorkTimeout() = %s, want 6s", got)
	}
	opts.RecAXFR = true
	if got := aggregateDNSWorkTimeout(opts, queries); got != 2*time.Second {
		t.Fatalf("recaxfr aggregateDNSWorkTimeout() = %s, want 2s", got)
	}
}

func TestRunBudgetsEachSerializedRRQuery(t *testing.T) {
	isolateRunEnvironment(t)
	server := startTestDNSServerWithDelay(t, "udp", 40*time.Millisecond, 1)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"--server=" + server,
		"--qname=example.com",
		"--type=A",
		"--type=AAAA",
		"--type=TXT",
		"--format=raw",
		"--timeout=80ms",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() code = %d, stderr=%q", code, stderr.String())
	}
}

func TestRunExtendsBudgetForEachPTRFollowup(t *testing.T) {
	isolateRunEnvironment(t)
	server := startTestDNSServerWithDelay(t, "udp", 30*time.Millisecond, 2)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"--server=" + server,
		"--qname=example.com",
		"--type=A",
		"--resolve-ips",
		"--format=raw",
		"--timeout=60ms",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() code = %d, stderr=%q", code, stderr.String())
	}
}

func TestRunRejectsMismatchedResponseID(t *testing.T) {
	query := dns.Msg{MsgHdr: dns.MsgHdr{Id: 1234}}
	txp := &staticTransport{reply: &dns.Msg{MsgHdr: dns.MsgHdr{Id: 1235}}}
	_, err := exchangeQueries(
		context.Background(),
		txp,
		ParsedServer{TransportType: transport.TypePlain},
		[]dns.Msg{query},
		&cli.Flags{IDCheck: true},
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "ID mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunHelpAndVersionDoNotQuery(t *testing.T) {
	isolateRunEnvironment(t)
	for _, test := range []struct {
		args []string
		want string
		code int
	}{
		{args: []string{"--help"}, want: "nexttrace --dns", code: 1},
		{args: []string{"--version"}, want: qCompatibilityVersion, code: 0},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), test.args, &stdout, &stderr); code != test.code {
			t.Fatalf("Run(%q) code=%d, want %d; stderr=%q", test.args, code, test.code, stderr.String())
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("Run(%q) stdout=%q", test.args, stdout.String())
		}
	}
}

func TestRunVersionReturnsWriterError(t *testing.T) {
	isolateRunEnvironment(t)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--version"}, errorWriter{}, &stderr); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "forced writer failure") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRestoresQProcessGlobals(t *testing.T) {
	isolateRunEnvironment(t)
	server := startTestDNSServer(t, "udp")
	originalLogger := qlog.Default()
	originalColor := qutil.UseColor
	originalResolver := net.DefaultResolver
	t.Cleanup(func() {
		qlog.SetDefault(originalLogger)
		qutil.UseColor = originalColor
		net.DefaultResolver = originalResolver
	})

	sentinelLogger := qlog.New(io.Discard)
	sentinelResolver := &net.Resolver{PreferGo: true}
	for _, test := range []struct {
		name     string
		extra    []string
		wantCode int
	}{
		{name: "success", wantCode: 0},
		{name: "error", extra: []string{"--tls-cipher-suites=NOT_A_CIPHER"}, wantCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			qlog.SetDefault(sentinelLogger)
			qutil.UseColor = true
			net.DefaultResolver = sentinelResolver
			args := []string{
				"--server=" + server,
				"--bootstrap-server=" + server,
				"--qname=example.com",
				"--type=A",
				"--format=raw",
				"--timeout=1s",
			}
			args = append(args, test.extra...)
			if code := Run(context.Background(), args, io.Discard, io.Discard); code != test.wantCode {
				t.Fatalf("code = %d, want %d", code, test.wantCode)
			}
			if qlog.Default() != sentinelLogger {
				t.Fatal("default logger was not restored")
			}
			if !qutil.UseColor {
				t.Fatal("q color global was not restored")
			}
			if net.DefaultResolver != sentinelResolver {
				t.Fatal("default resolver was not restored")
			}
		})
	}
}

type blockingTransport struct {
	unblock chan struct{}
}

func (b *blockingTransport) Exchange(*dns.Msg) (*dns.Msg, error) {
	<-b.unblock
	return nil, nil
}

func (*blockingTransport) Close() error { return nil }

type staticTransport struct {
	reply *dns.Msg
	err   error
}

func (s *staticTransport) Exchange(*dns.Msg) (*dns.Msg, error) { return s.reply, s.err }
func (*staticTransport) Close() error                          { return nil }

func TestExchangeWithContextReturnsOnCancellation(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	txp := &signalingBlockingTransport{started: started, unblock: unblock}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := exchangeWithContext(ctx, txp, new(dns.Msg))
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		t.Fatalf("exchange returned before transport finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v", err)
	}
}

type signalingBlockingTransport struct {
	started chan struct{}
	unblock chan struct{}
}

func (b *signalingBlockingTransport) Exchange(*dns.Msg) (*dns.Msg, error) {
	close(b.started)
	<-b.unblock
	return nil, nil
}

func (*signalingBlockingTransport) Close() error { return nil }

func TestRunTimedDNSWorkCoversPostQueryWork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdoutScope := newDiscardableWriter(&stdout)
	stderrScope := newDiscardableWriter(&stderr)
	release := make(chan struct{})
	cleaned := make(chan struct{})

	start := time.Now()
	err := runTimedDNSWork(
		context.Background(),
		20*time.Millisecond,
		stdoutScope,
		stderrScope,
		func() { close(cleaned) },
		func(context.Context) error {
			<-release
			_, _ = io.WriteString(stdoutScope, "late output")
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "timeout after 20ms") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout returned after %s", elapsed)
	}
	close(release)
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("background work did not clean up")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("late output leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTimedDNSWorkHonorsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-started
		cancel()
	}()

	stdoutScope := newDiscardableWriter(io.Discard)
	stderrScope := newDiscardableWriter(io.Discard)
	err := runTimedDNSWork(
		ctx,
		time.Second,
		stdoutScope,
		stderrScope,
		func() { close(done) },
		func(workCtx context.Context) error {
			close(started)
			<-workCtx.Done()
			return workCtx.Err()
		},
	)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled work did not clean up")
	}
}

func isolateRunEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NO_COLOR", "1")
	t.Setenv(defaultServerEnv, "")
	t.Setenv("SSLKEYLOGFILE", "")
	t.Setenv("GO_FLAGS_COMPLETION", "")
}

func startTestDNSServer(t *testing.T, network string) string {
	return startTestDNSServerWithDelay(t, network, 0, 1)
}

func startTestDNSServerWithDelay(t *testing.T, network string, delay time.Duration, addressAnswers int) string {
	t.Helper()
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		time.Sleep(delay)
		reply := new(dns.Msg)
		reply.SetReply(request)
		if len(request.Question) > 0 {
			switch request.Question[0].Qtype {
			case dns.TypeA:
				reply.Answer = make([]dns.RR, 0, addressAnswers)
				for i := 0; i < addressAnswers; i++ {
					reply.Answer = append(reply.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 125},
						A:   net.ParseIP(fmt.Sprintf("192.0.2.%d", 10+i)),
					})
				}
			case dns.TypeTXT:
				reply.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{"part-one", "part-two"},
				}}
			case dns.TypePTR:
				reply.Answer = []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: "ptr.example.com.",
				}}
			}
		}
		_ = writer.WriteMsg(reply)
	})

	server := &dns.Server{Net: network, Handler: handler}
	switch network {
	case "udp":
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn = packetConn
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		return packetConn.LocalAddr().String()
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		return listener.Addr().String()
	default:
		t.Fatalf("unsupported network %q", network)
		return ""
	}
}
