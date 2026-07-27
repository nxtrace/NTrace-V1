//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	qlog "github.com/charmbracelet/log"
	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	qoutput "github.com/natesales/q/output"
	"github.com/natesales/q/transport"
	qutil "github.com/natesales/q/util"
)

const qCompatibilityVersion = "v0.19.12"

var dnsClientGlobalMu sync.Mutex

type dnsWorkTimeoutExtender func(time.Duration)
type dnsWorkTimeoutExtenderKey struct{}

type discardableWriter struct {
	mu       sync.Mutex
	out      io.Writer
	disabled bool
}

func newDiscardableWriter(out io.Writer) *discardableWriter {
	return &discardableWriter{out: out}
}

func (w *discardableWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.disabled {
		return len(p), nil
	}
	return w.out.Write(p)
}

func (w *discardableWriter) disable() {
	w.mu.Lock()
	w.disabled = true
	w.mu.Unlock()
}

// Run executes q-compatible DNS client arguments. It is intentionally scoped
// to NextTrace's exclusive full-flavor terminal mode.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	dnsClientGlobalMu.Lock()
	backgroundCleanup := false
	stdoutScope := newDiscardableWriter(stdout)
	stderrScope := newDiscardableWriter(stderr)
	previousLogger := qlog.Default()
	qlog.SetDefault(qlog.NewWithOptions(stderrScope, qlog.Options{ReportTimestamp: false}))
	previousColor := qutil.UseColor
	restoreResolver := func() {}
	closeTLS := func() error { return nil }
	cleanup := func() {
		_ = closeTLS()
		restoreResolver()
		qutil.UseColor = previousColor
		qlog.SetDefault(previousLogger)
		dnsClientGlobalMu.Unlock()
	}
	defer func() {
		if !backgroundCleanup {
			cleanup()
		}
	}()

	config, err := ParseConfig(args, DefaultParseOptions(writerIsTerminal(stdout)))
	if err != nil {
		if flagErr, ok := flagsError(err); ok {
			if flagErr.Type == flags.ErrHelp {
				_, _ = fmt.Fprintln(stdout, flagErr.Message)
				return 1
			}
			_, _ = fmt.Fprintln(stderr, flagErr.Message)
		}
		_, _ = fmt.Fprintf(stderr, "dns mode error: %v\n", err)
		return 1
	}
	for _, warning := range config.Warnings {
		_, _ = fmt.Fprintf(stderrScope, "dns mode warning: %s\n", warning)
	}
	if config.CompletionRequested {
		renderCompletions(stdoutScope, config.Completions, config.CompletionVerbose)
		return 0
	}

	opts := &config.Flags
	if opts.Verbose || opts.Trace {
		qlog.SetLevel(qlog.DebugLevel)
	}
	qutil.UseColor = opts.Color

	if opts.ShowVersion {
		if _, err := fmt.Fprintf(stdoutScope, "https://github.com/natesales/q version %s (NextTrace adapter)\n", qCompatibilityVersion); err != nil {
			_, _ = fmt.Fprintf(stderrScope, "dns mode error: write version: %v\n", err)
			return 1
		}
		return 0
	}
	restoreResolver, err = installBootstrapResolver(*opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dns mode error: %v\n", err)
		return 1
	}
	logRuntimeConfig(config)

	tlsConfig, tlsCleanup, err := BuildTLSConfig(*opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dns mode error: %v\n", err)
		return 1
	}
	closeTLS = tlsCleanup

	queries, err := BuildQueries(config)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dns mode error: %v\n", err)
		return 1
	}

	totalTimeout := aggregateDNSWorkTimeout(opts, queries)
	backgroundCleanup = true
	err = runTimedDNSWork(
		ctx,
		totalTimeout,
		stdoutScope,
		stderrScope,
		cleanup,
		func(workCtx context.Context) error {
			entries, queryErr := queryServers(workCtx, queries, opts, tlsConfig, stdoutScope, stderrScope)
			if queryErr != nil || opts.RecAXFR {
				return queryErr
			}
			return renderEntries(stdoutScope, opts, entries)
		},
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dns mode error: %v\n", err)
		return 1
	}
	return 0
}

func runTimedDNSWork(
	parent context.Context,
	totalTimeout time.Duration,
	stdout, stderr *discardableWriter,
	cleanup func(),
	work func(context.Context) error,
) error {
	baseCtx, cancel := context.WithCancel(parent)
	defer cancel()
	extensions := make(chan time.Duration)
	workCtx := context.WithValue(baseCtx, dnsWorkTimeoutExtenderKey{}, dnsWorkTimeoutExtender(func(extension time.Duration) {
		if extension <= 0 {
			return
		}
		select {
		case extensions <- extension:
		case <-baseCtx.Done():
		}
	}))
	result := make(chan error, 1)
	go func() {
		err := func() error {
			defer cleanup()
			return work(workCtx)
		}()
		result <- err
	}()

	timer := time.NewTimer(totalTimeout)
	defer timer.Stop()
	deadline := time.Now().Add(totalTimeout)
	effectiveTimeout := totalTimeout
	for {
		select {
		case err := <-result:
			cancel()
			return normalizeRunError(err, effectiveTimeout)
		case extension := <-extensions:
			effectiveTimeout += extension
			deadline = deadline.Add(extension)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			remaining := time.Until(deadline)
			if remaining < 0 {
				remaining = 0
			}
			timer.Reset(remaining)
		case <-timer.C:
			stdout.disable()
			stderr.disable()
			cancel()
			return normalizeRunError(context.DeadlineExceeded, effectiveTimeout)
		case <-baseCtx.Done():
			stdout.disable()
			stderr.disable()
			return normalizeRunError(baseCtx.Err(), effectiveTimeout)
		}
	}
}

func aggregateDNSWorkTimeout(opts *cli.Flags, queries []dns.Msg) time.Duration {
	serverCount := len(opts.Server)
	if serverCount == 0 {
		serverCount = 1
	}
	queryCount := len(queries)
	if queryCount == 0 || opts.RecAXFR {
		queryCount = 1
	}
	return opts.Timeout * time.Duration(serverCount*queryCount)
}

func extendDNSWorkTimeout(ctx context.Context, extension time.Duration) {
	extend, ok := ctx.Value(dnsWorkTimeoutExtenderKey{}).(dnsWorkTimeoutExtender)
	if ok {
		extend(extension)
	}
}

func normalizeRunError(err error, totalTimeout time.Duration) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timeout after %s", totalTimeout)
	}
	return err
}

func flagsError(err error) (*flags.Error, bool) {
	var flagErr *flags.Error
	ok := errors.As(err, &flagErr)
	return flagErr, ok
}

func renderCompletions(out io.Writer, items []flags.Completion, verbose bool) {
	if verbose && len(items) > 1 {
		maxLength := 0
		for _, item := range items {
			if len(item.Item) > maxLength {
				maxLength = len(item.Item)
			}
		}
		for _, item := range items {
			_, _ = fmt.Fprint(out, item.Item)
			if item.Description != "" {
				_, _ = fmt.Fprintf(out, "%s  # %s", strings.Repeat(" ", maxLength-len(item.Item)), item.Description)
			}
			_, _ = fmt.Fprintln(out)
		}
		return
	}
	for _, item := range items {
		_, _ = fmt.Fprintln(out, item.Item)
	}
}

func writerIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func installBootstrapResolver(opts cli.Flags) (func(), error) {
	if opts.BootstrapServer == "" {
		return func() {}, nil
	}
	server, err := serverWithDefaultPort(opts.BootstrapServer, "53")
	if err != nil {
		return nil, fmt.Errorf("bootstrap server: %w", err)
	}
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: opts.BootstrapTimeout}
			return dialer.DialContext(ctx, network, server)
		},
	}
	qlog.Debugf("Using bootstrap resolver %s", server)
	return func() { net.DefaultResolver = previous }, nil
}

func logRuntimeConfig(config Config) {
	opts := &config.Flags
	for _, message := range config.EarlyDebugMessages {
		qlog.Debug(message)
	}
	if opts.Verbose {
		qlog.Debugf("Name: %s", opts.Name)
		rrTypeStrings := make([]string, 0, len(config.RRTypes))
		for _, rrType := range config.RRTypes {
			name, ok := dns.TypeToString[rrType]
			if !ok {
				name = fmt.Sprintf("TYPE%d", rrType)
			}
			rrTypeStrings = append(rrTypeStrings, name)
		}
		qlog.Debugf("RR types: %+v", rrTypeStrings)
	}
	for _, message := range config.DebugMessages {
		qlog.Debug(message)
	}
	qlog.Debugf("Server(s): %v", opts.Server)
	if opts.Chaos {
		qlog.Debug("Flag set, using chaos class")
	}
}

func serverWithDefaultPort(server, port string) (string, error) {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	if !strings.Contains(server, ":") {
		return net.JoinHostPort(server, port), nil
	}
	return "", fmt.Errorf("invalid address %q", server)
}

func queryServers(
	ctx context.Context,
	queries []dns.Msg,
	opts *cli.Flags,
	tlsConfig *tls.Config,
	stdout, stderr io.Writer,
) ([]*qoutput.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries := make([]*qoutput.Entry, 0, len(opts.Server))
	multiple := len(opts.Server) > 1
	for _, rawServer := range opts.Server {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, transferred, err := queryServer(ctx, rawServer, queries, opts, tlsConfig, stdout)
		if transferred {
			return entries, err
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if multiple {
				if entry != nil {
					entries = append(entries, entry)
				}
				_, _ = fmt.Fprintf(stderr, "dns mode warning: skipping server %s: %v\n", rawServer, err)
				continue
			}
			return nil, err
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("all servers failed")
	}
	return entries, nil
}

func queryServer(
	ctx context.Context,
	rawServer string,
	queries []dns.Msg,
	opts *cli.Flags,
	tlsConfig *tls.Config,
	stdout io.Writer,
) (*qoutput.Entry, bool, error) {
	server, err := ParseServer(rawServer)
	if err != nil {
		return nil, false, fmt.Errorf("parsing server %s: %w", rawServer, err)
	}
	qlog.Debugf("Using server %s with transport %s", server.Address, server.TransportType)
	if opts.RecAXFR {
		return nil, true, runRecursiveAXFR(ctx, opts.Name, server.Address, opts.Timeout, stdout)
	}

	txp, err := NewTransport(server, *opts, tlsConfig)
	if err != nil {
		return nil, false, fmt.Errorf("creating transport: %w", err)
	}
	start := time.Now()
	replies, queryErr := exchangeQueries(ctx, txp, server, queries, opts, stdout)
	if queryErr != nil {
		_ = txp.Close()
		return nil, false, queryErr
	}
	postProcessReplies(replies, opts)
	entry := &qoutput.Entry{Queries: queries, Replies: replies, Server: server.Address, Time: time.Since(start)}
	if opts.ResolveIPs {
		extendDNSWorkTimeout(ctx, opts.Timeout*time.Duration(ptrFollowupCount(replies)))
		if err := loadPTRs(ctx, entry, txp); err != nil {
			_ = txp.Close()
			return nil, false, err
		}
	}
	if err := txp.Close(); err != nil {
		return entry, false, fmt.Errorf("closing transport: %w", err)
	}
	return entry, false, nil
}

func ptrFollowupCount(replies []*dns.Msg) int {
	count := 0
	for _, reply := range replies {
		for _, rr := range reply.Answer {
			if addressRecordIP(rr) != "" {
				count++
			}
		}
	}
	return count
}

func exchangeQueries(
	ctx context.Context,
	txp transport.Transport,
	server ParsedServer,
	queries []dns.Msg,
	opts *cli.Flags,
	stdout io.Writer,
) ([]*dns.Msg, error) {
	replies := make([]*dns.Msg, 0, len(queries))
	for i := range queries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		query := queries[i]
		reply, err := exchangeWithContext(ctx, txp, &query)
		if err != nil {
			return nil, fmt.Errorf("exchange: %w", err)
		}
		if reply == nil {
			return nil, fmt.Errorf("no reply from server")
		}
		if opts.ShowOpt {
			printOPTRecords(stdout, reply)
		}
		if server.TransportType != transport.TypeQUIC && opts.IDCheck && reply.Id != query.Id {
			return nil, fmt.Errorf("ID mismatch: expected %d, got %d", query.Id, reply.Id)
		}
		replies = append(replies, reply)
	}
	return replies, nil
}

func printOPTRecords(out io.Writer, reply *dns.Msg) {
	for _, rr := range reply.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			_, _ = fmt.Fprintf(out, "OPT: %v\n", rr)
		}
	}
}

func exchangeWithContext(ctx context.Context, txp transport.Transport, msg *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reply, err := txp.Exchange(msg)
	if err == nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return reply, err
}
