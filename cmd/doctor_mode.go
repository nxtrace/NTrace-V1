package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/nxtrace/NTrace-core/config"
	"github.com/nxtrace/NTrace-core/internal/doctor"
	"github.com/nxtrace/NTrace-core/util"
)

func containsDoctorFlag(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		if arg == "--doctor" || arg == "--doctor=true" {
			return true
		}
		// Do not steal a token or filename whose literal value is --doctor
		// from the main parser. These are the main CLI's value-taking options.
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && !inline && doctorValueOption(name) {
			i++
		}
	}
	return false
}

func doctorValueOption(name string) bool {
	switch name {
	case "p", "port", "s", "source", "D", "dev", "source-port", "Q", "tos", "timeout", "dot-server", "g", "language", "icmp-mode",
		"q", "queries", "max-attempts", "parallel-requests", "m", "max-hops", "d", "data-provider", "pow-provider", "f", "first",
		"o", "output", "listen", "deploy-token", "z", "send-time", "i", "ttl-time", "psize", "from", "mtr-columns", "y", "ipinfo", "file":
		return true
	}
	return false
}

// doctorArgs permits flags on either side of the target, while preserving flag
// values and the -- delimiter. Unsupported options never reach normal dispatch.
func doctorArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			return nil, errors.New("unsupported doctor option")
		}
		flags = append(flags, arg)
		b, isBool := f.Value.(interface{ IsBoolFlag() bool })
		if !hasValue && (!isBool || !b.IsBoolFlag()) {
			i++
			if i == len(args) {
				return nil, errors.New("missing option value")
			}
			flags = append(flags, args[i])
		}
	}
	return append(append(flags, "--"), positionals...), nil
}

type doctorCLIFlags struct {
	opts                                      doctor.Options
	enabled, help, version, tcp, udp, noColor bool
	timeout                                   int
}

func registerDoctorFlags() (*flag.FlagSet, *doctorCLIFlags) {
	fs := flag.NewFlagSet(appBinName+" --doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	v := &doctorCLIFlags{}
	fs.BoolVar(&v.enabled, "doctor", false, "Check local probe prerequisites without sending probes")
	for _, n := range []string{"h", "help"} {
		fs.BoolVar(&v.help, n, false, "Show doctor help")
	}
	for _, n := range []string{"V", "version"} {
		fs.BoolVar(&v.version, n, false, "Show version")
	}
	for _, n := range []string{"4", "ipv4"} {
		fs.BoolVar(&v.opts.IPv4Only, n, false, "Select IPv4")
	}
	for _, n := range []string{"6", "ipv6"} {
		fs.BoolVar(&v.opts.IPv6Only, n, false, "Select IPv6")
	}
	for _, n := range []string{"T", "tcp"} {
		fs.BoolVar(&v.tcp, n, false, "Check TCP prerequisites")
	}
	for _, n := range []string{"U", "udp"} {
		fs.BoolVar(&v.udp, n, false, "Check UDP prerequisites")
	}
	for _, n := range []string{"p", "port"} {
		fs.IntVar(&v.opts.Config.DstPort, n, 0, "Destination port")
	}
	for _, n := range []string{"s", "source"} {
		fs.StringVar(&v.opts.Config.SrcAddr, n, "", "Source address")
	}
	for _, n := range []string{"D", "dev"} {
		fs.StringVar(&v.opts.Config.SourceDevice, n, "", "Requested interface")
	}
	fs.IntVar(&v.opts.Config.SrcPort, "source-port", 0, "Requested source port (0: automatic)")
	for _, n := range []string{"Q", "tos"} {
		fs.IntVar(&v.opts.Config.TOS, n, 0, "Requested TOS; application is not verified")
	}
	fs.IntVar(&v.timeout, "timeout", 5000, "Per-network-check timeout in milliseconds")
	fs.StringVar(&v.opts.DotServer, "dot-server", "", "dnssb, aliyun, dnspod, google or cloudflare")
	for _, n := range []string{"g", "language"} {
		fs.StringVar(&v.opts.Config.Lang, n, "cn", "cn or en")
	}
	for _, n := range []string{"C", "no-color"} {
		fs.BoolVar(&v.noColor, n, false, "Doctor always uses plain text")
	}
	v.opts.Config.OSType = resolveOSType()
	if v.opts.Config.OSType == 2 {
		fs.IntVar(&v.opts.Config.ICMPMode, "icmp-mode", 0, "ICMP receiver: 0=auto, 1=socket, 2=WinDivert")
	}
	return fs, v
}

func maybeRunDoctorMode(args []string, stdout, stderr io.Writer) (bool, int) {
	if !containsDoctorFlag(args) {
		return false, 0
	}
	fs, v := registerDoctorFlags()
	ordered, err := doctorArgs(fs, args)
	if err == nil {
		err = fs.Parse(ordered)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "Invalid or unsupported doctor arguments; use --doctor --help.")
		return true, 2
	}
	if !v.enabled {
		return false, 0
	}
	if v.help {
		_, _ = fmt.Fprintf(stdout, "Usage: %s --doctor [options] <domain|IP>\nText-only local initialization checks. No probe packets or driver installation.\n", appBinName)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return true, 0
	}
	if v.version {
		_, _ = fmt.Fprintln(stdout, config.Version, config.CommitID)
		return true, 0
	}
	if err := validateDoctorOptions(fs, v); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return true, 2
	}
	return true, runDoctorCLI(v.opts, stdout, stderr)
}

func validateDoctorOptions(fs *flag.FlagSet, v *doctorCLIFlags) error {
	if fs.NArg() != 1 {
		return errors.New("doctor requires exactly one domain or IP target")
	}
	o := &v.opts
	o.Target = fs.Arg(0)
	if !validDoctorTarget(o.Target) {
		return errors.New("doctor requires a domain or IP literal; URLs and scoped addresses are not supported")
	}
	if o.IPv4Only && o.IPv6Only || v.tcp && v.udp {
		return errors.New("conflicting address families or probe protocols")
	}
	if v.timeout <= 0 || int64(v.timeout) > int64((1<<63-1)/time.Millisecond) || o.Config.TOS < 0 || o.Config.TOS > 255 || o.Config.ICMPMode < 0 || o.Config.ICMPMode > 2 {
		return errors.New("invalid timeout, TOS or ICMP mode")
	}
	if o.Config.Lang != "cn" && o.Config.Lang != "en" {
		return errors.New("language must be cn or en")
	}
	switch o.DotServer {
	case "", "dnssb", "aliyun", "dnspod", "google", "cloudflare":
	default:
		return errors.New("unsupported DoT resolver")
	}
	o.Method = resolveTraceMethod(v.tcp, v.udp)
	portSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "p" || f.Name == "port" || f.Name == "source-port" {
			portSet = true
		}
	})
	if !v.tcp && !v.udp && portSet {
		return errors.New("ICMP has no source or destination port")
	}
	if v.tcp || v.udp {
		applyDefaultPort(&o.Config.DstPort, v.udp)
	}
	if o.Config.DstPort < 0 || o.Config.DstPort > 65535 || o.Config.SrcPort < 0 || o.Config.SrcPort > 65535 {
		return errors.New("invalid source or destination port")
	}
	if o.Config.OSType == 2 && o.Config.ICMPMode == 0 && util.EnvICMPMode > 0 && util.EnvICMPMode <= 2 {
		o.Config.ICMPMode = util.EnvICMPMode
	}
	o.Config.Timeout = time.Duration(v.timeout) * time.Millisecond
	return nil
}

func runDoctorCLI(opts doctor.Options, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case sig := <-signals:
			cancel(&mtrJSONSignal{signal: sig})
		case <-ctx.Done():
		}
	}()
	defer func() { signal.Stop(signals); cancel(nil); <-done }()
	r := doctor.Run(ctx, opts)
	if err := doctor.Render(stdout, r); err != nil {
		_, _ = fmt.Fprintln(stderr, "Unable to write doctor report.")
		return 1
	}
	var interrupted *mtrJSONSignal
	if errors.As(context.Cause(ctx), &interrupted) {
		if interrupted.signal == syscall.SIGTERM {
			return 143
		}
		return 130
	}
	return r.ExitCode()
}
func validDoctorTarget(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
