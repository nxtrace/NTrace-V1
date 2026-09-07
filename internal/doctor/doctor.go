// Package doctor collects local probe prerequisites. It never runs a trace.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
)

type Status string

const (
	Pass          Status = "pass"
	Fail          Status = "fail"
	Unknown       Status = "unknown"
	Skip          Status = "skip"
	NotApplicable Status = "not_applicable"
)

type Check struct {
	Name     string
	Status   Status
	Detail   string
	Optional bool
}

type Options struct {
	Target, DotServer  string
	IPv4Only, IPv6Only bool
	Method             trace.Method
	Config             trace.Config
}

type Route struct {
	Interface, Gateway, Source, Conditions, Limitations string
	OnLink                                              bool
}

type Report struct {
	Request                     Options
	Candidates                  []net.IP
	Target                      net.IP
	Source, Device, SourceBasis string
	Route                       Route
	Checks                      []Check
	Interrupted                 bool
}

var errNoRoute = errors.New("system reported no usable route")

type dependencies struct {
	resolve         func(context.Context, string, string) ([]net.IP, error)
	interfaceByName func(string) (*net.Interface, error)
	normalize       func(trace.Method, trace.Config) (trace.Config, error)
	source          func(context.Context, net.IP) (string, error)
	route           func(context.Context, trace.Method, trace.Config) (Route, error)
	backend         func(context.Context, trace.Method, trace.Config) []trace.BackendCheck
}

func Run(ctx context.Context, opts Options) Report {
	return run(ctx, opts, dependencies{
		resolve: util.ResolveTargetIPs, interfaceByName: net.InterfaceByName,
		normalize: trace.NormalizeExplicitSourceConfig, source: predictSource,
		route: queryRoute, backend: trace.CheckProbeBackend,
	})
}

func (r *Report) add(name string, status Status, detail string, optional bool) {
	r.Checks = append(r.Checks, Check{name, status, detail, optional})
}

func (r Report) ExitCode() int {
	unknown := false
	for _, c := range r.Checks {
		if c.Optional {
			continue
		}
		if c.Status == Fail {
			return 1
		}
		unknown = unknown || c.Status == Unknown || c.Status == Skip
	}
	if unknown || r.Interrupted {
		return 3
	}
	return 0
}

func run(ctx context.Context, opts Options, deps dependencies) Report {
	r := Report{Request: opts}
	if opts.Config.Timeout <= 0 {
		opts.Config.Timeout = 5 * time.Second
	}
	// Interface inspection does not depend on DNS. On Windows an explicit
	// source makes --dev informational, matching normal probe semantics.
	if dev := strings.TrimSpace(opts.Config.SourceDevice); dev != "" {
		_, err := deps.interfaceByName(dev)
		optional := opts.Config.OSType == 2 && opts.Config.SrcAddr != ""
		if err != nil {
			r.add("interface", Fail, err.Error(), optional)
		} else {
			r.add("interface", Pass, dev, optional)
		}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, opts.Config.Timeout)
	ips, err := deps.resolve(lookupCtx, opts.Target, opts.DotServer)
	cancel()
	if err != nil {
		status := Fail
		if ctx.Err() != nil {
			status = Skip
		}
		r.add("resolve", status, err.Error(), false)
	} else {
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			r.Candidates = append(r.Candidates, ip)
			if r.Target == nil && (!opts.IPv4Only || ip.To4() != nil) && (!opts.IPv6Only || ip.To4() == nil) {
				r.Target = ip
			}
		}
		if r.Target == nil {
			r.add("resolve", Fail, "no address matches the requested family", false)
		} else if net.ParseIP(opts.Target) != nil {
			r.add("resolve", NotApplicable, "IP literal", false)
		} else {
			r.add("resolve", Pass, r.Target.String(), false)
		}
	}
	if r.Target == nil {
		r.add("source", Skip, "target unavailable", false)
		r.add("route", Skip, "target unavailable", false)
		r.add("backend", Skip, "target unavailable", false)
		r.Interrupted = ctx.Err() != nil
		return r
	}
	cfg := opts.Config
	cfg.DstIP = r.Target
	cfg, err = deps.normalize(opts.Method, cfg)
	if err == nil && cfg.SrcAddr != "" {
		ip := net.ParseIP(cfg.SrcAddr)
		if ip == nil || ip.IsUnspecified() || (ip.To4() == nil) != (r.Target.To4() == nil) {
			err = errors.New("source address is invalid or does not match the target family")
		}
	}
	if err != nil {
		r.add("source", Fail, err.Error(), false)
		r.add("route", Skip, "effective source configuration unavailable", false)
		r.add("backend", Skip, "effective source configuration unavailable", false)
		r.Interrupted = ctx.Err() != nil
		return r
	}
	r.Device = cfg.SourceDevice
	switch {
	case opts.Config.SrcAddr != "":
		r.SourceBasis = "explicit_source"
	case opts.Config.SourceDevice != "":
		r.SourceBasis = "device_source"
	default:
		r.SourceBasis = "socket_prediction"
		sourceCtx, stop := context.WithTimeout(ctx, opts.Config.Timeout)
		cfg.SrcAddr, err = deps.source(sourceCtx, r.Target)
		stop()
	}
	r.Source = cfg.SrcAddr
	if err != nil {
		status := Unknown
		if ctx.Err() != nil {
			status = Skip
		}
		r.add("source", status, err.Error(), false)
	} else {
		r.add("source", Pass, r.Source, false)
	}
	// Route queries can still explain a failed automatic source selection.
	routeCtx, stop := context.WithTimeout(ctx, opts.Config.Timeout)
	r.Route, err = deps.route(routeCtx, opts.Method, cfg)
	stop()
	switch {
	case ctx.Err() != nil:
		r.add("route", Skip, ctx.Err().Error(), false)
	case errors.Is(err, errNoRoute):
		r.add("route", Fail, err.Error(), false)
	case err != nil:
		r.add("route", Unknown, err.Error(), false)
	default:
		r.add("route", Pass, "", false)
	}
	if r.Source == "" {
		r.add("backend", Skip, "source address unavailable", false)
	} else {
		for _, c := range deps.backend(ctx, opts.Method, cfg) {
			status, detail := Pass, c.Detail
			if c.Err != nil {
				status, detail = Fail, c.Err.Error()
			}
			if c.Unknown {
				status = Unknown
			}
			if c.Skipped {
				status = Skip
			}
			r.add(c.Name, status, detail, c.Optional)
		}
	}
	r.Interrupted = ctx.Err() != nil
	return r
}

// UDP connect asks the kernel for a source address. No payload is written.
func predictSource(ctx context.Context, target net.IP) (string, error) {
	network := "udp4"
	if target.To4() == nil {
		network = "udp6"
	}
	c, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(target.String(), "9"))
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	a, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || a.IP.IsUnspecified() {
		return "", errors.New("kernel did not select a source address")
	}
	return a.IP.String(), nil
}

func routeConditions(method trace.Method, cfg trace.Config) string {
	return fmt.Sprintf("dst=%s source=%s dev=%s protocol=%s sport=%d dport=%d tos=%d", cfg.DstIP, cfg.SrcAddr, cfg.SourceDevice, method, cfg.SrcPort, cfg.DstPort, cfg.TOS)
}

func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
