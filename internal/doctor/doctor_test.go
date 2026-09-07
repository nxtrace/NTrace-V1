package doctor

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

func testOptions() Options {
	return Options{Target: "example.test", Method: trace.ICMPTrace, Config: trace.Config{Timeout: 20 * time.Millisecond, Lang: "en"}}
}

func testDependencies() dependencies {
	return dependencies{
		resolve: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, nil
		},
		interfaceByName: func(string) (*net.Interface, error) { return &net.Interface{Name: "test0"}, nil },
		normalize:       func(_ trace.Method, c trace.Config) (trace.Config, error) { return c, nil },
		source:          func(context.Context, net.IP) (string, error) { return "192.0.2.2", nil },
		route: func(context.Context, trace.Method, trace.Config) (Route, error) {
			return Route{Interface: "test0", OnLink: true}, nil
		},
		backend: func(context.Context, trace.Method, trace.Config) []trace.BackendCheck {
			return []trace.BackendCheck{{Name: "icmp_socket_bind"}}
		},
	}
}

func checkNamed(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing check %s: %+v", name, r)
	return Check{}
}

func TestDNSFailurePreservesIndependentChecks(t *testing.T) {
	o, d := testOptions(), testDependencies()
	o.Config.SourceDevice = "missing0"
	d.interfaceByName = func(string) (*net.Interface, error) { return nil, errors.New("no interface") }
	d.resolve = func(context.Context, string, string) ([]net.IP, error) { return nil, errors.New("NXDOMAIN") }
	d.route = func(context.Context, trace.Method, trace.Config) (Route, error) {
		t.Fatal("route ran without target")
		return Route{}, nil
	}
	d.backend = func(context.Context, trace.Method, trace.Config) []trace.BackendCheck {
		t.Fatal("backend ran without target")
		return nil
	}
	r := run(t.Context(), o, d)
	for _, name := range []string{"interface", "resolve"} {
		if checkNamed(t, r, name).Status != Fail {
			t.Fatalf("%s not failed", name)
		}
	}
	if checkNamed(t, r, "route").Status != Skip || r.ExitCode() != 1 {
		t.Fatalf("bad failure report: %+v", r)
	}
}

func TestRouteUnknownIsNotNoRouteAndBackendContinues(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status Status
		code   int
	}{{errors.New("permission denied"), Unknown, 3}, {context.DeadlineExceeded, Unknown, 3}, {errNoRoute, Fail, 1}} {
		d := testDependencies()
		d.route = func(context.Context, trace.Method, trace.Config) (Route, error) { return Route{}, tc.err }
		r := run(t.Context(), testOptions(), d)
		if checkNamed(t, r, "route").Status != tc.status || checkNamed(t, r, "icmp_socket_bind").Status != Pass || r.ExitCode() != tc.code {
			t.Fatalf("%v: %+v", tc.err, r)
		}
	}
}

func TestDoctorDNSDeadlineAndFamilySelection(t *testing.T) {
	o, d := testOptions(), testDependencies()
	o.IPv6Only = true
	d.source = func(_ context.Context, ip net.IP) (string, error) {
		if ip.To4() != nil {
			t.Fatal("selected IPv4")
		}
		return "2001:db8::2", nil
	}
	r := run(t.Context(), o, d)
	if len(r.Candidates) != 2 || !r.Target.Equal(net.ParseIP("2001:db8::1")) || r.ExitCode() != 0 {
		t.Fatalf("%+v", r)
	}
	d.resolve = func(ctx context.Context, _, _ string) ([]net.IP, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	r = run(t.Context(), o, d)
	if time.Since(start) > time.Second || !strings.Contains(checkNamed(t, r, "resolve").Detail, "deadline") {
		t.Fatalf("deadline not respected: %+v", r)
	}
}

func TestExplicitSourceNotOverwrittenByRoute(t *testing.T) {
	o, d := testOptions(), testDependencies()
	o.Config.SrcAddr = "192.0.2.90"
	o.Config.SourceDevice = "ignored0"
	o.Config.OSType = 2
	d.interfaceByName = func(string) (*net.Interface, error) { return nil, errors.New("missing interface") }
	d.normalize = trace.NormalizeExplicitSourceConfig
	d.source = func(context.Context, net.IP) (string, error) { t.Fatal("automatic source called"); return "", nil }
	d.route = func(_ context.Context, _ trace.Method, c trace.Config) (Route, error) {
		if c.SrcAddr != o.Config.SrcAddr || c.SourceDevice != "" {
			t.Fatalf("wrong query: %+v", c)
		}
		return Route{Source: "192.0.2.99"}, nil
	}
	r := run(t.Context(), o, d)
	if r.Source != o.Config.SrcAddr || r.Device != "" || r.ExitCode() != 0 {
		t.Fatalf("source overwritten: %+v", r)
	}
}

func TestWindowsDoctorNormalizesDeviceBeforeBackend(t *testing.T) {
	devices, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback string
	for _, dev := range devices {
		if dev.Flags&net.FlagLoopback != 0 {
			loopback = dev.Name
			break
		}
	}
	if loopback == "" {
		t.Skip("loopback interface unavailable")
	}
	for _, method := range []trace.Method{trace.ICMPTrace, trace.TCPTrace, trace.UDPTrace} {
		o, d := testOptions(), testDependencies()
		o.Method, o.Config.OSType, o.Config.SourceDevice = method, 2, loopback
		d.interfaceByName = net.InterfaceByName
		d.normalize = trace.NormalizeExplicitSourceConfig
		d.source = func(context.Context, net.IP) (string, error) {
			t.Fatal("automatic source selection bypassed the device")
			return "", nil
		}
		called := false
		d.backend = func(_ context.Context, _ trace.Method, cfg trace.Config) []trace.BackendCheck {
			called = true
			if cfg.SourceDevice != "" || cfg.SrcAddr != "127.0.0.1" {
				t.Fatalf("%s backend received unnormalized source: %+v", method, cfg)
			}
			return []trace.BackendCheck{{Name: "backend"}}
		}
		r := run(t.Context(), o, d)
		if !called || r.ExitCode() != 0 {
			t.Fatalf("%s: %+v", method, r)
		}
	}
}

func TestCancellationAndBackendUncertainty(t *testing.T) {
	o, d := testOptions(), testDependencies()
	d.backend = func(context.Context, trace.Method, trace.Config) []trace.BackendCheck {
		return []trace.BackendCheck{{Name: "windivert_availability", Err: errors.New("NO_INSTALL"), Unknown: true}}
	}
	r := run(t.Context(), o, d)
	if r.ExitCode() != 3 {
		t.Fatalf("unverified driver reported success: %+v", r)
	}
	d.backend = func(context.Context, trace.Method, trace.Config) []trace.BackendCheck {
		return []trace.BackendCheck{{Name: "windivert_availability", Err: errors.New("DLL missing; socket alternative checked"), Optional: true}}
	}
	r = run(t.Context(), o, d)
	if r.ExitCode() != 0 {
		t.Fatalf("optional alternative blocked: %+v", r)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d.resolve = func(ctx context.Context, _, _ string) ([]net.IP, error) { return nil, ctx.Err() }
	r = run(ctx, o, d)
	if !r.Interrupted {
		t.Fatal("missing interruption marker")
	}
	if checkNamed(t, r, "resolve").Status != Skip || r.ExitCode() != 3 {
		t.Fatal("cancellation reported as a diagnostic failure")
	}
}

func TestRenderBoundariesAndTerminalEscapes(t *testing.T) {
	r := run(t.Context(), testOptions(), testDependencies())
	r.Request.Config.SourceDevice = "fake\n[Pass] forged\x1b[2J"
	for _, lang := range []string{"cn", "en"} {
		r.Request.Config.Lang = lang
		var b bytes.Buffer
		if err := Render(&b, r); err != nil {
			t.Fatal(err)
		}
		s := b.String()
		if strings.Contains(s, "\x1b") || strings.Contains(s, "\n[Pass] forged") {
			t.Fatalf("terminal injection: %q", s)
		}
		if !strings.Contains(s, textLabel("boundary", lang)) || !strings.Contains(s, textLabel("prediction", lang)) {
			t.Fatal("missing evidence boundaries")
		}
	}
	if err := Render(failingWriter{}, r); err == nil {
		t.Fatal("write error ignored")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }
