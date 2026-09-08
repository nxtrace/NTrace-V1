//go:build linux && !android

package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/internal/routeprobe"
	"github.com/nxtrace/NTrace-core/util"
)

func stubProbeRoute(t *testing.T, query func(context.Context, routeprobe.Request) (routeprobe.Route, error)) {
	t.Helper()
	previous := queryProbeRoute
	queryProbeRoute = query
	t.Cleanup(func() { queryProbeRoute = previous })
}

func TestTOSSourceRouteConditions(t *testing.T) {
	for _, target := range []string{"192.0.2.9", "2001:db8::9"} {
		for _, method := range []Method{ICMPTrace, TCPTrace, UDPTrace} {
			for _, tos := range []int{1, 2, 3, 16, 46, 184, 255} {
				for _, mark := range []struct {
					value uint32
					set   bool
				}{{256, false}, {0, true}, {256, true}} {
					name := fmt.Sprintf("%s/%s/%d/%d/%t", target, method, tos, mark.value, mark.set)
					t.Run(name, func(t *testing.T) {
						source := "192.0.2.2"
						if net.ParseIP(target).To4() == nil {
							source = "2001:db8::2"
						}
						cfg := Config{DstIP: net.ParseIP(target), TOS: tos, FWMark: mark.value, FWMarkSet: mark.set, SrcPort: 40000, DstPort: 443, Context: t.Context(), Timeout: time.Second}
						calls := 0
						stubProbeRoute(t, func(ctx context.Context, req routeprobe.Request) (routeprobe.Route, error) {
							calls++
							if req.Method != string(method) || !req.DstIP.Equal(cfg.DstIP) || req.TOS != tos || req.FWMark != mark.value || req.FWMarkSet != mark.set {
								t.Fatalf("lost route condition: %+v", req)
							}
							if req.SrcPort != 0 || req.DstPort != 0 {
								t.Fatalf("raw route unexpectedly includes ports: %+v", req)
							}
							if _, ok := ctx.Deadline(); !ok {
								t.Fatal("route query has no timeout")
							}
							return routeprobe.Route{Source: source}, nil
						})
						got, err := NormalizeExplicitSourceConfig(method, cfg)
						if err != nil || calls != 1 || got.SrcAddr != source || got.SrcPort != 40000 || got.TOS != tos || got.FWMarkSet != mark.set || cfg.SrcAddr != "" {
							t.Fatalf("prepared=%+v calls=%d err=%v", got, calls, err)
						}
					})
				}
			}
		}
	}
}

func TestTOSSourceDeviceAndExplicitSource(t *testing.T) {
	restore := stubSourceDeviceResolver(t, func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 7}, nil
	}, func(*net.Interface) ([]net.Addr, error) {
		t.Fatal("policy-routed source must come from the kernel route, not the first device address")
		return nil, nil
	})
	defer restore()
	calls := 0
	stubProbeRoute(t, func(_ context.Context, req routeprobe.Request) (routeprobe.Route, error) {
		calls++
		if req.SourceDevice != "policy0" || req.SrcAddr != "" {
			t.Fatalf("device constraint lost: %+v", req)
		}
		return routeprobe.Route{Source: "192.0.2.2"}, nil
	})
	cfg := Config{DstIP: net.ParseIP("192.0.2.9"), SourceDevice: " policy0 ", TOS: 184}
	got, err := NormalizeExplicitSourceConfig(ICMPTrace, cfg)
	if err != nil || got.SrcAddr != "192.0.2.2" || got.SourceDevice != "policy0" || calls != 1 {
		t.Fatalf("device selection: %+v %v", got, err)
	}
	cfg.SrcAddr = " 192.0.2.3 "
	got, err = NormalizeExplicitSourceConfig(ICMPTrace, cfg)
	if err != nil || got.SrcAddr != "192.0.2.3" || got.SourceDevice != "policy0" || calls != 1 {
		t.Fatalf("explicit source was replaced: %+v %v", got, err)
	}
}

func TestTOSRouteFailureDoesNotFallBack(t *testing.T) {
	for _, cause := range []error{routeprobe.ErrNoRoute, context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			stubProbeRoute(t, func(context.Context, routeprobe.Request) (routeprobe.Route, error) {
				return routeprobe.Route{}, cause
			})
			cfg := Config{DstIP: net.ParseIP("127.0.0.1"), TOS: 184, Context: t.Context()}
			got, err := NormalizeExplicitSourceConfig(ICMPTrace, cfg)
			wantSetup := errors.Is(cause, routeprobe.ErrNoRoute)
			if IsInitializationError(err) != wantSetup || !errors.Is(err, cause) || got.SrcAddr != "" {
				t.Fatalf("route error was hidden by fallback: %+v %v", got, err)
			}
			for _, method := range []Method{ICMPTrace, TCPTrace, UDPTrace} {
				for _, interval := range []time.Duration{0, time.Millisecond} {
					err = RunMTR(t.Context(), method, cfg, MTROptions{HopInterval: interval}, nil)
					if IsInitializationError(err) != wantSetup || !errors.Is(err, cause) {
						t.Fatalf("MTR %s interval=%s swallowed source error: %v", method, interval, err)
					}
					err = RunMTRRaw(t.Context(), method, cfg, MTRRawOptions{HopInterval: interval}, nil)
					if IsInitializationError(err) != wantSetup || !errors.Is(err, cause) {
						t.Fatalf("MTR raw %s interval=%s swallowed source error: %v", method, interval, err)
					}
				}
			}
		})
	}
}

func TestTOSSessionsDoNotReuseSourceCache(t *testing.T) {
	stubProbeRoute(t, func(_ context.Context, req routeprobe.Request) (routeprobe.Route, error) {
		return routeprobe.Route{Source: fmt.Sprintf("192.0.%d.%d", req.TOS, req.DstIP.To4()[3])}, nil
	})
	var workers sync.WaitGroup
	for _, tos := range []int{16, 46, 184} {
		for _, target := range []string{"198.51.100.9", "198.51.100.10"} {
			workers.Go(func() {
				cfg := Config{DstIP: net.ParseIP(target), TOS: tos, Context: t.Context()}
				want := fmt.Sprintf("192.0.%d.%d", tos, cfg.DstIP.To4()[3])
				for range 10 {
					got, err := PrepareProbeSourceConfig(ICMPTrace, cfg)
					if err != nil || got.SrcAddr != want {
						t.Errorf("session selected another source: %+v, want %s: %v", got, want, err)
					}
				}
			})
		}
	}
	workers.Wait()
}

func TestTOSSourcePortUsesSessionConfig(t *testing.T) {
	oldPort, oldRandom := util.SrcPort, util.EnvRandomPort
	util.SrcPort, util.EnvRandomPort = -1, false
	t.Cleanup(func() { util.SrcPort, util.EnvRandomPort = oldPort, oldRandom })
	for _, method := range []Method{TCPTrace, UDPTrace} {
		for _, source := range []string{"127.0.0.1", "::1"} {
			cfg := Config{DstIP: net.ParseIP(source), SrcAddr: source, TOS: 184}
			got, err := PrepareProbeSourceConfig(method, cfg)
			if err != nil || got.SrcPort <= 0 || got.SrcAddr != source || probeRandomPortEnabled(got) {
				t.Fatalf("session adopted global random-port/source state: %+v %v", got, err)
			}
			cfg.SrcPort = -1
			got, err = PrepareProbeSourceConfig(method, cfg)
			if err != nil || got.SrcPort != -1 || !probeRandomPortEnabled(got) {
				t.Fatalf("lost per-session random source port: %+v %v", got, err)
			}
		}
	}
}
