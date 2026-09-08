//go:build (linux && !android) || darwin

package trace

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/nxtrace/NTrace-core/trace/internal"
)

// A closed real socket fails its TOS setter before any packet can be sent.
// Exercise the complete sender-to-MTR error path, without a listener race.
func TestMTRTOSConfigurationFailureIsTerminal(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1"} {
		for _, mode := range []string{"per-hop", "legacy", "scheduler"} {
			t.Run(addr+"/"+mode, func(t *testing.T) {
				ip := net.ParseIP(addr)
				version := 4
				if ip.To4() == nil {
					version = 6
				}
				spec := internal.NewICMPSpec(version, 1, 123, ip, ip)
				if err := spec.InitICMP(); err != nil {
					if os.Getenv("NEXTTRACE_TOS_INTEGRATION") == "1" {
						t.Fatalf("mandatory ICMP socket setup: %v", err)
					}
					t.Skipf("ICMP socket unavailable: %v", err)
				}
				spec.Close()
				engine := newMTRICMPEngineState(Config{DstIP: ip, TOS: 184, Timeout: time.Second}, version, ip)
				engine.spec.Store(spec)
				engine.sentAt = make(map[int]mtrProbeMeta)
				engine.probeNotify = make(map[int]chan struct{})
				engine.curTtlSeq = make(map[int]int)
				var err error
				switch mode {
				case "per-hop":
					_, err = engine.ProbeTTL(t.Context(), 1)
				case "legacy":
					_, err = engine.sendProbeForTTL(t.Context(), 1, 0)
				case "scheduler":
					probes := 0
					// Forward calls without the scheduler reopening the closed engine.
					prober := &mockTTLProber{probeFn: engine.ProbeTTL}
					err = runMTRScheduler(t.Context(), prober, NewMTRAggregator(), mtrSchedulerConfig{
						BeginHop: 1, MaxHops: 1, MaxPerHop: 2, ParallelRequests: 1, MaxInFlightPerHop: 1,
						HopInterval: time.Millisecond,
					}, nil, func(mtrProbeResult, int, time.Time) { probes++ })
					if probes != 0 {
						t.Fatalf("configuration failure counted as %d probes", probes)
					}
				}
				if !IsInitializationError(err) {
					t.Fatalf("TOS failure was lost or treated as timeout: %v", err)
				}
				if len(engine.sentAt) != 0 || len(engine.probeNotify) != 0 || len(engine.curTtlSeq) != 0 {
					t.Fatal("failed send left pending probe state")
				}
			})
		}
	}
}

// Exercise the actual send goroutines with closed sockets, not just the
// protocol setters. CI makes socket initialization mandatory under sudo.
func TestTraceSendTOSConfigurationFailureIsTerminal(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1"} {
		for _, method := range []Method{ICMPTrace, TCPTrace, UDPTrace} {
			t.Run(string(method)+"/"+addr, func(t *testing.T) {
				ip := net.ParseIP(addr)
				cfg := Config{DstIP: ip, SrcAddr: addr, SrcPort: 40000, DstPort: 443, PktSize: packetSizeMinPayload(method, ip), TOS: 184, Timeout: time.Second, BeginHop: 1, MaxHops: 1, NumMeasurements: 1, MaxAttempts: 1, ParallelRequests: 1}
				version := 4
				if ip.To4() == nil {
					version = 6
				}
				var res *Result
				var final *atomic.Int32
				var launch func(context.Context, context.CancelCauseFunc)
				var wait func()
				ready := func(err error) {
					if err == nil {
						return
					}
					if os.Getenv("NEXTTRACE_TOS_INTEGRATION") == "1" {
						t.Fatalf("mandatory socket setup: %v", err)
					}
					t.Skipf("probe socket unavailable: %v", err)
				}
				switch method {
				case ICMPTrace:
					spec := internal.NewICMPSpec(version, 1, 123, ip, ip)
					t.Cleanup(spec.Close)
					ready(spec.InitICMP())
					spec.Close()
					if version == 4 {
						tr := &ICMPTracer{Config: cfg, SrcIP: ip, pending: make(map[int]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					} else {
						tr := &ICMPTracerv6{Config: cfg, SrcIP: ip, pending: make(map[int]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					}
				case TCPTrace:
					spec := internal.NewTCPSpec(version, 1, ip, ip, 443, 0)
					t.Cleanup(spec.Close)
					ready(spec.InitTCP())
					spec.Close()
					if version == 4 {
						tr := &TCPTracer{Config: cfg, SrcIP: ip, pending: make(map[int]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					} else {
						tr := &TCPTracerIPv6{Config: cfg, SrcIP: ip, pending: make(map[int]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					}
				case UDPTrace:
					spec := internal.NewUDPSpec(version, 1, ip, ip, 443)
					t.Cleanup(spec.Close)
					ready(spec.InitUDP())
					spec.Close()
					if version == 4 {
						tr := &UDPTracer{Config: cfg, SrcIP: ip, pending: make(map[attemptKey]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					} else {
						tr := &UDPTracerIPv6{Config: cfg, SrcIP: ip, pending: make(map[int]struct{}), sem: semaphore.NewWeighted(1)}
						res, final, wait = &tr.res, &tr.final, tr.wg.Wait
						launch = func(ctx context.Context, cancel context.CancelCauseFunc) { tr.launchTTL(ctx, cancel, spec, 1) }
					}
				}
				res.Hops, res.tailDone = make([][]Hop, 1), make([]bool, 1)
				final.Store(-1)
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				launch(ctx, cancel)
				wait()
				cause := context.Cause(ctx)
				if !IsInitializationError(cause) {
					t.Fatalf("send setup error lost: cause=%v hops=%+v", cause, res.Hops)
				}
				if len(res.Hops[0]) != 0 {
					t.Fatalf("setup failure counted as a hop: %+v", res.Hops)
				}
				// Execute returns this same cancellation cause to the fallback prober.
				// The MTR scheduler must stop without publishing or counting a probe.
				agg := NewMTRAggregator()
				probes := 0
				prober := &mockTTLProber{probeFn: func(context.Context, int) (mtrProbeResult, error) { return mtrProbeResult{}, cause }}
				err := runMTRScheduler(t.Context(), prober, agg, mtrSchedulerConfig{BeginHop: 1, MaxHops: 1, MaxPerHop: 1, ParallelRequests: 1, HopInterval: time.Millisecond}, nil, func(mtrProbeResult, int, time.Time) { probes++ })
				if !IsInitializationError(err) || probes != 0 || len(agg.Snapshot()) != 0 {
					t.Fatalf("setup failure counted by MTR: err=%v probes=%d", err, probes)
				}
			})
		}
	}
}
