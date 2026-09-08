//go:build (linux && !android) || darwin

package trace

import (
	"net"
	"os"
	"testing"
	"time"

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
