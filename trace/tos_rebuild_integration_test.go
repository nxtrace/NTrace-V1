package trace

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// The external tcpdump/WinDivert observer matches each marker against a real
// echo request. This test proves successful socket writes and engine replacement;
// only that independent capture proves the TOS byte on both socket generations.
func TestMTRTOSRebuildIntegration(t *testing.T) {
	if os.Getenv("NEXTTRACE_TOS_REBUILD_INTEGRATION") != "1" {
		t.Skip("set NEXTTRACE_TOS_REBUILD_INTEGRATION=1 for mandatory native MTR rebuild capture")
	}
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("ipv%d", family), func(t *testing.T) {
			ip := net.ParseIP("127.0.0.1")
			if family == 6 {
				ip = net.ParseIP("::1")
			}
			cfg := Config{
				Context: t.Context(), DstIP: ip, SrcAddr: ip.String(),
				TOS: 184, ICMPMode: 1, BeginHop: 1, MaxHops: 2,
				Timeout: 100 * time.Millisecond,
			}
			engine := newMTRICMPEngineState(cfg, family, ip)
			// Production rotation uses pid&255 in the low byte. A different low
			// byte guarantees a distinct first generation without changing it.
			firstEchoID := 0x5a00 | ((os.Getpid() + 1) & 0xff)
			engine.echoID.Store(int32(firstEchoID))
			workers := newMTRWorkerSession(t.Context())
			defer workers.shutdown(engine.close)
			if err := engine.startMTRSession(workers); err != nil {
				t.Fatalf("mandatory native ICMPv%d initialization: %v", family, err)
			}
			firstSpec, firstListenerDone := engine.spec.Load(), engine.listenerDone
			engine.seqCounter.Store(0xfffd)

			for generation := range 2 {
				round := engine.prepareProbeRound(workers.ctx)
				if round.err != nil {
					t.Fatalf("prepare generation %d: %v", generation, round.err)
				}
				spec, echoID := engine.spec.Load(), int(engine.echoID.Load())
				if spec == nil || spec.EchoID != echoID || engine.config.TOS != 184 {
					t.Fatalf("invalid generation %d socket/configuration", generation)
				}
				if generation == 0 {
					if spec != firstSpec || echoID != firstEchoID {
						t.Fatal("engine rotated before the sequence boundary")
					}
				} else {
					if spec == firstSpec || echoID == firstEchoID {
						t.Fatal("sequence boundary did not replace the socket and echoID")
					}
					select {
					case <-firstListenerDone:
					default:
						t.Fatal("previous generation listener remains active")
					}
				}
				for ttl := 1; ttl <= 2; ttl++ {
					sent, err := engine.sendProbeForTTL(workers.ctx, ttl, round.roundID)
					if err != nil || !sent {
						t.Fatalf("mandatory send generation=%d ttl=%d: sent=%t error=%v", generation, ttl, sent, err)
					}
					sequence := int(engine.seqCounter.Load() & 0xffff)
					wantSequence := ttl
					if generation == 0 {
						wantSequence += 0xfffd
					}
					if sequence != wantSequence {
						t.Fatalf("generation=%d sequence=%d want=%d", generation, sequence, wantSequence)
					}
					marker, err := json.Marshal(struct {
						Family     int `json:"family"`
						Generation int `json:"generation"`
						EchoID     int `json:"echo_id"`
						Sequence   int `json:"sequence"`
						TOS        int `json:"tos"`
					}{family, generation, echoID, sequence, cfg.TOS})
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("TOS_REBUILD %s", marker)
				}
			}
		})
	}
}
