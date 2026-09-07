//go:build linux && !android

package trace

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestFWMarkMTRRotation(t *testing.T) {
	if os.Getenv("NEXTTRACE_FWMARK_INTEGRATION") != "1" {
		t.Skip("requires privileged Linux fixture")
	}
	for _, dst := range []string{"127.0.0.1", "::1"} {
		cfg := Config{DstIP: net.ParseIP(dst), Timeout: time.Second, FWMark: 256, FWMarkSet: true, Context: t.Context()}
		engine, err := newMTRICMPEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		workers := newMTRWorkerSession(t.Context())
		if err = engine.startMTRSession(workers); err != nil {
			workers.shutdown(engine.close)
			t.Fatal(err)
		}
		for _, seq := range []uint32{0, 0xffff} {
			engine.seqCounter.Store(seq)
			result, err := engine.ProbeTTL(workers.ctx, 1)
			if err != nil || !result.Success {
				workers.shutdown(engine.close)
				t.Fatalf("seq=%d %+v %v", seq, result, err)
			}
			if spec := engine.spec.Load(); spec == nil || !spec.FWMarkSet || spec.FWMark != 256 {
				workers.shutdown(engine.close)
				t.Fatal("rotation lost mark")
			}
		}
		workers.shutdown(engine.close)
	}
}

func TestFWMarkRouteOmitsRawSocketPorts(t *testing.T) {
	for _, method := range []Method{TCPTrace, UDPTrace} {
		for _, port := range []int{-1, 0, 40000} {
			cfg := Config{FWMarkSet: true, FWMark: 256, SrcPort: port, DstPort: 443}
			req := fwmarkRouteRequest(method, cfg)
			if req.SrcPort != 0 || req.DstPort != 0 {
				t.Fatalf("raw socket route includes transport ports: %+v", req)
			}
		}
	}
}

func TestFWMarkRoutePreservesSource(t *testing.T) {
	cfg := Config{FWMarkSet: true, SrcAddr: "192.0.2.2", SrcPort: 40000}
	req := fwmarkRouteRequest(UDPTrace, cfg)
	if req.SrcAddr != cfg.SrcAddr {
		t.Fatalf("route constraints changed: %+v", req)
	}
}
