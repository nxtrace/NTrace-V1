package doctor

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

// Explicit opt-in: exercise local OS APIs, with no external target or packets.
// This catches failures that serialized route fixtures and cross-builds cannot.
func TestNativeLoopbackRoute(t *testing.T) {
	if os.Getenv("NEXTTRACE_DOCTOR_INTEGRATION") != "1" {
		t.Skip("set NEXTTRACE_DOCTOR_INTEGRATION=1 to check native routing")
	}
	for _, target := range []string{"127.0.0.1", "::1"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			r, err := queryRoute(ctx, trace.ICMPTrace, trace.Config{DstIP: net.ParseIP(target), SrcAddr: target})
			if err != nil || r.Interface == "" {
				t.Fatalf("native route: %+v, %v", r, err)
			}
		})
	}
}
