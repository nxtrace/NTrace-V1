//go:build linux && !android

package service

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestTOSRouteUsesServiceRequestContext(t *testing.T) {
	previous := traceTargetLookupFn
	t.Cleanup(func() { traceTargetLookupFn = previous })
	traceTargetLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tos := 184
	_, err := (&Service{}).prepareTrace(ctx, TraceRequest{Target: "127.0.0.1", DataProvider: "disable-geoip", TOS: &tos})
	if trace.IsInitializationError(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("source route ignored request cancellation: %v", err)
	}
}
