//go:build linux && !android

package server

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestTOSRouteUsesHTTPRequestContext(t *testing.T) {
	previous := traceDomainLookupFn
	t.Cleanup(func() { traceDomainLookupFn = previous })
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tos := 184
	_, _, err := prepareTrace(ctx, traceRequest{Target: "127.0.0.1", DataProvider: "disable-geoip", TOS: &tos})
	if trace.IsInitializationError(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("source route ignored request cancellation: %v", err)
	}
}
