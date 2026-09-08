//go:build linux && !android

package cmd

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestCLIRejectsFailedTOSRouteBeforeFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cfg := trace.Config{Context: ctx, DstIP: net.ParseIP("127.0.0.1"), TOS: 184}
	got, err := resolveCLIProbeSource(trace.ICMPTrace, cfg)
	if trace.IsInitializationError(err) || !errors.Is(err, context.Canceled) || got.SrcAddr != "" {
		t.Fatalf("CLI used fallback source after failed TOS route: %+v %v", got, err)
	}
}
