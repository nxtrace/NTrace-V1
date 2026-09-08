//go:build linux && !android

package trace

import (
	"context"
	"fmt"
	"time"

	"github.com/nxtrace/NTrace-core/internal/routeprobe"
)

var queryProbeRoute = routeprobe.Query

func resolveProbeRouteSource(method Method, cfg Config) (string, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r, err := queryProbeRoute(ctx, probeRouteRequest(method, cfg))
	if err != nil {
		return "", err
	}
	if r.Source == "" {
		return "", fmt.Errorf("probe route did not provide a source address")
	}
	return r.Source, nil
}

func probeRouteRequest(method Method, cfg Config) routeprobe.Request {
	// Raw probe sockets serialize transport headers in user space. Their kernel
	// route lookup has no transport ports, even when the probe uses fixed ports.
	return routeprobe.Request{
		Method: string(method), DstIP: cfg.DstIP, SrcAddr: cfg.SrcAddr, SourceDevice: cfg.SourceDevice,
		TOS: cfg.TOS, FWMark: cfg.FWMark, FWMarkSet: cfg.FWMarkSet,
		HeaderIncluded: method == UDPTrace && cfg.DstIP.To4() != nil,
	}
}
