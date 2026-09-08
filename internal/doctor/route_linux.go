//go:build linux

package doctor

import (
	"context"
	"errors"
	"fmt"
	"github.com/nxtrace/NTrace-core/internal/routeprobe"
	"github.com/nxtrace/NTrace-core/trace"
	"os"
)

func queryRoute(ctx context.Context, method trace.Method, cfg trace.Config) (Route, error) {
	request := linuxProbeRouteRequest(method, cfg)
	native, err := routeprobe.Query(ctx, request)
	r := Route{Interface: native.Interface, Gateway: native.Gateway, Source: native.Source,
		Conditions: routeConditions(method, cfg) + fmt.Sprintf(" uid=%d", os.Geteuid()), Limitations: native.Limitations, OnLink: native.OnLink}
	if method != trace.ICMPTrace {
		r.Conditions += " route_ports=omitted"
		r.Limitations = "raw socket lookup omits transport ports; ECMP prediction may differ"
	}
	if request.HeaderIncluded {
		r.Conditions += " kernel_protocol=255"
	}
	if errors.Is(err, routeprobe.ErrNoRoute) {
		return r, fmt.Errorf("%w: %v", errNoRoute, err)
	}
	if err == nil && native.Incomplete != "" {
		err = errors.New(native.Incomplete)
	}
	return r, err
}

// Linux probe senders serialize their transport headers in user space. UDPv4
// additionally uses IP_HDRINCL, so the kernel route protocol is RAW, not UDP.
func linuxProbeRouteRequest(method trace.Method, cfg trace.Config) routeprobe.Request {
	return routeprobe.Request{
		Method: string(method), DstIP: cfg.DstIP, SrcAddr: cfg.SrcAddr, SourceDevice: cfg.SourceDevice,
		TOS: cfg.TOS, FWMark: cfg.FWMark, FWMarkSet: cfg.FWMarkSet,
		HeaderIncluded: method == trace.UDPTrace && cfg.DstIP.To4() != nil,
	}
}
