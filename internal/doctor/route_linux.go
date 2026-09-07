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
	native, err := routeprobe.Query(ctx, routeprobe.Request{
		Method: string(method), DstIP: cfg.DstIP, SrcAddr: cfg.SrcAddr, SourceDevice: cfg.SourceDevice,
		SrcPort: cfg.SrcPort, DstPort: cfg.DstPort, TOS: cfg.TOS,
	})
	r := Route{Interface: native.Interface, Gateway: native.Gateway, Source: native.Source,
		Conditions: routeConditions(method, cfg) + fmt.Sprintf(" uid=%d", os.Geteuid()), Limitations: native.Limitations, OnLink: native.OnLink}
	if errors.Is(err, routeprobe.ErrNoRoute) {
		return r, fmt.Errorf("%w: %v", errNoRoute, err)
	}
	if err == nil && native.Incomplete != "" {
		err = errors.New(native.Incomplete)
	}
	return r, err
}
