package trace

import (
	"context"
	"net"

	"github.com/nxtrace/NTrace-core/trace/internal"
)

// BackendCheck describes only local initialization, never packet delivery.
type BackendCheck = internal.BackendCheck

// CheckProbeBackend opens and closes the selected backend without sending or
// receiving packets. Source configuration must already be normalized.
func CheckProbeBackend(ctx context.Context, method Method, cfg Config) []BackendCheck {
	v := 4
	if cfg.DstIP.To4() == nil {
		v = 6
	}
	return internal.CheckProbeBackend(ctx, internal.BackendOptions{
		Protocol: string(method), IPVersion: v, ICMPMode: cfg.ICMPMode,
		Source: net.ParseIP(cfg.SrcAddr), Target: cfg.DstIP,
		Device: cfg.SourceDevice, Port: cfg.DstPort, TOS: cfg.TOS,
	})
}
